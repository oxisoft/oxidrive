//! The HTTP API end to end (server HTTP §8): every endpoint and error code in process, on
//! SQLite and PostgreSQL, and the whole flow over a real socket, with events and the pairing
//! long poll.

#![cfg(test)]
#![expect(
    clippy::too_many_lines,
    reason = "each test is one end-to-end scenario"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use oxisoft_drive_chunking::{ChunkKeys, seal_chunk};
use oxisoft_drive_crypto::hash;
use oxisoft_drive_crypto::keys::{
    AccountKemKey, AccountKey, AccountSigningKey, CollectionKey, DeviceIdentity,
};
use oxisoft_drive_crypto::sign::SignContext;
use oxisoft_drive_proto::api::{
    AccountCreated, AppendCommit, AppendResult, Challenge, ChallengeRequest, CollectionInfo,
    CreateAccount, CreateCollection, Devices, ErrorBody, ErrorCode, Event, Head, Keys, MacBytes,
    Missing, MissingRequest, PairingApproval, PairingCreated, PairingRequest, PairingState,
    PatchCollection, PutDevices, PutKeys, Recovery, ServerInfo, Session, SessionRequest,
};
use oxisoft_drive_proto::{
    AccountId, CertificateHash, ChunkId, ChunkRef, CollectionId, Commit, CommitDraft, ContentHash,
    DEVICE_FORMAT, DeviceCertificate, DeviceEntry, DeviceId, DeviceList, Envelope, EnvelopeKind,
    FileInfo, HeadAttestation, KemKeyPublication, NODE_FORMAT, Name, NodeId, NodeKind, NodePayload,
    NodeRecord, RecordContext, Signed, Version, auth_message,
};
use oxisoft_drive_server::{
    Api, ApiConfig, Clock, MemBlobStore, RateLimits, Service, Settings, With,
};
use oxisoft_drive_server_store::MetaStore;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tower::ServiceExt as _;

const ORIGIN: &str = "https://drive.example.test";
const DAY_MS: u64 = 86_400_000;

#[derive(Debug, Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The API as these tests run it.
type TestApi<M> = Arc<Api<With<M, Arc<MemBlobStore>, TestClock, ChaCha20Rng>>>;

fn cbor<T: minicbor::Encode<()>>(value: &T) -> Vec<u8> {
    minicbor::to_vec(value).unwrap()
}

fn uncbor<T: for<'b> minicbor::Decode<'b, ()>>(bytes: &[u8]) -> T {
    minicbor::decode(bytes).unwrap()
}

/// What a device keeps: its keys, and its session once signed in.
struct Device {
    identity: DeviceIdentity,
    token: Option<String>,
}

impl Device {
    fn id(&self) -> DeviceId {
        DeviceId::from_key(&self.identity.verifying_key())
    }
}

/// An account as its devices know it.
struct Account {
    id: AccountId,
    key: AccountKey,
    signing: AccountSigningKey,
    kem: AccountKemKey,
    certificates: Vec<Signed<DeviceCertificate>>,
}

impl Account {
    fn certificate(&mut self, device: &Device, rng: &mut ChaCha20Rng) -> Signed<DeviceCertificate> {
        let certificate = DeviceCertificate::new(
            self.id,
            (
                device.identity.verifying_key(),
                device.identity.kem_public_key(),
            ),
            "device",
            &self.key.meta(),
            rng,
            1,
        )
        .unwrap();
        let signed = Signed::sign(self.signing.signing_key(), &certificate);
        self.certificates.push(signed.clone());
        signed
    }

    fn list(&self, version: u64, trusted: &[DeviceId], revoked: &[DeviceId]) -> Signed<DeviceList> {
        let devices = trusted
            .iter()
            .map(|device| {
                let signed = self
                    .certificates
                    .iter()
                    .find(|signed| signed.decode_unverified().unwrap().device == *device)
                    .unwrap();
                DeviceEntry {
                    device: *device,
                    certificate: CertificateHash(signed.hash()),
                }
            })
            .collect();
        Signed::sign(
            self.signing.signing_key(),
            &DeviceList {
                format: DEVICE_FORMAT,
                account: self.id,
                version,
                devices,
                revoked: revoked.to_vec(),
            },
        )
    }
}

/// An envelope with placeholder contents: the server never opens envelopes.
fn envelope(
    kind: EnvelopeKind,
    epoch: u32,
    device: Option<DeviceId>,
    collection: Option<CollectionId>,
) -> Envelope {
    Envelope {
        kind,
        epoch,
        device,
        collection,
        wrapped: vec![7; 40],
    }
}

/// A server in process, reached through its router.
struct Fixture<M: MetaStore + 'static> {
    api: TestApi<M>,
    clock: TestClock,
    rng: ChaCha20Rng,
    _guard: Box<dyn std::any::Any + Send>,
}

struct Reply {
    status: StatusCode,
    retry_after: Option<String>,
    body: Vec<u8>,
}

impl Reply {
    fn ok<T: for<'b> minicbor::Decode<'b, ()>>(&self) -> T {
        assert!(
            self.status.is_success(),
            "{} {:?}",
            self.status,
            self.error()
        );
        uncbor(&self.body)
    }

    fn error(&self) -> Option<ErrorBody> {
        minicbor::decode(&self.body).ok()
    }

    fn code(&self) -> ErrorCode {
        self.error()
            .unwrap_or_else(|| panic!("no error body with {}", self.status))
            .code
    }
}

impl<M: MetaStore + 'static> Fixture<M> {
    fn new(
        store: M,
        guard: Box<dyn std::any::Any + Send>,
        limits: RateLimits,
        settings: Settings,
    ) -> Self {
        let clock = TestClock(Arc::new(AtomicU64::new(10 * DAY_MS)));
        let service = Service::new(
            store,
            Arc::new(MemBlobStore::new()),
            clock.clone(),
            ChaCha20Rng::seed_from_u64(1),
            settings,
        );
        let api = Api::new(
            service,
            ApiConfig {
                origin: ORIGIN.to_owned(),
                trusted_proxies: Vec::new(),
                limits,
            },
        );
        Self {
            api,
            clock,
            rng: ChaCha20Rng::seed_from_u64(2),
            _guard: guard,
        }
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        content_type: &str,
        body: Vec<u8>,
    ) -> Reply {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if !body.is_empty() {
            request = request.header("content-type", content_type);
        }
        let response = self
            .api
            .router()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .map(|value| value.to_str().unwrap().to_owned());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        Reply {
            status,
            retry_after,
            body,
        }
    }

    async fn call<T: minicbor::Encode<()>>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&T>,
    ) -> Reply {
        self.send(
            method,
            path,
            token,
            "application/cbor",
            body.map(cbor).unwrap_or_default(),
        )
        .await
    }

    async fn get(&self, path: &str, token: Option<&str>) -> Reply {
        self.call::<()>(Method::GET, path, token, None).await
    }

    fn new_device(&mut self) -> Device {
        Device {
            identity: DeviceIdentity::generate(&mut self.rng),
            token: None,
        }
    }

    /// Creates an account with an invite; `device` is its first device.
    async fn create_account(&mut self, device: &Device) -> Account {
        let invite = self.api.service().create_invite(DAY_MS).await.unwrap();
        let mut account = Account {
            id: AccountId::random(&mut self.rng),
            key: AccountKey::generate(&mut self.rng, 0),
            signing: AccountSigningKey::generate(&mut self.rng),
            kem: AccountKemKey::generate(&mut self.rng),
            certificates: Vec::new(),
        };
        let request = self.account_request(&mut account, device, invite);
        let reply = self
            .call(Method::POST, "/v1/accounts", None, Some(&request))
            .await;
        assert_eq!(reply.ok::<AccountCreated>().account, account.id);
        account
    }

    fn account_request(
        &mut self,
        account: &mut Account,
        device: &Device,
        invite: String,
    ) -> CreateAccount {
        let first_device = account.certificate(device, &mut self.rng);
        CreateAccount {
            invite,
            account: account.id,
            signing_key: account.signing.verifying_key(),
            kem_key: Signed::sign(
                account.signing.signing_key(),
                &KemKeyPublication {
                    format: DEVICE_FORMAT,
                    account: account.id,
                    kem_key: account.kem.public_key(),
                },
            ),
            first_device,
            list: account.list(1, &[device.id()], &[]),
            envelopes: vec![
                envelope(EnvelopeKind::AccountKeyToDevice, 0, Some(device.id()), None),
                envelope(EnvelopeKind::AccountKeyToRecovery, 0, None, None),
                envelope(EnvelopeKind::AccountSigningKey, 0, None, None),
                envelope(EnvelopeKind::AccountKemKey, 0, None, None),
            ],
        }
    }

    async fn sign_in(&self, device: &mut Device) {
        let challenge: Challenge = self
            .call(
                Method::POST,
                "/v1/auth/challenge",
                None,
                Some(&ChallengeRequest {
                    device: device.id(),
                }),
            )
            .await
            .ok();
        let signature = device.identity.signing_key().sign(
            SignContext::AuthChallenge,
            &auth_message(ORIGIN, &challenge.nonce, device.id()),
        );
        let session: Session = self
            .call(
                Method::POST,
                "/v1/auth/session",
                None,
                Some(&SessionRequest {
                    device: device.id(),
                    nonce: challenge.nonce,
                    signature,
                }),
            )
            .await
            .ok();
        device.token = Some(session.token);
    }

    fn advance(&self, ms: u64) {
        self.clock.0.fetch_add(ms, Ordering::SeqCst);
    }
}

/// A commit by `device` of one record per node referencing `chunks`.
fn commit(
    device: &Device,
    key: &CollectionKey,
    collection: CollectionId,
    previous: Option<Head>,
    nodes: &[(u8, Vec<ChunkId>)],
    rng: &mut ChaCha20Rng,
) -> Commit {
    let seq = previous.map_or(1, |head| head.seq + 1);
    let context = RecordContext {
        collection,
        seq,
        epoch: 0,
    };
    let records: Vec<NodeRecord> = nodes
        .iter()
        .map(|(node, chunks)| {
            let payload = NodePayload {
                format: NODE_FORMAT,
                parent: None,
                name: Name::new(&format!("f{node}")).unwrap(),
                kind: NodeKind::File(FileInfo {
                    size: 1,
                    mtime_ms: 1,
                    executable: false,
                    content_hash: ContentHash(hash::hash(&[*node])),
                    chunks: chunks
                        .iter()
                        .map(|id| ChunkRef { id: *id, len: 1 })
                        .collect(),
                }),
                version: Version {
                    device: device.id(),
                    counter: seq,
                },
                base: None,
            };
            NodeRecord::seal(
                NodeId::from_bytes([*node; 16]),
                &payload,
                &key.meta(),
                rng,
                &context,
            )
            .unwrap()
        })
        .collect();
    Commit::create(
        device.identity.signing_key(),
        &CommitDraft {
            collection,
            seq,
            prev: previous.map(|head| head.hash),
            epoch: 0,
            time_ms: 1,
        },
        &records,
    )
}

// ── scenarios, run on every backend ─────────────────────────────────────────────────

async fn info_and_wire_errors<M: MetaStore + 'static>(f: Fixture<M>) {
    let info: ServerInfo = f.get("/v1/info", None).await.ok();
    assert_eq!(info.protocols, [oxisoft_drive_proto::api::PROTOCOL_VERSION]);
    assert_eq!(info.limits, Settings::default().limits);
    // Wrong content type, undecodable body, malformed ID, missing session.
    let wrong = f
        .send(
            Method::POST,
            "/v1/auth/challenge",
            None,
            "application/json",
            b"{}".to_vec(),
        )
        .await;
    assert_eq!(
        (wrong.status, wrong.code()),
        (StatusCode::UNSUPPORTED_MEDIA_TYPE, ErrorCode::Unsupported)
    );
    let garbage = f
        .send(
            Method::POST,
            "/v1/auth/challenge",
            None,
            "application/cbor",
            vec![0xff, 0x00],
        )
        .await;
    assert_eq!(garbage.code(), ErrorCode::BadRequest);
    assert_eq!(
        f.get("/v1/accounts/zz/recovery", None).await.code(),
        ErrorCode::BadRequest
    );
    let unsigned = f.get("/v1/devices", None).await;
    assert_eq!(
        (unsigned.status, unsigned.code()),
        (StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized)
    );
    assert_eq!(
        f.get("/v1/devices", Some("nonsense")).await.code(),
        ErrorCode::Unauthorized
    );
}

async fn accounts_and_sign_in<M: MetaStore + 'static>(mut f: Fixture<M>) {
    let mut first = f.new_device();
    let mut account = Account {
        id: AccountId::random(&mut f.rng),
        key: AccountKey::generate(&mut f.rng, 0),
        signing: AccountSigningKey::generate(&mut f.rng),
        kem: AccountKemKey::generate(&mut f.rng),
        certificates: Vec::new(),
    };
    // An unknown invite.
    let request = f.account_request(&mut account, &first, "no such invite".into());
    let refused = f
        .call(Method::POST, "/v1/accounts", None, Some(&request))
        .await;
    assert_eq!(
        (refused.status, refused.code()),
        (StatusCode::FORBIDDEN, ErrorCode::Forbidden)
    );
    // A list that trusts no device.
    let invite = f.api.service().create_invite(DAY_MS).await.unwrap();
    let mut bad = CreateAccount {
        invite: invite.clone(),
        ..request.clone()
    };
    bad.list = account.list(1, &[], &[]);
    assert_eq!(
        f.call(Method::POST, "/v1/accounts", None, Some(&bad))
            .await
            .code(),
        ErrorCode::BadRequest
    );
    let good = CreateAccount {
        invite: invite.clone(),
        ..request
    };
    assert_eq!(
        f.call(Method::POST, "/v1/accounts", None, Some(&good))
            .await
            .ok::<AccountCreated>()
            .account,
        account.id
    );
    // The invite is used up.
    assert_eq!(
        f.call(Method::POST, "/v1/accounts", None, Some(&good))
            .await
            .code(),
        ErrorCode::Forbidden
    );

    // A wrong signature, an unknown device, a reused nonce: all refused.
    let challenge: Challenge = f
        .call(
            Method::POST,
            "/v1/auth/challenge",
            None,
            Some(&ChallengeRequest { device: first.id() }),
        )
        .await
        .ok();
    let stranger = f.new_device();
    let forged = stranger.identity.signing_key().sign(
        SignContext::AuthChallenge,
        &auth_message(ORIGIN, &challenge.nonce, first.id()),
    );
    let session = |nonce, signature| SessionRequest {
        device: first.id(),
        nonce,
        signature,
    };
    assert_eq!(
        f.call(
            Method::POST,
            "/v1/auth/session",
            None,
            Some(&session(challenge.nonce, forged))
        )
        .await
        .code(),
        ErrorCode::Unauthorized
    );
    // The failed attempt used the challenge up.
    let genuine = first.identity.signing_key().sign(
        SignContext::AuthChallenge,
        &auth_message(ORIGIN, &challenge.nonce, first.id()),
    );
    assert_eq!(
        f.call(
            Method::POST,
            "/v1/auth/session",
            None,
            Some(&session(challenge.nonce, genuine))
        )
        .await
        .code(),
        ErrorCode::Unauthorized
    );
    // Signed for another server.
    let challenge: Challenge = f
        .call(
            Method::POST,
            "/v1/auth/challenge",
            None,
            Some(&ChallengeRequest { device: first.id() }),
        )
        .await
        .ok();
    let elsewhere = first.identity.signing_key().sign(
        SignContext::AuthChallenge,
        &auth_message("https://evil.example", &challenge.nonce, first.id()),
    );
    assert_eq!(
        f.call(
            Method::POST,
            "/v1/auth/session",
            None,
            Some(&session(challenge.nonce, elsewhere))
        )
        .await
        .code(),
        ErrorCode::Unauthorized
    );
    // Unknown devices get a challenge they can't use.
    let unknown: Challenge = f
        .call(
            Method::POST,
            "/v1/auth/challenge",
            None,
            Some(&ChallengeRequest {
                device: stranger.id(),
            }),
        )
        .await
        .ok();
    let answer = stranger.identity.signing_key().sign(
        SignContext::AuthChallenge,
        &auth_message(ORIGIN, &unknown.nonce, stranger.id()),
    );
    let request = SessionRequest {
        device: stranger.id(),
        nonce: unknown.nonce,
        signature: answer,
    };
    assert_eq!(
        f.call(Method::POST, "/v1/auth/session", None, Some(&request))
            .await
            .code(),
        ErrorCode::Unauthorized
    );

    f.sign_in(&mut first).await;
    let devices: Devices = f.get("/v1/devices", first.token.as_deref()).await.ok();
    assert_eq!(devices.certificates.len(), 1);
    // Sessions expire.
    f.advance(Settings::default().session_ms);
    assert_eq!(
        f.get("/v1/devices", first.token.as_deref()).await.code(),
        ErrorCode::Unauthorized
    );
}

async fn devices_keys_pairing_and_recovery<M: MetaStore + 'static>(mut f: Fixture<M>) {
    let mut first = f.new_device();
    let mut account = f.create_account(&first).await;
    f.sign_in(&mut first).await;
    let token = first.token.clone();

    // A new device asks to pair; the first device checks its keys and approves.
    let mut second = f.new_device();
    let request = PairingRequest {
        verifying_key: second.identity.verifying_key(),
        kem_key: second.identity.kem_public_key(),
    };
    let created: PairingCreated = f
        .call(Method::POST, "/v1/pairings", None, Some(&request))
        .await
        .ok();
    let path = format!("/v1/pairings/{}", hex(created.pairing.as_bytes()));
    let pending: PairingState = f.get(&format!("{path}?wait=0"), None).await.ok();
    assert_eq!(pending, PairingState::Pending(Box::new(request.clone())));
    let certificate = account.certificate(&second, &mut f.rng);
    let approval = PairingApproval {
        account: account.id,
        signing_key: account.signing.verifying_key(),
        certificate: certificate.clone(),
        envelopes: vec![envelope(
            EnvelopeKind::AccountKeyToDevice,
            0,
            Some(second.id()),
            None,
        )],
        mac: MacBytes([1; 32]),
    };
    // Not before the device is in the list.
    assert_eq!(
        f.call(
            Method::POST,
            &format!("{path}/approve"),
            token.as_deref(),
            Some(&approval)
        )
        .await
        .code(),
        ErrorCode::BadRequest
    );
    let put = PutDevices {
        list: account.list(2, &[first.id(), second.id()], &[]),
        new_certificates: vec![certificate],
        envelopes: vec![envelope(
            EnvelopeKind::AccountKeyToDevice,
            0,
            Some(second.id()),
            None,
        )],
    };
    let devices: Devices = f
        .call(Method::PUT, "/v1/devices", token.as_deref(), Some(&put))
        .await
        .ok();
    assert_eq!(devices.certificates.len(), 2);
    // The same version again is stale: fetch and retry.
    assert_eq!(
        f.call(Method::PUT, "/v1/devices", token.as_deref(), Some(&put))
            .await
            .code(),
        ErrorCode::Conflict
    );
    assert_eq!(
        f.call(
            Method::POST,
            &format!("{path}/approve"),
            token.as_deref(),
            Some(&approval)
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    let approved: PairingState = f.get(&path, None).await.ok();
    assert_eq!(approved, PairingState::Approved(Box::new(approval.clone())));
    assert_eq!(
        f.call(
            Method::POST,
            &format!("{path}/approve"),
            token.as_deref(),
            Some(&approval)
        )
        .await
        .code(),
        ErrorCode::NotFound
    );

    // The new device signs in and sees its own keys only.
    f.sign_in(&mut second).await;
    let keys: Keys = f.get("/v1/keys", second.token.as_deref()).await.ok();
    assert!(keys.envelopes.iter().any(|e| e.device == Some(second.id())));
    assert!(!keys.envelopes.iter().any(|e| e.device == Some(first.id())));
    assert!(
        !keys
            .envelopes
            .iter()
            .any(|e| e.kind == EnvelopeKind::AccountKeyToRecovery)
    );

    // A new epoch needs every trusted device, recovery and the older key.
    let partial = PutKeys {
        epoch: 1,
        envelopes: vec![envelope(
            EnvelopeKind::AccountKeyToDevice,
            1,
            Some(first.id()),
            None,
        )],
    };
    assert_eq!(
        f.call(Method::PUT, "/v1/keys", token.as_deref(), Some(&partial))
            .await
            .code(),
        ErrorCode::BadRequest
    );
    let full = PutKeys {
        epoch: 1,
        envelopes: vec![
            envelope(EnvelopeKind::AccountKeyToDevice, 1, Some(first.id()), None),
            envelope(EnvelopeKind::AccountKeyToDevice, 1, Some(second.id()), None),
            envelope(EnvelopeKind::AccountKeyToRecovery, 1, None, None),
            envelope(EnvelopeKind::OlderAccountKey, 1, None, None),
        ],
    };
    let keys: Keys = f
        .call(Method::PUT, "/v1/keys", token.as_deref(), Some(&full))
        .await
        .ok();
    assert!(keys.envelopes.iter().any(|e| e.epoch == 1));
    assert_eq!(
        f.call(Method::PUT, "/v1/keys", token.as_deref(), Some(&full))
            .await
            .code(),
        ErrorCode::Conflict
    );

    // Revoking the second device ends its session at once.
    let revoke = PutDevices {
        list: account.list(3, &[first.id()], &[second.id()]),
        new_certificates: Vec::new(),
        envelopes: Vec::new(),
    };
    let _: Devices = f
        .call(Method::PUT, "/v1/devices", token.as_deref(), Some(&revoke))
        .await
        .ok();
    assert_eq!(
        f.get("/v1/keys", second.token.as_deref()).await.code(),
        ErrorCode::Unauthorized
    );

    // Recovery: the envelopes needed to restore, then a list put with no session.
    let recovery: Recovery = f
        .get(
            &format!("/v1/accounts/{}/recovery", hex(account.id.as_bytes())),
            None,
        )
        .await
        .ok();
    assert_eq!(recovery.account_key.epoch, 1);
    assert_eq!(recovery.signing_public, account.signing.verifying_key());
    assert_eq!(
        f.get(&format!("/v1/accounts/{}/recovery", hex(&[3; 16])), None)
            .await
            .code(),
        ErrorCode::NotFound
    );
    let restored = f.new_device();
    let certificate = account.certificate(&restored, &mut f.rng);
    let by_recovery = PutDevices {
        list: account.list(4, &[first.id(), restored.id()], &[second.id()]),
        new_certificates: vec![certificate],
        envelopes: vec![envelope(
            EnvelopeKind::AccountKeyToDevice,
            1,
            Some(restored.id()),
            None,
        )],
    };
    let devices: Devices = f
        .call(Method::PUT, "/v1/devices", None, Some(&by_recovery))
        .await
        .ok();
    assert_eq!(devices.certificates.len(), 2);
    // A list signed by anyone else gets nowhere.
    let stranger = AccountSigningKey::generate(&mut f.rng);
    let forged = PutDevices {
        list: Signed::sign(
            stranger.signing_key(),
            &account
                .list(5, &[first.id()], &[second.id()])
                .decode_unverified()
                .unwrap(),
        ),
        new_certificates: Vec::new(),
        envelopes: Vec::new(),
    };
    assert_eq!(
        f.call(Method::PUT, "/v1/devices", None, Some(&forged))
            .await
            .code(),
        ErrorCode::BadRequest
    );
    // Unknown and expired pairings.
    f.advance(Settings::default().pairing_ms);
    assert_eq!(
        f.get(&path, None).await.ok::<PairingState>(),
        PairingState::Expired
    );
}

async fn collections_commits_and_chunks<M: MetaStore + 'static>(mut f: Fixture<M>) {
    let mut device = f.new_device();
    let _account = f.create_account(&device).await;
    f.sign_in(&mut device).await;
    let token = device.token.clone();
    let key = CollectionKey::generate(&mut f.rng, 0);
    let collection = CollectionId::random(&mut f.rng);
    let base = format!("/v1/collections/{}", hex(collection.as_bytes()));

    // A key that isn't this collection's is refused.
    let wrong = CreateCollection {
        id: collection,
        key: envelope(
            EnvelopeKind::CollectionKey,
            0,
            None,
            Some(CollectionId::from_bytes([1; 16])),
        ),
        config: vec![1],
    };
    assert_eq!(
        f.call(
            Method::POST,
            "/v1/collections",
            token.as_deref(),
            Some(&wrong)
        )
        .await
        .code(),
        ErrorCode::BadRequest
    );
    let create = CreateCollection {
        id: collection,
        key: envelope(EnvelopeKind::CollectionKey, 0, None, Some(collection)),
        config: vec![1],
    };
    assert_eq!(
        f.call(
            Method::POST,
            "/v1/collections",
            token.as_deref(),
            Some(&create)
        )
        .await
        .status,
        StatusCode::CREATED
    );
    assert_eq!(
        f.call(
            Method::POST,
            "/v1/collections",
            token.as_deref(),
            Some(&create)
        )
        .await
        .code(),
        ErrorCode::Conflict
    );

    // Chunks: which are missing, then uploads under the lease.
    let sealed = seal_chunk(
        &ChunkKeys::new(&key),
        &mut f.rng,
        collection.as_bytes(),
        b"hello",
    )
    .unwrap();
    let chunk = ChunkId(sealed.id);
    let missing: Missing = f
        .call(
            Method::POST,
            &format!("{base}/chunks/missing"),
            token.as_deref(),
            Some(&MissingRequest { ids: vec![chunk] }),
        )
        .await
        .ok();
    assert_eq!(missing.ids, [chunk]);
    let chunk_path = format!("{base}/chunks/{}", hex(chunk.0.as_bytes()));
    let no_lease = f
        .send(
            Method::PUT,
            &chunk_path,
            token.as_deref(),
            "application/octet-stream",
            sealed.object.clone(),
        )
        .await;
    assert_eq!(no_lease.code(), ErrorCode::BadRequest);
    let upload = format!("{chunk_path}?lease={}", hex(missing.lease.as_bytes()));
    assert_eq!(
        f.send(
            Method::PUT,
            &upload,
            token.as_deref(),
            "application/cbor",
            sealed.object.clone()
        )
        .await
        .code(),
        ErrorCode::Unsupported
    );
    assert_eq!(
        f.send(
            Method::PUT,
            &upload,
            token.as_deref(),
            "application/octet-stream",
            sealed.object.clone()
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    let object = f.get(&chunk_path, token.as_deref()).await;
    assert_eq!(
        (object.status, object.body),
        (StatusCode::OK, sealed.object.clone())
    );

    // Commits: append, conflict with the head in the body, list.
    let first = commit(
        &device,
        &key,
        collection,
        None,
        &[(1, vec![chunk])],
        &mut f.rng,
    );
    let appended: AppendResult = f
        .call(
            Method::POST,
            &format!("{base}/commits"),
            token.as_deref(),
            Some(&AppendCommit {
                expected: None,
                commit: first.clone(),
            }),
        )
        .await
        .ok();
    let AppendResult::Appended(head) = appended else {
        panic!("not appended: {appended:?}");
    };
    let stale = commit(
        &device,
        &key,
        collection,
        None,
        &[(2, Vec::new())],
        &mut f.rng,
    );
    let conflict = f
        .call(
            Method::POST,
            &format!("{base}/commits"),
            token.as_deref(),
            Some(&AppendCommit {
                expected: None,
                commit: stale,
            }),
        )
        .await;
    assert_eq!(
        (conflict.status, conflict.error().unwrap().head),
        (StatusCode::CONFLICT, Some(head))
    );
    assert_eq!(
        f.get(&format!("{base}/head"), token.as_deref())
            .await
            .ok::<Option<Head>>(),
        Some(head)
    );
    let listed: oxisoft_drive_proto::api::Commits = f
        .get(
            &format!("{base}/commits?after=0&limit=10"),
            token.as_deref(),
        )
        .await
        .ok();
    assert_eq!(listed.commits, [first]);
    assert_eq!(
        f.get(&format!("{base}/commits?after=x"), token.as_deref())
            .await
            .code(),
        ErrorCode::BadRequest
    );

    // Attestations.
    let attestation = Signed::sign(
        device.identity.signing_key(),
        &HeadAttestation {
            format: DEVICE_FORMAT,
            collection,
            seq: head.seq,
            hash: head.hash,
            device: device.id(),
            time_ms: 5,
        },
    );
    assert_eq!(
        f.call(
            Method::POST,
            &format!("{base}/heads"),
            token.as_deref(),
            Some(&attestation)
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    let attested: Vec<Signed<HeadAttestation>> =
        f.get(&format!("{base}/heads"), token.as_deref()).await.ok();
    assert_eq!(attested, [attestation]);

    // Listing, changing, trashing.
    let listed: Vec<CollectionInfo> = f.get("/v1/collections", token.as_deref()).await.ok();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].keys.len(), listed[0].head, listed[0].usage),
        (1, Some(head), sealed.object.len() as u64)
    );
    let patch = PatchCollection {
        retention_days: Some(2),
        config: None,
    };
    assert_eq!(
        f.call(Method::PATCH, &base, token.as_deref(), Some(&patch))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.get("/v1/collections", token.as_deref())
            .await
            .ok::<Vec<CollectionInfo>>()[0]
            .retention_days,
        2
    );
    assert_eq!(
        f.call::<()>(Method::DELETE, &base, token.as_deref(), None)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.get(&format!("{base}/head"), token.as_deref())
            .await
            .code(),
        ErrorCode::NotFound
    );
    assert!(
        f.get("/v1/collections", token.as_deref())
            .await
            .ok::<Vec<CollectionInfo>>()
            .is_empty()
    );
    // After the retention the trash is emptied and its chunk collected.
    f.advance(3 * DAY_MS);
    let report = f.api.service().collect_garbage().await.unwrap();
    assert_eq!((report.collections, report.chunks), (1, 1));
}

async fn limits<M: MetaStore + 'static>(mut f: Fixture<M>) {
    // Two requests a minute for `info` (see the fixture's limits).
    assert_eq!(f.get("/v1/info", None).await.status, StatusCode::OK);
    assert_eq!(f.get("/v1/info", None).await.status, StatusCode::OK);
    let limited = f.get("/v1/info", None).await;
    assert_eq!(
        (limited.status, limited.code()),
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
    );
    let seconds: u64 = limited.retry_after.unwrap().parse().unwrap();
    assert!((1..=61).contains(&seconds));
    // A chunk over the object limit (1 KiB here) is refused before it reaches the service.
    let mut device = f.new_device();
    let _account = f.create_account(&device).await;
    f.sign_in(&mut device).await;
    let path = format!(
        "/v1/collections/{}/chunks/{}?lease={}",
        hex(&[1; 16]),
        hex(&[2; 32]),
        hex(&[3; 16])
    );
    let big = f
        .send(
            Method::PUT,
            &path,
            device.token.as_deref(),
            "application/octet-stream",
            vec![0; 2048],
        )
        .await;
    assert_eq!(
        (big.status, big.code()),
        (StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::TooLarge)
    );
    f.api.forget_idle_clients();
}

fn tight_limits() -> (RateLimits, Settings) {
    let limits = RateLimits {
        info_per_minute: 2,
        ..RateLimits::default()
    };
    let mut settings = Settings::default();
    settings.limits.max_object = 1024;
    (limits, settings)
}

macro_rules! scenarios {
    ($fixture:ident) => {
        #[tokio::test]
        async fn info_and_wire_errors() {
            super::info_and_wire_errors($fixture(Default::default(), Default::default()).await)
                .await;
        }
        #[tokio::test]
        async fn accounts_and_sign_in() {
            super::accounts_and_sign_in($fixture(Default::default(), Default::default()).await)
                .await;
        }
        #[tokio::test]
        async fn devices_keys_pairing_and_recovery() {
            super::devices_keys_pairing_and_recovery(
                $fixture(Default::default(), Default::default()).await,
            )
            .await;
        }
        #[tokio::test]
        async fn collections_commits_and_chunks() {
            super::collections_commits_and_chunks(
                $fixture(Default::default(), Default::default()).await,
            )
            .await;
        }
        #[tokio::test]
        async fn limits() {
            let (limits, settings) = super::tight_limits();
            super::limits($fixture(limits, settings).await).await;
        }
    };
}

mod sqlite {
    use super::*;
    use oxisoft_drive_server_sqlite::SqliteStore;

    async fn fixture(limits: RateLimits, settings: Settings) -> Fixture<SqliteStore> {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(&dir.path().join("meta.db"))
            .await
            .unwrap();
        Fixture::new(store, Box::new(dir), limits, settings)
    }

    scenarios!(fixture);
}

mod postgres {
    use super::*;
    use oxisoft_drive_server_postgres::PostgresStore;
    use sqlx::Connection;

    /// A new database on `OXIDRIVE_TEST_POSTGRES_URL` (fails without it; server crate G3).
    async fn fixture(limits: RateLimits, settings: Settings) -> Fixture<PostgresStore> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::var("OXIDRIVE_TEST_POSTGRES_URL")
            .expect("OXIDRIVE_TEST_POSTGRES_URL must point at a PostgreSQL server for these tests");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!(
            "api{}_{stamp}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let mut admin = sqlx::PgConnection::connect(&base).await.unwrap();
        // The name is made of letters, digits and underscores only.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await
            .unwrap();
        let (prefix, _) = base.rsplit_once('/').unwrap();
        let store = PostgresStore::open(&format!("{prefix}/{name}"))
            .await
            .unwrap();
        Fixture::new(store, Box::new(()), limits, settings)
    }

    scenarios!(fixture);
}

// ── over a real socket ──────────────────────────────────────────────────────────────

/// Sign-in, an append, its event over the WebSocket, and a long poll answered by an
/// approval, through `reqwest` and `tokio-tungstenite` against a listening server.
#[tokio::test]
async fn over_a_real_socket() {
    use futures_util::StreamExt as _;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let dir = tempfile::tempdir().unwrap();
    let store = oxisoft_drive_server_sqlite::SqliteStore::open(&dir.path().join("meta.db"))
        .await
        .unwrap();
    let mut f = Fixture::new(
        store,
        Box::new(()),
        RateLimits::default(),
        Settings::default(),
    );
    let mut device = f.new_device();
    let mut account = f.create_account(&device).await;
    f.sign_in(&mut device).await;
    let token = device.token.clone().unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = f.api.router();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let http = reqwest::Client::new();
    let url = |path: &str| format!("http://{address}{path}");

    let info = http.get(url("/v1/info")).send().await.unwrap();
    assert_eq!(info.status(), StatusCode::OK);
    let _: ServerInfo = uncbor(&info.bytes().await.unwrap());

    // Events: subscribe, then append and receive the new head.
    let mut request = format!("ws://{address}/v1/events")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let key = CollectionKey::generate(&mut f.rng, 0);
    let collection = CollectionId::random(&mut f.rng);
    let create = CreateCollection {
        id: collection,
        key: envelope(EnvelopeKind::CollectionKey, 0, None, Some(collection)),
        config: Vec::new(),
    };
    let created = http
        .post(url("/v1/collections"))
        .bearer_auth(&token)
        .header("content-type", "application/cbor")
        .body(cbor(&create))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let first = commit(
        &device,
        &key,
        collection,
        None,
        &[(1, Vec::new())],
        &mut f.rng,
    );
    let appended = http
        .post(url(&format!(
            "/v1/collections/{}/commits",
            hex(collection.as_bytes())
        )))
        .bearer_auth(&token)
        .header("content-type", "application/cbor")
        .body(cbor(&AppendCommit {
            expected: None,
            commit: first,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(appended.status(), StatusCode::OK);
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Binary(bytes) = frame else {
        panic!("not a binary frame: {frame:?}");
    };
    assert_eq!(uncbor::<Event>(&bytes), Event::Head { collection, seq: 1 });

    // A long poll that an approval ends early.
    let mut second = f.new_device();
    let request = PairingRequest {
        verifying_key: second.identity.verifying_key(),
        kem_key: second.identity.kem_public_key(),
    };
    let created: PairingCreated = uncbor(
        &http
            .post(url("/v1/pairings"))
            .header("content-type", "application/cbor")
            .body(cbor(&request))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    );
    let path = format!("/v1/pairings/{}", hex(created.pairing.as_bytes()));
    let poll = tokio::spawn({
        let (http, poll_url) = (http.clone(), url(&format!("{path}?wait=20")));
        async move {
            let started = std::time::Instant::now();
            let bytes = http
                .get(poll_url)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
            (uncbor::<PairingState>(&bytes), started.elapsed())
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let certificate = account.certificate(&second, &mut f.rng);
    let put = PutDevices {
        list: account.list(2, &[device.id(), second.id()], &[]),
        new_certificates: vec![certificate.clone()],
        envelopes: Vec::new(),
    };
    let _: Devices = f
        .call(Method::PUT, "/v1/devices", Some(&token), Some(&put))
        .await
        .ok();
    let approval = PairingApproval {
        account: account.id,
        signing_key: account.signing.verifying_key(),
        certificate,
        envelopes: Vec::new(),
        mac: MacBytes([2; 32]),
    };
    let approved = http
        .post(url(&format!("{path}/approve")))
        .bearer_auth(&token)
        .header("content-type", "application/cbor")
        .body(cbor(&approval))
        .send()
        .await
        .unwrap();
    assert_eq!(approved.status(), StatusCode::NO_CONTENT);
    let (state, waited) = poll.await.unwrap();
    assert_eq!(state, PairingState::Approved(Box::new(approval)));
    assert!(
        waited < std::time::Duration::from_secs(10),
        "the approval didn't end the wait"
    );
    // The devices event reached the socket too.
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Message::Binary(bytes) = frame else {
        panic!("not a binary frame: {frame:?}");
    };
    assert_eq!(
        uncbor::<Event>(&bytes),
        Event::Devices {
            version: 2,
            by_recovery: false
        }
    );
    f.sign_in(&mut second).await;
    drop(dir);
}
