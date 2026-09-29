//! Request and response bodies of the server API (`server-api.md`). CBOR maps throughout;
//! chunk objects travel as raw bytes and have no type here.

use minicbor::{Decode, Encode};
use oxisoft_drive_crypto::kem::KemPublicKey;
use oxisoft_drive_crypto::sign::{Signature, VerifyingKey};

use crate::cbor;
use crate::device::{DeviceCertificate, DeviceList, KemKeyPublication};
use crate::envelope::Envelope;
use crate::signed::Signed;
use crate::{
    AccountId, ChunkId, CollectionId, Commit, CommitHash, DeviceId, LeaseId, PairingId, Seq,
};
use oxisoft_drive_crypto::hash::Digest;

/// API protocol version implemented by this code.
pub const PROTOCOL_VERSION: u16 = 1;

/// `GET /v1/info`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ServerInfo {
    /// Server software version.
    #[n(0)]
    pub version: String,
    /// Supported API protocol versions.
    #[n(1)]
    pub protocols: Vec<u16>,
    /// Supported crypto suite IDs.
    #[n(2)]
    pub suites: Vec<u8>,
    /// Size limits.
    #[n(3)]
    pub limits: Limits,
}

/// Size limits advertised by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Limits {
    /// Largest chunk object in bytes.
    #[n(0)]
    pub max_object: u32,
    /// Largest encoded commit in bytes.
    #[n(1)]
    pub max_commit: u32,
    /// Most items in one batch request.
    #[n(2)]
    pub max_batch: u32,
}

/// `POST /v1/auth/challenge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ChallengeRequest {
    /// The device asking.
    #[n(0)]
    pub device: DeviceId,
}

/// The server's challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Challenge {
    /// Random nonce to sign.
    #[cbor(n(0), with = "minicbor::bytes")]
    pub nonce: [u8; 32],
    /// When it expires, milliseconds since the Unix epoch.
    #[n(1)]
    pub expires_ms: u64,
}

/// `POST /v1/auth/session`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct SessionRequest {
    /// The device.
    #[n(0)]
    pub device: DeviceId,
    /// The nonce from [`Challenge`].
    #[cbor(n(1), with = "minicbor::bytes")]
    pub nonce: [u8; 32],
    /// Signature over [`auth_message`](crate::auth_message).
    #[cbor(n(2), with = "cbor::signature")]
    pub signature: Signature,
}

/// A session token.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Session {
    /// Opaque bearer token.
    #[n(0)]
    pub token: String,
    /// When it expires, milliseconds since the Unix epoch.
    #[n(1)]
    pub expires_ms: u64,
}

/// `POST /v1/accounts`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct CreateAccount {
    /// The admin's one-time invite code.
    #[n(0)]
    pub invite: String,
    /// The new account's ID.
    #[n(1)]
    pub account: AccountId,
    /// The account signing key's public half.
    #[cbor(n(2), with = "cbor::verifying_key")]
    pub signing_key: VerifyingKey,
    /// The account KEM key, signed by the account.
    #[n(3)]
    pub kem_key: Signed<KemKeyPublication>,
    /// The first device's certificate.
    #[n(4)]
    pub first_device: Signed<DeviceCertificate>,
    /// The initial device list.
    #[n(5)]
    pub list: Signed<DeviceList>,
    /// Initial envelopes: account key to the device and to recovery, wrapped account keys.
    #[n(6)]
    pub envelopes: Vec<Envelope>,
}

/// The created account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AccountCreated {
    /// Its ID.
    #[n(0)]
    pub account: AccountId,
}

/// `GET /v1/devices` and the response of `PUT /v1/devices`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Devices {
    /// The current signed list.
    #[n(0)]
    pub list: Signed<DeviceList>,
    /// Certificates of every listed device.
    #[n(1)]
    pub certificates: Vec<Signed<DeviceCertificate>>,
}

/// `PUT /v1/devices`: add or revoke devices.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct PutDevices {
    /// The new list; its version must exceed the current one.
    #[n(0)]
    pub list: Signed<DeviceList>,
    /// Certificates of devices new in the list.
    #[n(1)]
    pub new_certificates: Vec<Signed<DeviceCertificate>>,
    /// Envelopes for the new devices.
    #[n(2)]
    pub envelopes: Vec<Envelope>,
}

/// `GET /v1/keys`: every envelope the calling device needs.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Keys {
    /// The envelopes.
    #[n(0)]
    pub envelopes: Vec<Envelope>,
}

/// `PUT /v1/keys`: a new key epoch.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct PutKeys {
    /// The new epoch; must be the current one plus one.
    #[n(0)]
    pub epoch: u32,
    /// Its envelopes.
    #[n(1)]
    pub envelopes: Vec<Envelope>,
}

/// `POST /v1/pairings`, sent by the new device.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct PairingRequest {
    /// Its public signing key.
    #[cbor(n(0), with = "cbor::verifying_key")]
    pub verifying_key: VerifyingKey,
    /// Its public KEM key.
    #[cbor(n(1), with = "cbor::kem_key")]
    pub kem_key: KemPublicKey,
}

/// The pending pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct PairingCreated {
    /// Its ID, shown in the pairing code.
    #[n(0)]
    pub pairing: PairingId,
    /// When it expires, milliseconds since the Unix epoch.
    #[n(1)]
    pub expires_ms: u64,
}

/// `GET /v1/pairings/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum PairingState {
    /// Waiting for approval; the new device's keys, for the approving device to check.
    #[n(0)]
    Pending(#[n(0)] Box<PairingRequest>),
    /// Approved; what the new device needs.
    #[n(1)]
    Approved(#[n(0)] Box<PairingApproval>),
    /// Expired or unknown.
    #[n(2)]
    Expired,
}

/// `POST /v1/pairings/{id}/approve`, sent by the approving device.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct PairingApproval {
    /// The account the new device joins.
    #[n(0)]
    pub account: AccountId,
    /// The account signing key.
    #[cbor(n(1), with = "cbor::verifying_key")]
    pub signing_key: VerifyingKey,
    /// The new device's certificate.
    #[n(2)]
    pub certificate: Signed<DeviceCertificate>,
    /// The account key (every epoch) wrapped to the new device.
    #[n(3)]
    pub envelopes: Vec<Envelope>,
    /// MAC over [`approval_mac_data`](crate::approval_mac_data) with the pairing secret.
    #[n(4)]
    pub mac: MacBytes,
}

/// A pairing MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(transparent)]
pub struct MacBytes(#[cbor(n(0), with = "minicbor::bytes")] pub [u8; 32]);

impl From<Digest> for MacBytes {
    fn from(digest: Digest) -> Self {
        Self(*digest.as_bytes())
    }
}

impl From<MacBytes> for Digest {
    fn from(mac: MacBytes) -> Self {
        Self::from_bytes(mac.0)
    }
}

/// `GET /v1/accounts/{id}/recovery`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Recovery {
    /// The account key, wrapped with the recovery key.
    #[n(0)]
    pub account_key: Envelope,
    /// The account signing key, wrapped with the account key.
    #[n(1)]
    pub signing_key: Envelope,
    /// The account signing key's public half.
    #[cbor(n(2), with = "cbor::verifying_key")]
    pub signing_public: VerifyingKey,
}

/// `POST /v1/collections`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct CreateCollection {
    /// The new collection's ID.
    #[n(0)]
    pub id: CollectionId,
    /// Its key, wrapped with the account key.
    #[n(1)]
    pub key: Envelope,
    /// Its name and configuration, sealed with the account meta key.
    #[cbor(n(2), with = "minicbor::bytes")]
    pub config: Vec<u8>,
}

/// `PATCH /v1/collections/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct PatchCollection {
    /// New retention for versions and trash, in days.
    #[n(0)]
    pub retention_days: Option<u32>,
    /// New sealed configuration.
    #[cbor(n(1), with = "minicbor::bytes")]
    pub config: Option<Vec<u8>>,
}

/// One collection, as listed by `GET /v1/collections`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct CollectionInfo {
    /// Its ID.
    #[n(0)]
    pub id: CollectionId,
    /// Its key envelopes, one per epoch.
    #[n(1)]
    pub keys: Vec<Envelope>,
    /// Sealed name and configuration.
    #[cbor(n(2), with = "minicbor::bytes")]
    pub config: Vec<u8>,
    /// Retention for versions and trash, in days.
    #[n(3)]
    pub retention_days: u32,
    /// Stored bytes (padded objects).
    #[n(4)]
    pub usage: u64,
    /// Current head, if any commit exists.
    #[n(5)]
    pub head: Option<Head>,
}

/// A collection's head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Head {
    /// Sequence number of the newest commit.
    #[n(0)]
    pub seq: Seq,
    /// Its hash.
    #[n(1)]
    pub hash: CommitHash,
}

/// `GET /v1/collections/{id}/commits`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Commits {
    /// Commits in order.
    #[n(0)]
    pub commits: Vec<Commit>,
    /// Whether more follow.
    #[n(1)]
    pub more: bool,
}

/// `POST /v1/collections/{id}/commits`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct AppendCommit {
    /// The head the commit builds on; `None` for the first commit.
    #[n(0)]
    pub expected: Option<Head>,
    /// The commit.
    #[n(1)]
    pub commit: Commit,
}

/// Result of appending a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum AppendResult {
    /// Appended; the new head.
    #[n(0)]
    Appended(#[n(0)] Head),
    /// Someone else committed first; the current head (sync protocol §2).
    #[n(1)]
    Conflict(#[n(0)] Option<Head>),
}

/// `POST /v1/collections/{id}/chunks/missing`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct MissingRequest {
    /// Chunks the device is about to reference.
    #[n(0)]
    pub ids: Vec<ChunkId>,
}

/// Which of them the server lacks, and a lease protecting all of them.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Missing {
    /// Chunks to upload.
    #[n(0)]
    pub ids: Vec<ChunkId>,
    /// The upload lease.
    #[n(1)]
    pub lease: LeaseId,
    /// When the lease expires, milliseconds since the Unix epoch.
    #[n(2)]
    pub lease_expires_ms: u64,
}

/// A message on the `GET /v1/events` WebSocket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum Event {
    /// A collection has a new head.
    #[n(0)]
    Head {
        /// The collection.
        #[n(0)]
        collection: CollectionId,
        /// The new head's sequence number.
        #[n(1)]
        seq: Seq,
    },
    /// The device list changed.
    #[n(1)]
    Devices {
        /// The new list version.
        #[n(0)]
        version: u64,
        /// Whether a device was added with the recovery key: an alarm to show.
        #[n(1)]
        by_recovery: bool,
    },
    /// A new key epoch.
    #[n(2)]
    Keys {
        /// The epoch.
        #[n(0)]
        epoch: u32,
    },
    /// Another device published a head attestation.
    #[n(3)]
    Attestation {
        /// The collection.
        #[n(0)]
        collection: CollectionId,
    },
    // 4 is retired: a "pairing waiting" event the server can't address, since a new device
    // isn't signed in to any account (server HTTP I4). Never reuse it.
}

/// Machine-readable error codes (server API §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
pub enum ErrorCode {
    /// The request is malformed.
    #[n(0)]
    BadRequest,
    /// No valid session.
    #[n(1)]
    Unauthorized,
    /// Authenticated, but not allowed.
    #[n(2)]
    Forbidden,
    /// No such object.
    #[n(3)]
    NotFound,
    /// Stale expected head or version: fetch and retry.
    #[n(4)]
    Conflict,
    /// Over a size limit.
    #[n(5)]
    TooLarge,
    /// Too many requests; retry later.
    #[n(6)]
    RateLimited,
    /// Over quota.
    #[n(7)]
    QuotaExceeded,
    /// Protocol version or suite not supported.
    #[n(8)]
    Unsupported,
    /// Server-side failure.
    #[n(9)]
    Internal,
}

/// The body of every error response.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct ErrorBody {
    /// What went wrong.
    #[n(0)]
    pub code: ErrorCode,
    /// A human-readable explanation.
    #[n(1)]
    pub message: String,
    /// The current head, for [`ErrorCode::Conflict`] on commits.
    #[n(2)]
    pub head: Option<Head>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DEVICE_FORMAT, DeviceEntry};
    use crate::envelope::EnvelopeKind;
    use crate::test_util::rng;
    use crate::{CertificateHash, CommitDraft};
    use oxisoft_drive_crypto::hash;
    use oxisoft_drive_crypto::keys::{
        AccountKemKey, AccountKey, AccountSigningKey, DeviceIdentity,
    };
    use proptest::prelude::*;

    fn round_trip<T>(value: &T)
    where
        T: Encode<()> + for<'b> Decode<'b, ()> + PartialEq + std::fmt::Debug,
    {
        let bytes = minicbor::to_vec(value).unwrap();
        assert_eq!(&minicbor::decode::<T>(&bytes).unwrap(), value);
    }

    struct Fixture {
        account: AccountId,
        signing: AccountSigningKey,
        device: DeviceIdentity,
        certificate: Signed<DeviceCertificate>,
        list: Signed<DeviceList>,
        envelope: Envelope,
        head: Head,
        commit: Commit,
    }

    fn fixture() -> Fixture {
        let mut rng = rng(1);
        let account = AccountId::random(&mut rng);
        let signing = AccountSigningKey::generate(&mut rng);
        let meta = AccountKey::generate(&mut rng, 0).meta();
        let device = DeviceIdentity::generate(&mut rng);
        let certificate = DeviceCertificate::new(
            account,
            (device.verifying_key(), device.kem_public_key()),
            "phone",
            &meta,
            &mut rng,
            1,
        )
        .unwrap();
        let list = DeviceList {
            format: DEVICE_FORMAT,
            account,
            version: 1,
            devices: vec![DeviceEntry {
                device: certificate.device,
                certificate: CertificateHash(hash::hash(b"c")),
            }],
            revoked: vec![],
        };
        let commit = Commit::create(
            device.signing_key(),
            &CommitDraft {
                collection: CollectionId::from_bytes([4; 16]),
                seq: 1,
                prev: None,
                epoch: 0,
                time_ms: 2,
            },
            &[],
        );
        Fixture {
            account,
            certificate: Signed::sign(signing.signing_key(), &certificate),
            list: Signed::sign(signing.signing_key(), &list),
            signing,
            device,
            envelope: Envelope {
                kind: EnvelopeKind::AccountKeyToDevice,
                epoch: 0,
                device: Some(DeviceId::from_bytes([5; 16])),
                collection: None,
                wrapped: vec![9; 40],
            },
            head: Head {
                seq: 1,
                hash: commit.hash(),
            },
            commit,
        }
    }

    #[test]
    fn auth_and_account_messages_round_trip() {
        let f = fixture();
        let kem = AccountKemKey::generate(&mut rng(2));
        round_trip(&ServerInfo {
            version: "0.1.0".into(),
            protocols: vec![PROTOCOL_VERSION],
            suites: vec![1],
            limits: Limits {
                max_object: 4_300_000,
                max_commit: 1_000_000,
                max_batch: 1000,
            },
        });
        let device = DeviceId::from_key(&f.device.verifying_key());
        round_trip(&ChallengeRequest { device });
        round_trip(&Challenge {
            nonce: [3; 32],
            expires_ms: 9,
        });
        round_trip(&SessionRequest {
            device,
            nonce: [3; 32],
            signature: f.device.signing_key().sign(
                oxisoft_drive_crypto::sign::SignContext::AuthChallenge,
                &crate::auth_message("https://x", &[3; 32], device),
            ),
        });
        round_trip(&Session {
            token: "t".into(),
            expires_ms: 1,
        });
        round_trip(&CreateAccount {
            invite: "invite".into(),
            account: f.account,
            signing_key: f.signing.verifying_key(),
            kem_key: Signed::sign(
                f.signing.signing_key(),
                &KemKeyPublication {
                    format: DEVICE_FORMAT,
                    account: f.account,
                    kem_key: kem.public_key(),
                },
            ),
            first_device: f.certificate.clone(),
            list: f.list.clone(),
            envelopes: vec![f.envelope.clone()],
        });
        round_trip(&AccountCreated { account: f.account });
    }

    #[test]
    fn device_key_and_pairing_messages_round_trip() {
        let f = fixture();
        round_trip(&Devices {
            list: f.list.clone(),
            certificates: vec![f.certificate.clone()],
        });
        round_trip(&PutDevices {
            list: f.list.clone(),
            new_certificates: vec![f.certificate.clone()],
            envelopes: vec![f.envelope.clone()],
        });
        round_trip(&Keys {
            envelopes: vec![f.envelope.clone()],
        });
        round_trip(&PutKeys {
            epoch: 1,
            envelopes: vec![],
        });
        let request = PairingRequest {
            verifying_key: f.device.verifying_key(),
            kem_key: f.device.kem_public_key(),
        };
        round_trip(&request);
        round_trip(&PairingCreated {
            pairing: PairingId::from_bytes([6; 16]),
            expires_ms: 3,
        });
        let approval = PairingApproval {
            account: f.account,
            signing_key: f.signing.verifying_key(),
            certificate: f.certificate.clone(),
            envelopes: vec![f.envelope.clone()],
            mac: MacBytes::from(hash::hash(b"mac")),
        };
        assert_eq!(Digest::from(approval.mac), hash::hash(b"mac"));
        round_trip(&PairingState::Pending(Box::new(request)));
        round_trip(&PairingState::Approved(Box::new(approval)));
        round_trip(&PairingState::Expired);
        round_trip(&Recovery {
            account_key: f.envelope.clone(),
            signing_key: f.envelope.clone(),
            signing_public: f.signing.verifying_key(),
        });
    }

    #[test]
    fn collection_and_commit_messages_round_trip() {
        let f = fixture();
        round_trip(&CreateCollection {
            id: CollectionId::from_bytes([7; 16]),
            key: f.envelope.clone(),
            config: vec![1, 2],
        });
        round_trip(&PatchCollection {
            retention_days: Some(30),
            config: None,
        });
        round_trip(&CollectionInfo {
            id: CollectionId::from_bytes([7; 16]),
            keys: vec![f.envelope.clone()],
            config: vec![],
            retention_days: 30,
            usage: 10,
            head: Some(f.head),
        });
        round_trip(&Commits {
            commits: vec![f.commit.clone()],
            more: false,
        });
        round_trip(&AppendCommit {
            expected: None,
            commit: f.commit.clone(),
        });
        round_trip(&AppendResult::Appended(f.head));
        round_trip(&AppendResult::Conflict(None));
        round_trip(&MissingRequest {
            ids: vec![ChunkId(hash::hash(b"x"))],
        });
        round_trip(&Missing {
            ids: vec![],
            lease: LeaseId::from_bytes([8; 16]),
            lease_expires_ms: 4,
        });
    }

    #[test]
    fn events_and_errors_round_trip() {
        let f = fixture();
        for event in [
            Event::Head {
                collection: CollectionId::from_bytes([1; 16]),
                seq: 2,
            },
            Event::Devices {
                version: 3,
                by_recovery: true,
            },
            Event::Keys { epoch: 1 },
            Event::Attestation {
                collection: CollectionId::from_bytes([1; 16]),
            },
        ] {
            round_trip(&event);
        }
        for code in [
            ErrorCode::BadRequest,
            ErrorCode::Unauthorized,
            ErrorCode::Forbidden,
            ErrorCode::NotFound,
            ErrorCode::Conflict,
            ErrorCode::TooLarge,
            ErrorCode::RateLimited,
            ErrorCode::QuotaExceeded,
            ErrorCode::Unsupported,
            ErrorCode::Internal,
        ] {
            round_trip(&ErrorBody {
                code,
                message: "m".into(),
                head: Some(f.head),
            });
        }
    }

    /// Format evolution (N4): an older reader ignores fields it doesn't know, and a newer
    /// reader accepts messages without its new optional fields.
    #[test]
    fn older_and_newer_definitions_read_each_other() {
        #[derive(Debug, PartialEq, Encode, Decode)]
        #[cbor(map)]
        struct HeadV2 {
            #[n(0)]
            seq: Seq,
            #[n(1)]
            hash: CommitHash,
            #[n(2)]
            note: Option<String>,
        }
        let hash = CommitHash(hash::hash(b"h"));
        let newer = HeadV2 {
            seq: 5,
            hash,
            note: Some("added later".into()),
        };
        let old: Head = minicbor::decode(&minicbor::to_vec(&newer).unwrap()).unwrap();
        assert_eq!(old, Head { seq: 5, hash });
        let new: HeadV2 = minicbor::decode(&minicbor::to_vec(old).unwrap()).unwrap();
        assert_eq!(new.note, None);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        /// Hostile bytes produce errors, never panics or unbounded allocation.
        #[test]
        fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = minicbor::decode::<CreateAccount>(&bytes);
            let _ = minicbor::decode::<Commits>(&bytes);
            let _ = minicbor::decode::<PairingState>(&bytes);
            let _ = minicbor::decode::<Event>(&bytes);
            let _ = minicbor::decode::<ErrorBody>(&bytes);
            let _ = minicbor::decode::<crate::NodeRecord>(&bytes);
            let _ = crate::PairingCode::from_bytes(&bytes);
        }
    }
}
