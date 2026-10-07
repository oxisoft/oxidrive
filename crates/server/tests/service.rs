//! The service's rules on the real SQLite store and an in-memory blob store (server storage
//! §6): every rejection, leases and quotas, pruning, garbage collection and fsck.

#![cfg(test)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use oxisoft_drive_chunking::{ChunkKeys, seal_chunk};
use oxisoft_drive_crypto::hash;
use oxisoft_drive_crypto::keys::{AccountKey, AccountSigningKey, CollectionKey, DeviceIdentity};
use oxisoft_drive_proto::api::Head;
use oxisoft_drive_proto::{
    AccountId, CertificateHash, ChunkId, ChunkRef, CollectionId, Commit, CommitDraft, ContentHash,
    DEVICE_FORMAT, DeviceCertificate, DeviceEntry, DeviceList, FileInfo, LeaseId, NODE_FORMAT,
    Name, NodeId, NodeKind, NodePayload, NodeRecord, RecordContext, RecordSlot, Signed, Version,
};
use oxisoft_drive_server::{BlobKey, BlobOp, Clock, MemBlobStore, Service, ServiceError, Settings};
use oxisoft_drive_server_sqlite::SqliteStore;
use oxisoft_drive_server_store::MetaStore;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const DAY_MS: u64 = 86_400_000;

#[derive(Debug, Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

type TestService = Service<SqliteStore, Arc<MemBlobStore>, TestClock, ChaCha20Rng>;

struct Fixture {
    service: TestService,
    blobs: Arc<MemBlobStore>,
    clock: TestClock,
    account: AccountId,
    account_key: AccountKey,
    signing: AccountSigningKey,
    devices: Vec<DeviceIdentity>,
    certificates: Vec<Signed<DeviceCertificate>>,
    collection: CollectionId,
    key: CollectionKey,
    rng: ChaCha20Rng,
    dir: tempfile::TempDir,
}

impl Fixture {
    /// An account with devices 0 and 1 trusted, and one collection.
    async fn new() -> Self {
        Self::with_quota(1 << 30).await
    }

    async fn with_quota(quota: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let meta = SqliteStore::open(&dir.path().join("meta.db"))
            .await
            .unwrap();
        let blobs = Arc::new(MemBlobStore::new());
        let clock = TestClock(Arc::new(AtomicU64::new(10 * DAY_MS)));
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let service = Service::new(
            meta,
            Arc::clone(&blobs),
            clock.clone(),
            ChaCha20Rng::seed_from_u64(8),
            Settings::default(),
        );
        let signing = AccountSigningKey::generate(&mut rng);
        let mut fixture = Self {
            service,
            blobs,
            clock,
            account: AccountId::random(&mut rng),
            account_key: AccountKey::generate(&mut rng, 0),
            signing,
            devices: (0..3).map(|_| DeviceIdentity::generate(&mut rng)).collect(),
            certificates: Vec::new(),
            collection: CollectionId::random(&mut rng),
            key: CollectionKey::generate(&mut rng, 0),
            rng,
            dir,
        };
        fixture
            .service
            .create_account(fixture.account, &fixture.signing.verifying_key(), quota)
            .await
            .unwrap();
        fixture.certificates = (0..3)
            .map(|device| fixture.make_certificate(device))
            .collect();
        let certificates = vec![fixture.certificate(0), fixture.certificate(1)];
        let list = fixture.list(1, &certificates, &[]);
        fixture
            .service
            .put_device_list(fixture.account, None, &list, &certificates)
            .await
            .unwrap();
        fixture
            .service
            .create_collection(fixture.account, fixture.collection, vec![1], 30)
            .await
            .unwrap();
        fixture
    }

    /// Device `device`'s certificate, made once.
    fn certificate(&self, device: usize) -> Signed<DeviceCertificate> {
        self.certificates[device].clone()
    }

    fn make_certificate(&mut self, device: usize) -> Signed<DeviceCertificate> {
        let identity = &self.devices[device];
        let certificate = DeviceCertificate::new(
            self.account,
            (identity.verifying_key(), identity.kem_public_key()),
            "device",
            &self.account_key.meta(),
            &mut self.rng,
            1,
        )
        .unwrap();
        Signed::sign(self.signing.signing_key(), &certificate)
    }

    fn list(
        &self,
        version: u64,
        trusted: &[Signed<DeviceCertificate>],
        revoked: &[usize],
    ) -> Signed<DeviceList> {
        let list = DeviceList {
            format: DEVICE_FORMAT,
            account: self.account,
            version,
            devices: trusted
                .iter()
                .map(|signed| DeviceEntry {
                    device: signed.decode_unverified().unwrap().device,
                    certificate: CertificateHash(signed.hash()),
                })
                .collect(),
            revoked: revoked
                .iter()
                .map(|device| {
                    oxisoft_drive_proto::DeviceId::from_key(&self.devices[*device].verifying_key())
                })
                .collect(),
        };
        Signed::sign(self.signing.signing_key(), &list)
    }

    fn chunk(&mut self, plaintext: &[u8]) -> (ChunkId, Vec<u8>) {
        let sealed = seal_chunk(
            &ChunkKeys::new(&self.key),
            &mut self.rng,
            self.collection.as_bytes(),
            plaintext,
        )
        .unwrap();
        (ChunkId(sealed.id), sealed.object)
    }

    /// A commit by `device` following `previous`, one record per (node, chunks).
    fn commit(
        &mut self,
        device: usize,
        previous: Option<Head>,
        records: &[(u8, Vec<ChunkId>)],
    ) -> Commit {
        let seq = previous.map_or(1, |head| head.seq + 1);
        let context = RecordContext {
            collection: self.collection,
            seq,
            epoch: 0,
        };
        let identity = &self.devices[device];
        let sealed: Vec<NodeRecord> = records
            .iter()
            .map(|(node, chunks)| {
                let payload = NodePayload {
                    format: NODE_FORMAT,
                    parent: None,
                    name: Name::new(&format!("file {node}")).unwrap(),
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
                        device: oxisoft_drive_proto::DeviceId::from_key(&identity.verifying_key()),
                        counter: seq,
                    },
                    base: None,
                };
                NodeRecord::seal(
                    NodeId::from_bytes([*node; 16]),
                    &payload,
                    &self.key.meta(),
                    &mut self.rng,
                    &context,
                )
                .unwrap()
            })
            .collect();
        Commit::create(
            identity.signing_key(),
            &CommitDraft {
                collection: self.collection,
                seq,
                prev: previous.map(|head| head.hash),
                epoch: 0,
                time_ms: 1,
            },
            &sealed,
        )
    }

    /// Uploads chunks the server lacks, under a fresh lease.
    async fn upload(&mut self, chunks: &[(ChunkId, Vec<u8>)]) -> LeaseId {
        let ids: Vec<ChunkId> = chunks.iter().map(|(id, _)| *id).collect();
        let missing = self
            .service
            .missing(self.account, self.collection, &ids)
            .await
            .unwrap();
        for (id, object) in chunks {
            if missing.ids.contains(id) {
                self.service
                    .put_chunk(self.account, self.collection, missing.lease, *id, object)
                    .await
                    .unwrap();
            }
        }
        missing.lease
    }

    async fn append(&self, expected: Option<Head>, commit: &Commit) -> Result<Head, ServiceError> {
        self.service
            .append(self.account, self.collection, expected, commit)
            .await
    }

    fn advance(&self, ms: u64) {
        self.clock.0.fetch_add(ms, Ordering::SeqCst);
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "reads like an assertion around a call"
)]
fn invalid(result: Result<impl std::fmt::Debug, ServiceError>) -> bool {
    matches!(result, Err(ServiceError::Invalid(_)))
}

#[tokio::test]
async fn upload_commit_and_read_back() {
    let mut f = Fixture::new().await;
    let chunks = [f.chunk(b"first chunk"), f.chunk(b"second chunk")];
    f.upload(&chunks).await;
    let ids: Vec<ChunkId> = chunks.iter().map(|(id, _)| *id).collect();
    let commit = f.commit(0, None, &[(1, ids.clone()), (2, Vec::new())]);
    let head = f.append(None, &commit).await.unwrap();
    assert_eq!(
        head,
        Head {
            seq: 1,
            hash: commit.hash()
        }
    );
    assert_eq!(
        f.service.head(f.account, f.collection).await.unwrap(),
        Some(head)
    );
    let read = f
        .service
        .commits_after(f.account, f.collection, 0, 10)
        .await
        .unwrap();
    assert_eq!((read.commits, read.more), (vec![commit.clone()], false));
    for (id, object) in &chunks {
        assert_eq!(
            &f.service
                .get_chunk(f.account, f.collection, *id)
                .await
                .unwrap(),
            object
        );
    }
    // Paging reports that more follow.
    let second = f.commit(1, Some(head), &[(2, ids)]);
    f.append(Some(head), &second).await.unwrap();
    let page = f
        .service
        .commits_after(f.account, f.collection, 0, 1)
        .await
        .unwrap();
    assert_eq!((page.commits.len(), page.more), (1, true));
    assert_eq!(
        f.service
            .get_chunk(f.account, f.collection, ChunkId(hash::hash(b"x")))
            .await,
        Err(ServiceError::NotFound)
    );
}

#[tokio::test]
async fn device_list_rules() {
    let mut f = Fixture::new().await;
    let (zero, one, two) = (f.certificate(0), f.certificate(1), f.certificate(2));
    let add_two = f.list(2, &[zero.clone(), one.clone(), two.clone()], &[]);
    // Stale expectations conflict.
    assert_eq!(
        f.service
            .put_device_list(f.account, None, &add_two, std::slice::from_ref(&two))
            .await,
        Err(ServiceError::Conflict(None))
    );
    // A trusted device needs a certificate.
    assert!(invalid(
        f.service
            .put_device_list(f.account, Some(1), &add_two, &[])
            .await
    ));
    f.service
        .put_device_list(f.account, Some(1), &add_two, std::slice::from_ref(&two))
        .await
        .unwrap();
    // Same version again: stale, like a list another device got in first.
    let again = f.list(2, std::slice::from_ref(&zero), &[]);
    assert_eq!(
        f.service
            .put_device_list(f.account, Some(2), &again, &[])
            .await,
        Err(ServiceError::Conflict(None))
    );
    // Revoking device 1, then trusting it again, is refused.
    let revoke = f.list(3, &[zero.clone(), two.clone()], &[1]);
    f.service
        .put_device_list(f.account, Some(2), &revoke, &[])
        .await
        .unwrap();
    let readd = f.list(4, &[zero.clone(), one.clone(), two.clone()], &[]);
    assert!(invalid(
        f.service
            .put_device_list(f.account, Some(3), &readd, &[])
            .await
    ));
    // A list signed by another key is refused.
    let stranger = AccountSigningKey::generate(&mut f.rng);
    let forged = Signed::sign(
        stranger.signing_key(),
        &f.list(4, std::slice::from_ref(&zero), &[1])
            .decode_unverified()
            .unwrap(),
    );
    assert!(invalid(
        f.service
            .put_device_list(f.account, Some(3), &forged, &[])
            .await
    ));
    // An entry whose certificate hash doesn't match.
    let mut wrong = f
        .list(4, &[zero.clone(), two.clone()], &[1])
        .decode_unverified()
        .unwrap();
    wrong.devices[1].certificate = CertificateHash(hash::hash(b"other"));
    let wrong = Signed::sign(f.signing.signing_key(), &wrong);
    assert!(invalid(
        f.service
            .put_device_list(f.account, Some(3), &wrong, &[])
            .await
    ));
    // A list for another account.
    let mut elsewhere = f.list(4, &[zero], &[1]).decode_unverified().unwrap();
    elsewhere.account = AccountId::from_bytes([1; 16]);
    let elsewhere = Signed::sign(f.signing.signing_key(), &elsewhere);
    assert!(invalid(
        f.service
            .put_device_list(f.account, Some(3), &elsewhere, &[])
            .await
    ));
    // Unknown accounts.
    assert_eq!(
        f.service
            .put_device_list(AccountId::from_bytes([2; 16]), None, &add_two, &[])
            .await,
        Err(ServiceError::NotFound)
    );
}

#[tokio::test]
async fn commits_from_untrusted_or_revoked_devices_are_refused() {
    let mut f = Fixture::new().await;
    // Device 2 was never trusted.
    let stranger = f.commit(2, None, &[(1, Vec::new())]);
    assert_eq!(
        f.append(None, &stranger).await,
        Err(ServiceError::Untrusted)
    );
    // Device 1 is revoked.
    let zero = f.certificate(0);
    let revoke = f.list(2, &[zero], &[1]);
    f.service
        .put_device_list(f.account, Some(1), &revoke, &[])
        .await
        .unwrap();
    let revoked = f.commit(1, None, &[(1, Vec::new())]);
    assert_eq!(f.append(None, &revoked).await, Err(ServiceError::Untrusted));
    // A header claiming device 0 but signed by device 1.
    let mut forged = f.commit(1, None, &[(1, Vec::new())]);
    let genuine = f.commit(0, None, &[(1, Vec::new())]);
    forged.header = Signed::sign(
        f.devices[1].signing_key(),
        &genuine.header.decode_unverified().unwrap(),
    );
    assert!(invalid(f.append(None, &forged).await));
    f.append(None, &genuine).await.unwrap();
}

#[tokio::test]
async fn malformed_and_stale_commits_are_refused() {
    let mut f = Fixture::new().await;
    let first = f.commit(0, None, &[(1, Vec::new())]);
    let head = f.append(None, &first).await.unwrap();
    // Stale: the current head comes back.
    let stale = f.commit(0, None, &[(2, Vec::new())]);
    assert_eq!(
        f.append(None, &stale).await,
        Err(ServiceError::Conflict(Some(head)))
    );
    // A record changed after signing.
    let mut tampered = f.commit(0, Some(head), &[(2, Vec::new())]);
    if let RecordSlot::Present(bytes) = &mut tampered.records[0] {
        bytes[0] ^= 1;
    }
    assert!(invalid(f.append(Some(head), &tampered).await));
    // A pruned slot in a new commit.
    let mut pruned = f.commit(0, Some(head), &[(2, Vec::new())]);
    pruned.prune(0);
    assert!(invalid(f.append(Some(head), &pruned).await));
    // A commit for another collection.
    let other = CollectionId::from_bytes([3; 16]);
    f.service
        .create_collection(f.account, other, Vec::new(), 30)
        .await
        .unwrap();
    let moved = f.commit(0, None, &[(2, Vec::new())]);
    assert!(invalid(
        f.service.append(f.account, other, None, &moved).await
    ));
    // A chunk nobody uploaded.
    let (ghost, _) = f.chunk(b"never uploaded");
    let wanting = f.commit(0, Some(head), &[(2, vec![ghost])]);
    assert_eq!(
        f.append(Some(head), &wanting).await,
        Err(ServiceError::MissingChunks(vec![ghost]))
    );
    // Over the commit size limit.
    let many: Vec<(u8, Vec<ChunkId>)> = (0..=255).map(|node| (node, Vec::new())).collect();
    let huge = f.commit(0, Some(head), &many);
    let tight = Settings {
        limits: oxisoft_drive_proto::api::Limits {
            max_commit: 1000,
            ..Settings::default().limits
        },
        ..Settings::default()
    };
    let small = Service::new(
        SqliteStore::open(&f.dir.path().join("other.db"))
            .await
            .unwrap(),
        MemBlobStore::new(),
        f.clock.clone(),
        ChaCha20Rng::seed_from_u64(1),
        tight,
    );
    small
        .create_account(f.account, &f.signing.verifying_key(), 1)
        .await
        .unwrap();
    small
        .create_collection(f.account, f.collection, Vec::new(), 1)
        .await
        .unwrap();
    assert_eq!(
        small.append(f.account, f.collection, None, &huge).await,
        Err(ServiceError::TooLarge)
    );
    // No device list at all.
    let fine = f.commit(0, None, &[(1, Vec::new())]);
    assert_eq!(
        small.append(f.account, f.collection, None, &fine).await,
        Err(ServiceError::Untrusted)
    );
    // Someone else's collection is not found.
    let stranger = AccountId::from_bytes([9; 16]);
    f.service
        .create_account(stranger, &f.signing.verifying_key(), 1)
        .await
        .unwrap();
    assert_eq!(
        f.service
            .append(stranger, f.collection, Some(head), &stale)
            .await,
        Err(ServiceError::NotFound)
    );
    assert_eq!(
        f.service.head(stranger, f.collection).await,
        Err(ServiceError::NotFound)
    );
}

#[tokio::test]
async fn leases_objects_and_quotas() {
    let mut f = Fixture::with_quota(3000).await;
    let (id, object) = f.chunk(&[7; 500]);
    let (other_id, other_object) = f.chunk(&[8; 500]);
    let missing = f
        .service
        .missing(f.account, f.collection, &[id, id])
        .await
        .unwrap();
    assert_eq!(missing.ids, [id]);
    assert_eq!(
        missing.lease_expires_ms,
        10 * DAY_MS + Settings::default().lease_ms
    );
    let put = |lease, chunk, object: Vec<u8>| {
        let service = &f.service;
        let (account, collection) = (f.account, f.collection);
        async move {
            service
                .put_chunk(account, collection, lease, chunk, &object)
                .await
        }
    };
    // The lease covers `id` only, in this collection, until it expires.
    assert_eq!(
        put(missing.lease, other_id, other_object.clone()).await,
        Err(ServiceError::BadLease)
    );
    assert_eq!(
        put(LeaseId::from_bytes([1; 16]), id, object.clone()).await,
        Err(ServiceError::BadLease)
    );
    assert!(invalid(
        put(missing.lease, id, b"not an object".to_vec()).await
    ));
    let oversize = vec![1; Settings::default().limits.max_object as usize + 1];
    assert_eq!(
        put(missing.lease, id, oversize).await,
        Err(ServiceError::TooLarge)
    );
    put(missing.lease, id, object.clone()).await.unwrap();
    // Again: a no-op.
    put(missing.lease, id, object.clone()).await.unwrap();
    f.advance(Settings::default().lease_ms);
    assert_eq!(
        put(missing.lease, id, object.clone()).await,
        Err(ServiceError::BadLease)
    );

    // Quota: 3000 bytes. Fill it, then new uploads are refused.
    let mut used = f
        .service
        .meta()
        .account(f.account)
        .await
        .map(|row| row.unwrap().used_bytes)
        .unwrap();
    let mut seed = 0_u8;
    let refused = loop {
        seed += 1;
        let (id, object) = f.chunk(&[seed; 700]);
        let lease = f.service.missing(f.account, f.collection, &[id]).await;
        let Ok(lease) = lease else {
            break lease.map(drop);
        };
        match f
            .service
            .put_chunk(f.account, f.collection, lease.lease, id, &object)
            .await
        {
            Ok(()) => used += object.len() as u64,
            Err(error) => break Err(error),
        }
    };
    assert_eq!(refused, Err(ServiceError::QuotaExceeded));
    assert!(used <= 3000);
    let too_many = vec![id; Settings::default().limits.max_batch as usize + 1];
    assert_eq!(
        f.service.missing(f.account, f.collection, &too_many).await,
        Err(ServiceError::TooLarge)
    );
}

#[tokio::test]
async fn pruning_garbage_collection_and_fsck() {
    let mut f = Fixture::new().await;
    let (old, new, spare) = (f.chunk(b"old"), f.chunk(b"new"), f.chunk(b"spare"));
    f.upload(std::slice::from_ref(&old)).await;
    let first = f.commit(0, None, &[(1, vec![old.0])]);
    let head = f.append(None, &first).await.unwrap();
    f.upload(std::slice::from_ref(&new)).await;
    let second = f.commit(0, Some(head), &[(1, vec![new.0])]);
    f.append(Some(head), &second).await.unwrap();
    // Uploaded under a lease, never committed.
    f.upload(std::slice::from_ref(&spare)).await;

    // Within retention nothing goes; the leased chunk stays while its lease holds.
    assert_eq!(f.service.prune().await.unwrap(), 0);
    let report = f.service.collect_garbage().await.unwrap();
    assert_eq!((report.chunks, report.leases), (0, 0));
    assert_eq!(f.blobs.len(), 3);
    assert!(f.service.fsck().await.unwrap().is_clean());

    // Past the lease: the spare chunk is marked, and goes a grace period later.
    let grace = Settings::default().garbage_grace_ms;
    f.advance(Settings::default().lease_ms);
    let report = f.service.collect_garbage().await.unwrap();
    assert_eq!((report.marked, report.chunks, report.leases), (1, 0, 3));
    assert_eq!(f.blobs.len(), 3);
    f.advance(grace - 1);
    assert_eq!(f.service.collect_garbage().await.unwrap().chunks, 0);
    f.advance(1);
    assert_eq!(f.service.collect_garbage().await.unwrap().chunks, 1);
    // Past retention: the old record goes, and its chunk a grace period later.
    f.advance(30 * DAY_MS);
    assert_eq!(f.service.prune().await.unwrap(), 1);
    assert_eq!(f.service.collect_garbage().await.unwrap().marked, 1);
    f.advance(grace);
    let report = f.service.collect_garbage().await.unwrap();
    assert_eq!(report.chunks, 1);
    assert_eq!(report.bytes, old.1.len() as u64);
    assert_eq!(f.blobs.len(), 1);
    assert_eq!(
        f.service.get_chunk(f.account, f.collection, old.0).await,
        Err(ServiceError::NotFound)
    );
    assert_eq!(
        f.service
            .get_chunk(f.account, f.collection, new.0)
            .await
            .unwrap(),
        new.1
    );
    // The pruned commit still verifies: its record is a hash now.
    let commits = f
        .service
        .commits_after(f.account, f.collection, 0, 10)
        .await
        .unwrap()
        .commits;
    assert!(matches!(commits[0].records[0], RecordSlot::Pruned(_)));
    let key = |id| BlobKey::new(f.account, f.collection, id);
    assert_eq!(
        oxisoft_drive_proto::verify_chain(f.collection, None, &commits, |device| {
            f.devices
                .iter()
                .map(DeviceIdentity::verifying_key)
                .find(|key| oxisoft_drive_proto::DeviceId::from_key(key) == *device)
        })
        .map(|headers| headers.len()),
        Ok(2)
    );

    // fsck finds a missing object, an orphan and a wrong size.
    assert!(f.service.fsck().await.unwrap().is_clean());
    f.blobs.remove(&key(new.0));
    f.blobs.insert(key(spare.0), spare.1.clone());
    let report = f.service.fsck().await.unwrap();
    assert_eq!(report.missing_objects, [key(new.0)]);
    assert_eq!(report.orphan_objects, [key(spare.0)]);
    f.blobs.insert(key(new.0), vec![0; 3]);
    assert_eq!(f.service.fsck().await.unwrap().wrong_sizes, [key(new.0)]);
}

#[tokio::test]
async fn a_failed_object_write_records_nothing() {
    let mut f = Fixture::new().await;
    let (id, object) = f.chunk(b"chunk");
    let missing = f
        .service
        .missing(f.account, f.collection, &[id])
        .await
        .unwrap();
    f.blobs.fail_next(BlobOp::Put);
    assert!(matches!(
        f.service
            .put_chunk(f.account, f.collection, missing.lease, id, &object)
            .await,
        Err(ServiceError::Blob(_))
    ));
    let again = f
        .service
        .missing(f.account, f.collection, &[id])
        .await
        .unwrap();
    assert_eq!(again.ids, [id]);
    f.service
        .put_chunk(f.account, f.collection, again.lease, id, &object)
        .await
        .unwrap();
    assert!(f.service.fsck().await.unwrap().is_clean());
}

/// One step of the garbage-collection property test.
#[derive(Debug, Clone)]
enum Op {
    /// Upload these chunks (by number) under a new lease.
    Upload(Vec<u8>),
    /// Commit a new record of `node` referencing these chunks (those stored).
    Commit(u8, Vec<u8>),
    /// Move the clock forward by this many days.
    Advance(u8),
    Prune,
    Collect,
}

fn op() -> impl proptest::strategy::Strategy<Value = Op> {
    use proptest::prelude::*;
    prop_oneof![
        proptest::collection::vec(0..12_u8, 1..4).prop_map(Op::Upload),
        (0..4_u8, proptest::collection::vec(0..12_u8, 0..3)).prop_map(|(n, c)| Op::Commit(n, c)),
        (0..40_u8).prop_map(Op::Advance),
        Just(Op::Prune),
        Just(Op::Collect),
    ]
}

/// After every collection, exactly the chunks the model keeps are stored: a chunk is needed
/// while a present record references it or an unexpired lease covers it; one that isn't is
/// marked at a collection, and deleted at the first collection a grace period after its mark.
/// A new reference or lease clears the mark (server binary §5).
async fn garbage_run(ops: Vec<Op>) {
    let mut f = Fixture::new().await;
    let grace = Settings::default().garbage_grace_ms;
    let chunks: Vec<(ChunkId, Vec<u8>)> = (0..12_u8).map(|n| f.chunk(&[n; 64])).collect();
    let mut head = None;
    // (lease expiry, chunk numbers) of every lease taken.
    let mut leases: Vec<(u64, Vec<u8>)> = Vec::new();
    // The model: each stored chunk's garbage mark.
    let mut stored: std::collections::BTreeMap<u8, Option<u64>> = std::collections::BTreeMap::new();
    for op in ops {
        match op {
            Op::Upload(numbers) => {
                let batch: Vec<_> = numbers
                    .iter()
                    .map(|n| chunks[usize::from(*n)].clone())
                    .collect();
                f.upload(&batch).await;
                leases.push((
                    f.clock.now_ms() + Settings::default().lease_ms,
                    numbers.clone(),
                ));
                for n in numbers {
                    stored.insert(n, None);
                }
            }
            Op::Commit(node, numbers) => {
                let mut ids = Vec::new();
                for n in numbers {
                    let id = chunks[usize::from(n)].0;
                    if f.service
                        .get_chunk(f.account, f.collection, id)
                        .await
                        .is_ok()
                    {
                        ids.push(id);
                        stored.insert(n, None);
                    }
                }
                let commit = f.commit(0, head, &[(node, ids)]);
                head = Some(f.append(head, &commit).await.unwrap());
            }
            Op::Advance(days) => f.advance(u64::from(days) * DAY_MS),
            Op::Prune => {
                f.service.prune().await.unwrap();
            }
            Op::Collect => {
                f.service.collect_garbage().await.unwrap();
                let now = f.clock.now_ms();
                let mut needed: Vec<ChunkId> = leases
                    .iter()
                    .filter(|(expires, _)| now < *expires)
                    .flat_map(|(_, numbers)| numbers.iter().map(|n| chunks[usize::from(*n)].0))
                    .collect();
                let commits = f
                    .service
                    .commits_after(f.account, f.collection, 0, 1000)
                    .await
                    .unwrap()
                    .commits;
                for commit in &commits {
                    for record in commit.records().unwrap() {
                        needed.extend(record.chunks);
                    }
                }
                stored.retain(|n, mark| {
                    if needed.contains(&chunks[usize::from(*n)].0) {
                        *mark = None;
                        return true;
                    }
                    let marked = *mark.get_or_insert(now);
                    marked > now.saturating_sub(grace)
                });
                for (n, (id, object)) in (0_u8..).zip(&chunks) {
                    let found = f.service.get_chunk(f.account, f.collection, *id).await;
                    if stored.contains_key(&n) {
                        assert_eq!(found.as_ref(), Ok(object), "chunk {n} is gone too early");
                    } else {
                        assert_eq!(found, Err(ServiceError::NotFound), "chunk {n} survived");
                    }
                    if needed.contains(id) {
                        assert!(found.is_ok(), "a needed chunk is gone");
                    }
                }
                assert!(f.service.fsck().await.unwrap().is_clean());
            }
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]
    #[test]
    fn garbage_collection_keeps_exactly_what_is_needed(
        ops in proptest::collection::vec(op(), 1..40)
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mut ops = ops;
        ops.push(Op::Collect);
        runtime.block_on(garbage_run(ops));
    }
}
