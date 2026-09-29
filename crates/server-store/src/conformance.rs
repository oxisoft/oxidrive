//! The tests every [`MetaStore`] backend passes (server storage §6). A backend runs them
//! with [`conformance_tests!`](crate::conformance_tests), giving an expression that makes a
//! fresh, empty store.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "a test suite: every case panics when the store misbehaves"
)]

use std::sync::Arc;

use oxisoft_drive_crypto::hash::Digest;
use oxisoft_drive_proto::api::Head;
use oxisoft_drive_proto::{
    AccountId, ChunkId, CollectionId, CommitHash, DeviceId, LeaseId, NodeId, RecordHash, Seq,
};

use crate::{
    AccountStatus, AppendOutcome, MetaStore, NewAccount, NewChunk, NewCollection, NewLease,
    PreparedAppend, PreparedRecord, RecordRef, StoreError, StoredCertificate, StoredDeviceList,
    StoredSlot,
};

/// Generates one `#[tokio::test]` per conformance case, each on a fresh store made by
/// `$fresh`: an async expression giving `(store, guard)`, where the guard (a temporary
/// directory, a database to drop) lives until the test ends. The calling crate needs `tokio`
/// with `macros`, `rt` and `rt-multi-thread`.
#[macro_export]
macro_rules! conformance_tests {
    ($fresh:expr) => {
        $crate::conformance_tests!(@cases $fresh;
            accounts, device_lists, collections, appends_and_heads, appends_need_chunks, paging,
            superseding_and_pruning, chunks_and_usage, leases, garbage, all_chunks_in_order);
        #[::tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn racing_appends() {
            let (store, _guard) = $fresh.await;
            $crate::conformance::racing_appends(::std::sync::Arc::new(store)).await;
        }
        #[::tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn garbage_never_takes_a_chunk_being_committed() {
            let (store, _guard) = $fresh.await;
            $crate::conformance::garbage_never_takes_a_chunk_being_committed(
                ::std::sync::Arc::new(store),
            )
            .await;
        }
    };
    (@cases $fresh:expr; $($case:ident),*) => {
        $(
            #[::tokio::test]
            async fn $case() {
                let (store, _guard) = $fresh.await;
                $crate::conformance::$case(&store).await;
            }
        )*
    };
}

const DAY_MS: u64 = 86_400_000;

fn account_id(n: u8) -> AccountId {
    AccountId::from_bytes([n; 16])
}

fn collection_id(n: u8) -> CollectionId {
    CollectionId::from_bytes([n; 16])
}

fn chunk_id(n: u8) -> ChunkId {
    ChunkId(Digest::from_bytes([n; 32]))
}

fn node_id(n: u8) -> NodeId {
    NodeId::from_bytes([n; 16])
}

fn head(seq: Seq) -> Head {
    Head {
        seq,
        hash: CommitHash(Digest::from_bytes([u8::try_from(seq).unwrap(); 32])),
    }
}

async fn with_collection<S: MetaStore>(store: &S, account: u8, collection: u8) {
    let created = store
        .create_account(&NewAccount {
            id: account_id(account),
            signing_key: vec![account; 32],
            quota_bytes: 1 << 30,
            created_ms: 1,
        })
        .await;
    assert!(matches!(created, Ok(()) | Err(StoreError::Duplicate)));
    store
        .create_collection(&NewCollection {
            id: collection_id(collection),
            account: account_id(account),
            config: vec![collection],
            retention_days: 30,
            created_ms: 2,
        })
        .await
        .unwrap();
}

/// A record of `node` referencing `chunks`, with a body telling it apart.
fn record(node: u8, body: u8, chunks: &[u8]) -> PreparedRecord {
    PreparedRecord {
        node: node_id(node),
        hash: RecordHash(Digest::from_bytes([body; 32])),
        body: vec![body; 3],
        chunks: chunks.iter().copied().map(chunk_id).collect(),
    }
}

fn commit(
    collection: u8,
    seq: Seq,
    received_ms: u64,
    records: Vec<PreparedRecord>,
) -> PreparedAppend {
    PreparedAppend {
        collection: collection_id(collection),
        expected: (seq > 1).then(|| head(seq - 1)),
        head: head(seq),
        header: vec![0xa0, u8::try_from(seq).unwrap()],
        device: DeviceId::from_bytes([7; 16]),
        received_ms,
        records,
    }
}

async fn append_ok<S: MetaStore>(store: &S, append: &PreparedAppend) {
    assert_eq!(
        store.append(append).await.unwrap(),
        AppendOutcome::Appended(append.head)
    );
}

async fn store_chunk<S: MetaStore>(store: &S, collection: u8, chunk: u8, size: u64) -> bool {
    store
        .add_chunk(&NewChunk {
            collection: collection_id(collection),
            chunk: chunk_id(chunk),
            size,
            stored_ms: 5,
        })
        .await
        .unwrap()
}

/// Accounts: create, read, duplicates, unknown IDs.
pub async fn accounts<S: MetaStore>(store: &S) {
    assert_eq!(store.account(account_id(1)).await.unwrap(), None);
    let new = NewAccount {
        id: account_id(1),
        signing_key: vec![8; 32],
        quota_bytes: 5000,
        created_ms: 42,
    };
    store.create_account(&new).await.unwrap();
    assert_eq!(store.create_account(&new).await, Err(StoreError::Duplicate));
    let row = store.account(account_id(1)).await.unwrap().unwrap();
    assert_eq!(row.status, AccountStatus::Active);
    assert_eq!(row.signing_key, vec![8; 32]);
    assert_eq!(
        (row.quota_bytes, row.used_bytes, row.created_ms),
        (5000, 0, 42)
    );
}

/// Device lists replace each other only from the expected version; certificates stay.
pub async fn device_lists<S: MetaStore>(store: &S) {
    with_collection(store, 1, 1).await;
    let account = account_id(1);
    let device = DeviceId::from_bytes([3; 16]);
    assert_eq!(store.device_list(account).await.unwrap(), None);
    let first = StoredDeviceList {
        version: 1,
        signed: vec![1, 1],
    };
    let certificate = StoredCertificate {
        device,
        signed: vec![9, 9, 9],
    };
    store
        .put_device_list(account, None, &first, std::slice::from_ref(&certificate))
        .await
        .unwrap();
    assert_eq!(
        store.device_list(account).await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        store.certificate(account, device).await.unwrap(),
        Some(certificate.clone())
    );
    let second = StoredDeviceList {
        version: 2,
        signed: vec![2, 2],
    };
    assert_eq!(
        store.put_device_list(account, None, &second, &[]).await,
        Err(StoreError::Conflict)
    );
    assert_eq!(
        store.put_device_list(account, Some(5), &second, &[]).await,
        Err(StoreError::Conflict)
    );
    // A certificate added again is kept as it was.
    let other = StoredCertificate {
        device,
        signed: vec![0],
    };
    store
        .put_device_list(account, Some(1), &second, &[other])
        .await
        .unwrap();
    assert_eq!(store.device_list(account).await.unwrap(), Some(second));
    assert_eq!(
        store.certificate(account, device).await.unwrap(),
        Some(certificate)
    );
    assert_eq!(
        store
            .certificate(account, DeviceId::from_bytes([4; 16]))
            .await
            .unwrap(),
        None
    );
}

/// Collections: create, read, duplicates, unknown accounts.
pub async fn collections<S: MetaStore>(store: &S) {
    with_collection(store, 1, 1).await;
    let row = store.collection(collection_id(1)).await.unwrap().unwrap();
    assert_eq!(
        (row.account, row.config, row.retention_days, row.created_ms),
        (account_id(1), vec![1], 30, 2)
    );
    let again = NewCollection {
        id: collection_id(1),
        account: account_id(1),
        config: Vec::new(),
        retention_days: 1,
        created_ms: 3,
    };
    assert_eq!(
        store.create_collection(&again).await,
        Err(StoreError::Duplicate)
    );
    let orphan = NewCollection {
        id: collection_id(2),
        account: account_id(9),
        ..again
    };
    assert_eq!(
        store.create_collection(&orphan).await,
        Err(StoreError::NotFound)
    );
    assert_eq!(store.collection(collection_id(2)).await.unwrap(), None);
}

/// Appending moves the head only from the expected one; commits come back as appended.
pub async fn appends_and_heads<S: MetaStore>(store: &S) {
    with_collection(store, 1, 1).await;
    with_collection(store, 1, 2).await;
    for chunk in 1..=3 {
        store_chunk(store, 1, chunk, 10).await;
    }
    let collection = collection_id(1);
    assert_eq!(store.head(collection).await.unwrap(), None);
    let first = commit(1, 1, 10, vec![record(1, 11, &[1, 2]), record(2, 12, &[])]);
    append_ok(store, &first).await;
    assert_eq!(store.head(collection).await.unwrap(), Some(head(1)));
    // Stale or invented expectations lose.
    assert_eq!(
        store.append(&first).await.unwrap(),
        AppendOutcome::Conflict(Some(head(1)))
    );
    let mut wrong = commit(1, 2, 11, Vec::new());
    wrong.expected = Some(head(7));
    assert_eq!(
        store.append(&wrong).await.unwrap(),
        AppendOutcome::Conflict(Some(head(1)))
    );
    // An empty collection has no head to expect.
    let mut early = commit(2, 1, 11, Vec::new());
    early.expected = Some(head(1));
    assert_eq!(
        store.append(&early).await.unwrap(),
        AppendOutcome::Conflict(None)
    );
    append_ok(store, &commit(1, 2, 11, vec![record(3, 13, &[3])])).await;

    let commits = store.commits_after(collection, 0, 10).await.unwrap();
    assert_eq!(commits.len(), 2);
    assert_eq!(
        (commits[0].seq, commits[0].hash, commits[0].header.clone()),
        (1, head(1).hash, vec![0xa0, 1])
    );
    assert_eq!(
        commits[0].records,
        vec![
            StoredSlot::Present(vec![11; 3]),
            StoredSlot::Present(vec![12; 3])
        ]
    );
    assert_eq!(store.head(collection_id(2)).await.unwrap(), None);
}

/// An append referencing a chunk the collection doesn't store changes nothing.
pub async fn appends_need_chunks<S: MetaStore>(store: &S) {
    with_collection(store, 1, 1).await;
    with_collection(store, 1, 2).await;
    store_chunk(store, 1, 1, 10).await;
    // Chunk 2 is stored, but in another collection.
    store_chunk(store, 2, 2, 10).await;
    let wanting = commit(
        1,
        1,
        1,
        vec![record(1, 11, &[1, 3, 2]), record(2, 12, &[3])],
    );
    assert_eq!(
        store.append(&wanting).await.unwrap(),
        AppendOutcome::MissingChunks(vec![chunk_id(3), chunk_id(2)])
    );
    assert_eq!(store.head(collection_id(1)).await.unwrap(), None);
    store_chunk(store, 1, 2, 10).await;
    store_chunk(store, 1, 3, 10).await;
    append_ok(store, &wanting).await;
}

/// Commits page by sequence number.
pub async fn paging<S: MetaStore>(store: &S) {
    with_collection(store, 1, 1).await;
    for seq in 1..=5 {
        append_ok(store, &commit(1, seq, seq, Vec::new())).await;
    }
    let seqs = |commits: Vec<crate::StoredCommit>| -> Vec<Seq> {
        commits.iter().map(|commit| commit.seq).collect()
    };
    let collection = collection_id(1);
    assert_eq!(
        seqs(store.commits_after(collection, 0, 2).await.unwrap()),
        [1, 2]
    );
    assert_eq!(
        seqs(store.commits_after(collection, 2, 2).await.unwrap()),
        [3, 4]
    );
    assert_eq!(
        seqs(store.commits_after(collection, 4, 9).await.unwrap()),
        [5]
    );
    assert!(
        store
            .commits_after(collection, 5, 9)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .commits_after(collection_id(3), 0, 9)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A node's older record becomes prunable once superseded longer than the retention; pruned
/// records keep their hashes and release their chunks.
pub async fn superseding_and_pruning<S: MetaStore>(store: &S) {
    with_collection(store, 1, 1).await;
    for chunk in 1..=3 {
        store_chunk(store, 1, chunk, 100).await;
    }
    append_ok(
        store,
        &commit(1, 1, DAY_MS, vec![record(1, 11, &[1]), record(2, 12, &[2])]),
    )
    .await;
    append_ok(store, &commit(1, 2, 2 * DAY_MS, vec![record(1, 21, &[3])])).await;
    // Node 2's only record and node 1's newest are never prunable.
    assert_eq!(store.prunable(u64::MAX, 10).await.unwrap().len(), 1);
    // Superseded at day 2, kept 30 days.
    assert!(store.prunable(31 * DAY_MS, 10).await.unwrap().is_empty());
    let prunable = store.prunable(32 * DAY_MS, 10).await.unwrap();
    let old = RecordRef {
        collection: collection_id(1),
        seq: 1,
        index: 0,
    };
    assert_eq!(prunable, [old]);
    store.prune(&prunable).await.unwrap();
    assert!(store.prunable(u64::MAX, 10).await.unwrap().is_empty());
    let commits = store.commits_after(collection_id(1), 0, 10).await.unwrap();
    assert_eq!(
        commits[0].records,
        vec![
            StoredSlot::Pruned(RecordHash(Digest::from_bytes([11; 32]))),
            StoredSlot::Present(vec![12; 3])
        ]
    );
    // Chunk 1 is referenced by nothing now; chunks 2 and 3 still are.
    let garbage: Vec<ChunkId> = store
        .garbage(u64::MAX, 10)
        .await
        .unwrap()
        .iter()
        .map(|row| row.chunk)
        .collect();
    assert_eq!(garbage, [chunk_id(1)]);
}

/// Missing chunks, stored chunks and account usage.
pub async fn chunks_and_usage<S: MetaStore>(store: &S) {
    with_collection(store, 1, 1).await;
    with_collection(store, 1, 2).await;
    assert!(store_chunk(store, 1, 1, 100).await);
    assert!(!store_chunk(store, 1, 1, 100).await);
    assert!(store_chunk(store, 2, 1, 50).await);
    let row = store
        .chunk(collection_id(1), chunk_id(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.account, row.collection, row.size, row.stored_ms),
        (account_id(1), collection_id(1), 100, 5)
    );
    assert_eq!(
        store.chunk(collection_id(1), chunk_id(2)).await.unwrap(),
        None
    );
    assert_eq!(
        store
            .account(account_id(1))
            .await
            .unwrap()
            .unwrap()
            .used_bytes,
        150
    );
    let asked = [chunk_id(3), chunk_id(1), chunk_id(2), chunk_id(3)];
    assert_eq!(
        store.missing(collection_id(1), &asked).await.unwrap(),
        [chunk_id(3), chunk_id(2)]
    );
    assert_eq!(
        store
            .add_chunk(&NewChunk {
                collection: collection_id(9),
                chunk: chunk_id(1),
                size: 1,
                stored_ms: 1,
            })
            .await,
        Err(StoreError::NotFound)
    );
}

/// Leases keep their chunks until they expire.
pub async fn leases<S: MetaStore>(store: &S) {
    with_collection(store, 1, 1).await;
    let id = LeaseId::from_bytes([5; 16]);
    assert_eq!(store.lease(id).await.unwrap(), None);
    store
        .create_lease(&NewLease {
            id,
            collection: collection_id(1),
            expires_ms: 1000,
            chunks: vec![chunk_id(2), chunk_id(1)],
        })
        .await
        .unwrap();
    let lease = store.lease(id).await.unwrap().unwrap();
    assert_eq!(
        (lease.collection, lease.expires_ms),
        (collection_id(1), 1000)
    );
    let mut chunks = lease.chunks;
    chunks.sort_by_key(|chunk| *chunk.0.as_bytes());
    assert_eq!(chunks, [chunk_id(1), chunk_id(2)]);
    // Valid while `now < expires_ms`.
    assert_eq!(store.drop_expired_leases(999).await.unwrap(), 0);
    assert_eq!(store.drop_expired_leases(1000).await.unwrap(), 1);
    assert_eq!(store.lease(id).await.unwrap(), None);
}

/// Garbage: stored chunks neither referenced by an unpruned record nor leased; forgetting
/// checks again and frees the usage.
pub async fn garbage<S: MetaStore>(store: &S) {
    with_collection(store, 1, 1).await;
    for chunk in 1..=4 {
        store_chunk(store, 1, chunk, 10).await;
    }
    append_ok(store, &commit(1, 1, 1, vec![record(1, 11, &[1])])).await;
    store
        .create_lease(&NewLease {
            id: LeaseId::from_bytes([5; 16]),
            collection: collection_id(1),
            expires_ms: 100,
            chunks: vec![chunk_id(2)],
        })
        .await
        .unwrap();
    let ids = |rows: &[crate::ChunkRow]| -> Vec<ChunkId> {
        let mut ids: Vec<ChunkId> = rows.iter().map(|row| row.chunk).collect();
        ids.sort_by_key(|chunk| *chunk.0.as_bytes());
        ids
    };
    let found = store.garbage(50, 10).await.unwrap();
    assert_eq!(ids(&found), [chunk_id(3), chunk_id(4)]);
    // Chunk 2's lease has expired by then.
    assert_eq!(
        ids(&store.garbage(100, 10).await.unwrap()),
        [chunk_id(2), chunk_id(3), chunk_id(4)]
    );
    assert_eq!(store.garbage(50, 1).await.unwrap().len(), 1);

    // Chunk 4 gets referenced before it is forgotten: it stays.
    append_ok(store, &commit(1, 2, 2, vec![record(2, 12, &[4])])).await;
    let forgotten = store.forget_chunks(&found, 50).await.unwrap();
    assert_eq!(ids(&forgotten), [chunk_id(3)]);
    assert_eq!(
        store.chunk(collection_id(1), chunk_id(3)).await.unwrap(),
        None
    );
    assert!(
        store
            .chunk(collection_id(1), chunk_id(4))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .account(account_id(1))
            .await
            .unwrap()
            .unwrap()
            .used_bytes,
        30
    );
    // A leased chunk stays too, until the lease expires.
    let leased = store
        .chunk(collection_id(1), chunk_id(2))
        .await
        .unwrap()
        .unwrap();
    assert!(
        store
            .forget_chunks(std::slice::from_ref(&leased), 50)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.forget_chunks(&[leased], 100).await.unwrap().len(), 1);
}

/// Every chunk, paged in (collection, chunk) order.
pub async fn all_chunks_in_order<S: MetaStore>(store: &S) {
    with_collection(store, 1, 2).await;
    with_collection(store, 1, 1).await;
    for (collection, chunk) in [(2, 1), (1, 3), (1, 1), (2, 2)] {
        store_chunk(store, collection, chunk, 1).await;
    }
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = store.all_chunks(after, 3).await.unwrap();
        let Some(last) = page.last() else {
            break;
        };
        after = Some((last.collection, last.chunk));
        seen.extend(page.iter().map(|row| (row.collection, row.chunk)));
    }
    assert_eq!(
        seen,
        [
            (collection_id(1), chunk_id(1)),
            (collection_id(1), chunk_id(3)),
            (collection_id(2), chunk_id(1)),
            (collection_id(2), chunk_id(2)),
        ]
    );
}

/// Many tasks append the same next commit at once: exactly one wins each round, and the
/// others see its head.
pub async fn racing_appends<S: MetaStore + 'static>(store: Arc<S>) {
    with_collection(store.as_ref(), 1, 1).await;
    for seq in 1..=5 {
        let tasks: Vec<_> = (0..8_u8)
            .map(|writer| {
                let store = Arc::clone(&store);
                let mut append = commit(1, seq, seq, vec![record(writer, writer, &[])]);
                append.header = vec![writer];
                tokio::spawn(async move { store.append(&append).await })
            })
            .collect();
        let mut won = 0;
        for task in tasks {
            match task.await.unwrap().unwrap() {
                AppendOutcome::Appended(new) => {
                    won += 1;
                    assert_eq!(new, head(seq));
                }
                AppendOutcome::Conflict(current) => assert_eq!(current, Some(head(seq))),
                AppendOutcome::MissingChunks(missing) => {
                    assert!(missing.is_empty(), "round {seq}: no chunks referenced");
                }
            }
        }
        assert_eq!(won, 1, "round {seq}");
    }
    assert_eq!(
        store
            .commits_after(collection_id(1), 0, 10)
            .await
            .unwrap()
            .len(),
        5
    );
}

/// Garbage collection and an append needing the same chunk run at once, many times: the chunk
/// is never both committed and forgotten.
pub async fn garbage_never_takes_a_chunk_being_committed<S: MetaStore + 'static>(store: Arc<S>) {
    with_collection(store.as_ref(), 1, 1).await;
    for seq in 1..=30_u8 {
        store_chunk(store.as_ref(), 1, seq, 10).await;
        let row = store
            .chunk(collection_id(1), chunk_id(seq))
            .await
            .unwrap()
            .unwrap();
        let append = commit(1, Seq::from(seq), 1, vec![record(seq, seq, &[seq])]);
        let (for_append, for_gc) = (Arc::clone(&store), Arc::clone(&store));
        let append_task = tokio::spawn(async move { for_append.append(&append).await });
        let gc_task = tokio::spawn(async move { for_gc.forget_chunks(&[row], 1).await });
        let appended = append_task.await.unwrap().unwrap();
        let forgotten = gc_task.await.unwrap().unwrap();
        match appended {
            AppendOutcome::Appended(_) => {
                assert!(forgotten.is_empty(), "round {seq}: committed and forgotten");
                assert!(
                    store
                        .chunk(collection_id(1), chunk_id(seq))
                        .await
                        .unwrap()
                        .is_some()
                );
            }
            AppendOutcome::MissingChunks(missing) => {
                assert_eq!(missing, [chunk_id(seq)], "round {seq}");
                assert_eq!(forgotten.len(), 1, "round {seq}");
                // The next round expects this sequence number to be taken.
                store_chunk(store.as_ref(), 1, seq, 10).await;
                let again = commit(1, Seq::from(seq), 1, vec![record(seq, seq, &[seq])]);
                append_ok(store.as_ref(), &again).await;
            }
            AppendOutcome::Conflict(head) => panic!("round {seq}: conflict at {head:?}"),
        }
    }
}
