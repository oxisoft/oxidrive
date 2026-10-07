//! The tests every [`IndexStore`] passes (client foundation §5): the in-memory one here, the
//! SQLite one in the client crate. [`index_conformance_tests!`](crate::index_conformance_tests)
//! generates one test per case; the calling crate needs `tokio` with `macros` and `rt`.

#![expect(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "a test suite: every case panics when the index misbehaves"
)]

use oxisoft_drive_core::{
    BaseEntry, BaseKind, FileMeta, IndexState, IndexStore, IndexTxn, RelPath, RemoteEntry,
    RemoteKind, RemoteNode, Stat,
};
use oxisoft_drive_crypto::hash::Digest;
use oxisoft_drive_proto::api::Head;
use oxisoft_drive_proto::{
    ChunkId, ChunkRef, CommitHash, ContentHash, DeviceId, Name, NodeId, Version,
};

/// Generates one `#[tokio::test]` per case, each on a fresh index made by `$fresh`: an async
/// expression giving `(index, guard)`, where the guard lives until the test ends.
#[macro_export]
macro_rules! index_conformance_tests {
    ($fresh:expr) => {
        $crate::index_conformance_tests!(@cases $fresh;
            starts_empty, round_trips_every_kind, replaces_and_removes, empty_changes_nothing);
    };
    (@cases $fresh:expr; $($case:ident),*) => {
        $(
            #[::tokio::test]
            async fn $case() {
                let (index, _guard) = $fresh.await;
                $crate::index_conformance::$case(&index).await;
            }
        )*
    };
}

fn node(n: u8) -> NodeId {
    NodeId::from_bytes([n; 16])
}

fn version(counter: u64) -> Version {
    Version {
        device: DeviceId::from_bytes([3; 16]),
        counter,
    }
}

fn content(n: u8) -> ContentHash {
    ContentHash(Digest::from_bytes([n; 32]))
}

fn path(text: &str) -> RelPath {
    RelPath::parse(text).unwrap()
}

/// A base entry of each kind, with every field set to something unusual.
fn base_file(n: u8) -> BaseEntry {
    BaseEntry {
        path: path(&format!("folder/fïle {n}.txt")),
        kind: BaseKind::File {
            stat: Stat {
                size: u64::MAX - u64::from(n),
                mtime_ms: -1_000 - i64::from(n),
                file_id: u64::MAX,
                executable: true,
                change: 1_234_567_890_123_456_789,
            },
            content: content(n),
        },
        version: version(u64::from(n)),
    }
}

fn base_folder(n: u8) -> BaseEntry {
    BaseEntry {
        path: path(&format!("folder {n}")),
        kind: BaseKind::Folder { file_id: 77 },
        version: version(1),
    }
}

fn remote(n: u8, kind: RemoteKind) -> RemoteEntry {
    let file = matches!(kind, RemoteKind::File { .. }).then(|| FileMeta {
        chunks: vec![
            ChunkRef {
                id: ChunkId(Digest::from_bytes([n; 32])),
                len: 4096,
            },
            ChunkRef {
                id: ChunkId(Digest::from_bytes([n + 1; 32])),
                len: 1,
            },
        ],
        mtime_ms: 1_790_000_000_000,
        executable: false,
        epoch: 2,
    });
    RemoteEntry {
        node: RemoteNode {
            parent: (n > 1).then(|| node(1)),
            name: Name::new(&format!("name {n}")).unwrap(),
            kind,
            version: version(u64::from(n) * 10),
        },
        file,
    }
}

fn head(seq: u64) -> Head {
    Head {
        seq,
        hash: CommitHash(Digest::from_bytes([u8::try_from(seq % 256).unwrap(); 32])),
    }
}

/// What the index should hold after `txns`.
fn expected(txns: &[&IndexTxn]) -> IndexState {
    let mut state = IndexState::default();
    for txn in txns {
        txn.apply_to(&mut state);
    }
    state
}

/// A new index holds nothing.
pub async fn starts_empty<I: IndexStore>(index: &I) {
    assert_eq!(index.load().await.unwrap(), IndexState::default());
}

/// Every kind of entry comes back as it went in.
pub async fn round_trips_every_kind<I: IndexStore>(index: &I) {
    let txn = IndexTxn {
        put: vec![(node(1), base_folder(1)), (node(2), base_file(2))],
        remove: Vec::new(),
        remote: vec![
            (node(1), remote(1, RemoteKind::Folder)),
            (
                node(2),
                remote(
                    2,
                    RemoteKind::File {
                        content: content(9),
                        size: 4097,
                    },
                ),
            ),
            (node(3), remote(3, RemoteKind::Deleted)),
        ],
        head: Some(head(300)),
        counter: Some(41),
    };
    index.apply(txn.clone()).await.unwrap();
    assert_eq!(index.load().await.unwrap(), expected(&[&txn]));
}

/// Later changes replace entries, remove them, and move the head and counter on.
pub async fn replaces_and_removes<I: IndexStore>(index: &I) {
    let first = IndexTxn {
        put: vec![
            (node(1), base_folder(1)),
            (node(2), base_file(2)),
            (node(3), base_file(3)),
        ],
        remote: vec![(node(1), remote(1, RemoteKind::Folder))],
        head: Some(head(1)),
        counter: Some(1),
        ..IndexTxn::default()
    };
    let second = IndexTxn {
        put: vec![(node(2), base_file(20))],
        remove: vec![node(3), node(9)],
        remote: vec![(node(1), remote(1, RemoteKind::Deleted))],
        head: Some(head(2)),
        counter: None,
    };
    index.apply(first.clone()).await.unwrap();
    index.apply(second.clone()).await.unwrap();
    let loaded = index.load().await.unwrap();
    assert_eq!(loaded, expected(&[&first, &second]));
    assert_eq!(loaded.counter, 1);
    assert_eq!(loaded.base.len(), 2);
}

/// An empty change is fine and changes nothing.
pub async fn empty_changes_nothing<I: IndexStore>(index: &I) {
    let txn = IndexTxn {
        counter: Some(5),
        ..IndexTxn::default()
    };
    index.apply(txn.clone()).await.unwrap();
    index.apply(IndexTxn::default()).await.unwrap();
    assert_eq!(index.load().await.unwrap(), expected(&[&txn]));
}
