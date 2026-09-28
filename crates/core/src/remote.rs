//! The collection's state, replayed from verified commits (sync protocol §1, §7).

use std::collections::BTreeMap;

use oxisoft_drive_crypto::keys::CollectionKey;
use oxisoft_drive_crypto::sign::VerifyingKey;
use oxisoft_drive_proto::api::Head;
use oxisoft_drive_proto::{
    ChunkRef, CollectionId, DeviceId, NodeId, NodeKind, NodePayload, RecordContext, verify_chain,
};

use crate::error::EngineError;
use crate::model::{RemoteKind, RemoteNode, RemoteTree};
use crate::traits::{IndexTxn, ServerApi};

/// How many commits to fetch per request.
const PAGE: u32 = 256;

/// What the engine keeps about a file node beyond the tree: how to download it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// Its chunks, in order.
    pub chunks: Vec<ChunkRef>,
    /// Modification time to give the downloaded file.
    pub mtime_ms: i64,
    /// Executable bit to give it.
    pub executable: bool,
    /// Key epoch of the record: its chunk IDs and content hash use this epoch's keys.
    pub epoch: u32,
}

/// One node as currently committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    /// Parent, name, kind and version.
    pub node: RemoteNode,
    /// For files: how to download them.
    pub file: Option<FileMeta>,
}

impl RemoteEntry {
    /// The entry a decrypted payload (from a record of key epoch `epoch`) describes.
    #[must_use]
    pub fn from_payload(payload: &NodePayload, epoch: u32) -> Self {
        let (kind, file) = match &payload.kind {
            NodeKind::File(info) => (
                RemoteKind::File {
                    content: info.content_hash,
                    size: info.size,
                },
                Some(FileMeta {
                    chunks: info.chunks.clone(),
                    mtime_ms: info.mtime_ms,
                    executable: info.executable,
                    epoch,
                }),
            ),
            NodeKind::Folder => (RemoteKind::Folder, None),
            NodeKind::Deleted => (RemoteKind::Deleted, None),
        };
        Self {
            node: RemoteNode {
                parent: payload.parent,
                name: payload.name.clone(),
                kind,
                version: payload.version,
            },
            file,
        }
    }
}

/// The collection's keys, one per epoch.
#[derive(Debug)]
pub struct CollectionKeys {
    current: CollectionKey,
    older: BTreeMap<u32, CollectionKey>,
}

impl CollectionKeys {
    /// Keys starting with one epoch.
    #[must_use]
    pub const fn new(key: CollectionKey) -> Self {
        Self {
            current: key,
            older: BTreeMap::new(),
        }
    }

    /// Adds another epoch's key; the newest epoch becomes the current one.
    pub fn add(&mut self, key: CollectionKey) {
        if key.epoch() > self.current.epoch() {
            let previous = std::mem::replace(&mut self.current, key);
            self.older.insert(previous.epoch(), previous);
        } else {
            self.older.insert(key.epoch(), key);
        }
    }

    /// The newest key, used for everything written now.
    #[must_use]
    pub const fn current(&self) -> &CollectionKey {
        &self.current
    }

    /// The key of an epoch.
    ///
    /// # Errors
    ///
    /// [`EngineError::MissingKey`] if this device doesn't have it.
    pub fn get(&self, epoch: u32) -> Result<&CollectionKey, EngineError> {
        if self.current.epoch() == epoch {
            return Ok(&self.current);
        }
        self.older
            .get(&epoch)
            .ok_or(EngineError::MissingKey { epoch })
    }
}

/// The replayed collection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteState {
    /// The newest verified head.
    pub head: Option<Head>,
    /// Every node, including tombstones.
    pub entries: BTreeMap<NodeId, RemoteEntry>,
}

impl RemoteState {
    /// The tree the reconciler compares against.
    #[must_use]
    pub fn tree(&self) -> RemoteTree {
        self.entries
            .iter()
            .map(|(id, entry)| (*id, entry.node.clone()))
            .collect()
    }

    /// Records one committed change.
    pub fn apply(&mut self, node: NodeId, entry: RemoteEntry) {
        self.entries.insert(node, entry);
    }

    /// Fetches, verifies and replays every commit after the known head. Returns the index
    /// transaction recording what changed (remote entries and the new head).
    ///
    /// # Errors
    ///
    /// Server errors, a chain that doesn't verify, a record that doesn't open, or a key epoch
    /// this device doesn't have.
    pub async fn refresh<S: ServerApi>(
        &mut self,
        server: &S,
        collection: CollectionId,
        keys: &CollectionKeys,
        trusted: &BTreeMap<DeviceId, VerifyingKey>,
    ) -> Result<IndexTxn, EngineError> {
        let mut txn = IndexTxn::default();
        loop {
            let after = self.head.map_or(0, |head| head.seq);
            let page = server.commits_after(collection, after, PAGE).await?;
            if page.commits.is_empty() {
                break;
            }
            let previous = self.head.map(|head| (head.seq, head.hash));
            let headers = verify_chain(collection, previous, &page.commits, |device| {
                trusted.get(device).copied()
            })?;
            for (header, commit) in headers.iter().zip(&page.commits) {
                let meta = keys.get(header.epoch)?.meta();
                let context = RecordContext {
                    collection,
                    seq: header.seq,
                    epoch: header.epoch,
                };
                for record in commit.records()? {
                    let payload = record.open(&meta, &context)?;
                    let entry = RemoteEntry::from_payload(&payload, header.epoch);
                    txn.remote.push((record.node, entry.clone()));
                    self.apply(record.node, entry);
                }
                let head = Head {
                    seq: header.seq,
                    hash: commit.hash(),
                };
                self.head = Some(head);
                txn.head = Some(head);
            }
            if !page.more {
                break;
            }
        }
        Ok(txn)
    }
}
