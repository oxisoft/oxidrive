//! An in-memory server.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};

use oxisoft_drive_core::{ServerApi, ServerError};
use oxisoft_drive_proto::api::{AppendResult, Commits, Head, Missing};
use oxisoft_drive_proto::{ChunkId, CollectionId, Commit, LeaseId, Seq};

#[derive(Debug, Default)]
struct Collection {
    commits: Vec<Commit>,
    chunks: BTreeMap<[u8; 32], Vec<u8>>,
}

#[derive(Debug, Default)]
struct Inner {
    collections: BTreeMap<CollectionId, Collection>,
    next_lease: u128,
}

/// An in-memory server, shared by several devices through `Arc` (core executor §5). Wrap it
/// in [`Flaky`](crate::Flaky) to inject failures.
#[derive(Debug, Default)]
pub struct MemServer {
    inner: Mutex<Inner>,
}

impl MemServer {
    /// An empty server.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces every stored chunk object with another one's (a server serving wrong data).
    pub fn swap_chunks(&self, collection: CollectionId) {
        let mut inner = self.lock();
        if let Some(stored) = inner.collections.get_mut(&collection) {
            let objects: Vec<Vec<u8>> = stored.chunks.values().cloned().collect();
            for (index, object) in stored.chunks.values_mut().enumerate() {
                object.clone_from(&objects[(index + 1) % objects.len()]);
            }
        }
    }

    /// Every commit of a collection.
    #[must_use]
    pub fn commits(&self, collection: CollectionId) -> Vec<Commit> {
        self.lock()
            .collections
            .get(&collection)
            .map(|c| c.commits.clone())
            .unwrap_or_default()
    }

    /// How many chunk objects a collection stores.
    #[must_use]
    pub fn chunk_count(&self, collection: CollectionId) -> usize {
        self.lock()
            .collections
            .get(&collection)
            .map_or(0, |c| c.chunks.len())
    }

    fn head_of(collection: &Collection) -> Option<Head> {
        collection.commits.last().map(|commit| Head {
            seq: collection.commits.len() as Seq,
            hash: commit.hash(),
        })
    }
}

impl ServerApi for MemServer {
    fn head(
        &self,
        collection: CollectionId,
    ) -> impl Future<Output = Result<Option<Head>, ServerError>> + Send {
        std::future::ready(Ok(self.head_now(collection)))
    }

    fn commits_after(
        &self,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> impl Future<Output = Result<Commits, ServerError>> + Send {
        std::future::ready(Ok(self.commits_after_now(collection, after, limit)))
    }

    fn append(
        &self,
        collection: CollectionId,
        expected: Option<Head>,
        commit: Commit,
    ) -> impl Future<Output = Result<AppendResult, ServerError>> + Send {
        std::future::ready(self.append_now(collection, expected, commit))
    }

    fn missing(
        &self,
        collection: CollectionId,
        ids: Vec<ChunkId>,
    ) -> impl Future<Output = Result<Missing, ServerError>> + Send {
        std::future::ready(Ok(self.missing_now(collection, ids)))
    }

    fn put_chunk(
        &self,
        collection: CollectionId,
        _lease: LeaseId,
        id: ChunkId,
        object: Vec<u8>,
    ) -> impl Future<Output = Result<(), ServerError>> + Send {
        self.put_chunk_now(collection, id, object);
        std::future::ready(Ok(()))
    }

    fn get_chunk(
        &self,
        collection: CollectionId,
        id: ChunkId,
    ) -> impl Future<Output = Result<Vec<u8>, ServerError>> + Send {
        std::future::ready(self.get_chunk_now(collection, id))
    }
}

impl MemServer {
    fn head_now(&self, collection: CollectionId) -> Option<Head> {
        self.lock()
            .collections
            .get(&collection)
            .and_then(Self::head_of)
    }

    fn commits_after_now(&self, collection: CollectionId, after: Seq, limit: u32) -> Commits {
        let inner = self.lock();
        let all = inner
            .collections
            .get(&collection)
            .map_or(&[][..], |c| c.commits.as_slice());
        let start = usize::try_from(after).unwrap_or(usize::MAX).min(all.len());
        let end = start.saturating_add(limit as usize).min(all.len());
        Commits {
            commits: all[start..end].to_vec(),
            more: end < all.len(),
        }
    }

    fn append_now(
        &self,
        collection: CollectionId,
        expected: Option<Head>,
        commit: Commit,
    ) -> Result<AppendResult, ServerError> {
        let mut inner = self.lock();
        let log = inner.collections.entry(collection).or_default();
        let current = Self::head_of(log);
        if current != expected {
            return Ok(AppendResult::Conflict(current));
        }
        // The real server also checks signatures; clients verify everything anyway.
        let claimed = commit
            .header
            .decode_unverified()
            .map_err(|error| ServerError::Rejected(error.to_string()))?;
        let next = log.commits.len() as Seq + 1;
        if claimed.seq != next || claimed.prev != current.map(|head| head.hash) {
            return Err(ServerError::Rejected(
                "commit doesn't follow the head".into(),
            ));
        }
        log.commits.push(commit);
        Ok(Self::head_of(log).map_or(AppendResult::Conflict(None), AppendResult::Appended))
    }

    fn missing_now(&self, collection: CollectionId, ids: Vec<ChunkId>) -> Missing {
        let mut inner = self.lock();
        inner.next_lease += 1;
        let lease = LeaseId::from_bytes(inner.next_lease.to_le_bytes());
        let stored = inner.collections.entry(collection).or_default();
        let mut seen = BTreeSet::new();
        let missing = ids
            .into_iter()
            .filter(|id| {
                !stored.chunks.contains_key(id.0.as_bytes()) && seen.insert(*id.0.as_bytes())
            })
            .collect();
        Missing {
            ids: missing,
            lease,
            lease_expires_ms: u64::MAX,
        }
    }

    fn put_chunk_now(&self, collection: CollectionId, id: ChunkId, object: Vec<u8>) {
        self.lock()
            .collections
            .entry(collection)
            .or_default()
            .chunks
            .insert(*id.0.as_bytes(), object);
    }

    fn get_chunk_now(&self, collection: CollectionId, id: ChunkId) -> Result<Vec<u8>, ServerError> {
        self.lock()
            .collections
            .get(&collection)
            .and_then(|c| c.chunks.get(id.0.as_bytes()).cloned())
            .ok_or(ServerError::NotFound)
    }
}
