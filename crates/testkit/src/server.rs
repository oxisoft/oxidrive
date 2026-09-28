//! An in-memory server.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};

use oxisoft_drive_core::{ServerApi, ServerError};
use oxisoft_drive_proto::api::{AppendResult, Commits, Head, Missing};
use oxisoft_drive_proto::{ChunkId, CollectionId, Commit, LeaseId, Seq};

/// A server operation, for failure injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerOp {
    /// `head`.
    Head,
    /// `commits_after`.
    CommitsAfter,
    /// `append`.
    Append,
    /// `missing`.
    Missing,
    /// `put_chunk`.
    PutChunk,
    /// `get_chunk`.
    GetChunk,
}

/// How an injected failure behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerFailure {
    /// The request never arrived: nothing changes.
    Unavailable,
    /// The server applied the request, but the answer was lost.
    LostResponse,
    /// For `append`: another device committed first (the request is refused as a conflict).
    Conflict,
}

#[derive(Debug, Default)]
struct Collection {
    commits: Vec<Commit>,
    chunks: BTreeMap<[u8; 32], Vec<u8>>,
}

#[derive(Debug, Default)]
struct Inner {
    collections: BTreeMap<CollectionId, Collection>,
    next_lease: u128,
    failures: Vec<(ServerOp, ServerFailure)>,
    operations: usize,
    fail_at: Option<(usize, ServerFailure)>,
}

/// An in-memory server, shared by several devices through `Arc` (core executor §5).
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

    /// Makes the next call of `op` fail.
    pub fn fail_next(&self, op: ServerOp, failure: ServerFailure) {
        self.lock().failures.push((op, failure));
    }

    /// Makes the operation `count` operations from now fail (whatever it is).
    pub fn fail_after(&self, count: usize, failure: ServerFailure) {
        let mut inner = self.lock();
        let at = inner.operations + count;
        inner.fail_at = Some((at, failure));
    }

    /// Cancels every injected failure that hasn't fired.
    pub fn cancel_failures(&self) {
        let mut inner = self.lock();
        inner.fail_at = None;
        inner.failures.clear();
    }

    /// How many operations ran so far.
    #[must_use]
    pub fn operations(&self) -> usize {
        self.lock().operations
    }

    fn failure(&self, op: ServerOp) -> Option<ServerFailure> {
        let mut inner = self.lock();
        inner.operations += 1;
        if inner
            .fail_at
            .is_some_and(|(at, _)| at + 1 == inner.operations)
            && let Some((_, failure)) = inner.fail_at.take()
        {
            return Some(failure);
        }
        let index = inner
            .failures
            .iter()
            .position(|(failing, _)| *failing == op)?;
        Some(inner.failures.remove(index).1)
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

fn unavailable() -> ServerError {
    ServerError::Unavailable("injected failure".into())
}

impl ServerApi for MemServer {
    fn head(
        &self,
        collection: CollectionId,
    ) -> impl Future<Output = Result<Option<Head>, ServerError>> + Send {
        std::future::ready(self.head_now(collection))
    }

    fn commits_after(
        &self,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> impl Future<Output = Result<Commits, ServerError>> + Send {
        std::future::ready(self.commits_after_now(collection, after, limit))
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
        std::future::ready(self.missing_now(collection, ids))
    }

    fn put_chunk(
        &self,
        collection: CollectionId,
        _lease: LeaseId,
        id: ChunkId,
        object: Vec<u8>,
    ) -> impl Future<Output = Result<(), ServerError>> + Send {
        std::future::ready(self.put_chunk_now(collection, id, object))
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
    fn head_now(&self, collection: CollectionId) -> Result<Option<Head>, ServerError> {
        if self.failure(ServerOp::Head).is_some() {
            return Err(unavailable());
        }
        Ok(self
            .lock()
            .collections
            .get(&collection)
            .and_then(Self::head_of))
    }

    fn commits_after_now(
        &self,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> Result<Commits, ServerError> {
        if self.failure(ServerOp::CommitsAfter).is_some() {
            return Err(unavailable());
        }
        let inner = self.lock();
        let all = inner
            .collections
            .get(&collection)
            .map_or(&[][..], |c| c.commits.as_slice());
        let start = usize::try_from(after).unwrap_or(usize::MAX).min(all.len());
        let end = start.saturating_add(limit as usize).min(all.len());
        Ok(Commits {
            commits: all[start..end].to_vec(),
            more: end < all.len(),
        })
    }

    fn append_now(
        &self,
        collection: CollectionId,
        expected: Option<Head>,
        commit: Commit,
    ) -> Result<AppendResult, ServerError> {
        let failure = self.failure(ServerOp::Append);
        if failure == Some(ServerFailure::Unavailable) {
            return Err(unavailable());
        }
        let mut inner = self.lock();
        let log = inner.collections.entry(collection).or_default();
        let current = Self::head_of(log);
        if failure == Some(ServerFailure::Conflict) {
            return Ok(AppendResult::Conflict(current));
        }
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
        let head = Self::head_of(log);
        drop(inner);
        if failure == Some(ServerFailure::LostResponse) {
            return Err(unavailable());
        }
        Ok(head.map_or(AppendResult::Conflict(None), AppendResult::Appended))
    }

    fn missing_now(
        &self,
        collection: CollectionId,
        ids: Vec<ChunkId>,
    ) -> Result<Missing, ServerError> {
        if self.failure(ServerOp::Missing).is_some() {
            return Err(unavailable());
        }
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
        Ok(Missing {
            ids: missing,
            lease,
            lease_expires_ms: u64::MAX,
        })
    }

    fn put_chunk_now(
        &self,
        collection: CollectionId,
        id: ChunkId,
        object: Vec<u8>,
    ) -> Result<(), ServerError> {
        let failure = self.failure(ServerOp::PutChunk);
        if matches!(
            failure,
            Some(ServerFailure::Unavailable | ServerFailure::Conflict)
        ) {
            return Err(unavailable());
        }
        self.lock()
            .collections
            .entry(collection)
            .or_default()
            .chunks
            .insert(*id.0.as_bytes(), object);
        if failure == Some(ServerFailure::LostResponse) {
            return Err(unavailable());
        }
        Ok(())
    }

    fn get_chunk_now(&self, collection: CollectionId, id: ChunkId) -> Result<Vec<u8>, ServerError> {
        if self.failure(ServerOp::GetChunk).is_some() {
            return Err(unavailable());
        }
        self.lock()
            .collections
            .get(&collection)
            .and_then(|c| c.chunks.get(id.0.as_bytes()).cloned())
            .ok_or(ServerError::NotFound)
    }
}
