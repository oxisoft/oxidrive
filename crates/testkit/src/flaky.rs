//! Failure injection for any server (server storage H1): [`Flaky`] wraps a [`ServerApi`] and
//! makes chosen requests fail, lose their answers or run into another device's commit, and
//! runs hooks at exact moments of a sync.

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

/// Something that happens elsewhere at an exact moment of a device's conversation with the
/// server, such as another device syncing.
pub type Hook = Box<dyn FnOnce() + Send>;

struct PendingHook(Hook);

impl std::fmt::Debug for PendingHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingHook")
    }
}

#[derive(Debug, Default)]
struct State {
    failures: Vec<(ServerOp, ServerFailure)>,
    operations: usize,
    fail_at: Option<(usize, ServerFailure)>,
    hook_at: Option<(usize, PendingHook)>,
}

/// A server whose requests fail on demand.
#[derive(Debug, Default)]
pub struct Flaky<S> {
    inner: S,
    state: Mutex<State>,
}

fn unavailable() -> ServerError {
    ServerError::Unavailable("injected failure".into())
}

impl<S> Flaky<S> {
    /// Wraps a server; nothing fails until asked to.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            state: Mutex::default(),
        }
    }

    /// The wrapped server.
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes the next call of `op` fail.
    pub fn fail_next(&self, op: ServerOp, failure: ServerFailure) {
        self.lock().failures.push((op, failure));
    }

    /// Makes the operation `count` operations from now fail (whatever it is).
    pub fn fail_after(&self, count: usize, failure: ServerFailure) {
        let mut state = self.lock();
        let at = state.operations + count;
        state.fail_at = Some((at, failure));
    }

    /// Runs `hook` right before the operation `count` operations from now: another device
    /// syncing, or a user editing, at an exact point of this device's sync. The hook may use
    /// the server itself.
    pub fn interleave_after(&self, count: usize, hook: Hook) {
        let mut state = self.lock();
        let at = state.operations + count;
        state.hook_at = Some((at, PendingHook(hook)));
    }

    /// Cancels every injected failure and hook that hasn't fired.
    pub fn cancel_failures(&self) {
        let mut state = self.lock();
        state.fail_at = None;
        state.hook_at = None;
        state.failures.clear();
    }

    /// How many operations ran so far.
    #[must_use]
    pub fn operations(&self) -> usize {
        self.lock().operations
    }

    /// Runs a due hook, counts the operation, and says whether (and how) it fails.
    fn failure(&self, op: ServerOp) -> Option<ServerFailure> {
        let hook = {
            let mut state = self.lock();
            let due = state
                .hook_at
                .as_ref()
                .is_some_and(|(at, _)| *at == state.operations);
            if due { state.hook_at.take() } else { None }
        };
        // Outside the lock: the hook may call the server.
        if let Some((_, PendingHook(hook))) = hook {
            hook();
        }
        let mut state = self.lock();
        state.operations += 1;
        if state
            .fail_at
            .is_some_and(|(at, _)| at + 1 == state.operations)
            && let Some((_, failure)) = state.fail_at.take()
        {
            return Some(failure);
        }
        let index = state
            .failures
            .iter()
            .position(|(failing, _)| *failing == op)?;
        Some(state.failures.remove(index).1)
    }
}

impl<S: ServerApi> ServerApi for Flaky<S> {
    fn head(
        &self,
        collection: CollectionId,
    ) -> impl Future<Output = Result<Option<Head>, ServerError>> + Send {
        let failed = self.failure(ServerOp::Head).is_some();
        async move {
            if failed {
                return Err(unavailable());
            }
            self.inner.head(collection).await
        }
    }

    fn commits_after(
        &self,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> impl Future<Output = Result<Commits, ServerError>> + Send {
        let failed = self.failure(ServerOp::CommitsAfter).is_some();
        async move {
            if failed {
                return Err(unavailable());
            }
            self.inner.commits_after(collection, after, limit).await
        }
    }

    fn append(
        &self,
        collection: CollectionId,
        expected: Option<Head>,
        commit: Commit,
    ) -> impl Future<Output = Result<AppendResult, ServerError>> + Send {
        let failure = self.failure(ServerOp::Append);
        async move {
            match failure {
                Some(ServerFailure::Unavailable) => Err(unavailable()),
                Some(ServerFailure::Conflict) => {
                    Ok(AppendResult::Conflict(self.inner.head(collection).await?))
                }
                Some(ServerFailure::LostResponse) => {
                    self.inner.append(collection, expected, commit).await?;
                    Err(unavailable())
                }
                None => self.inner.append(collection, expected, commit).await,
            }
        }
    }

    fn missing(
        &self,
        collection: CollectionId,
        ids: Vec<ChunkId>,
    ) -> impl Future<Output = Result<Missing, ServerError>> + Send {
        let failed = self.failure(ServerOp::Missing).is_some();
        async move {
            if failed {
                return Err(unavailable());
            }
            self.inner.missing(collection, ids).await
        }
    }

    fn put_chunk(
        &self,
        collection: CollectionId,
        lease: LeaseId,
        id: ChunkId,
        object: Vec<u8>,
    ) -> impl Future<Output = Result<(), ServerError>> + Send {
        let failure = self.failure(ServerOp::PutChunk);
        async move {
            match failure {
                Some(ServerFailure::Unavailable | ServerFailure::Conflict) => Err(unavailable()),
                Some(ServerFailure::LostResponse) => {
                    self.inner.put_chunk(collection, lease, id, object).await?;
                    Err(unavailable())
                }
                None => self.inner.put_chunk(collection, lease, id, object).await,
            }
        }
    }

    fn get_chunk(
        &self,
        collection: CollectionId,
        id: ChunkId,
    ) -> impl Future<Output = Result<Vec<u8>, ServerError>> + Send {
        let failed = self.failure(ServerOp::GetChunk).is_some();
        async move {
            if failed {
                return Err(unavailable());
            }
            self.inner.get_chunk(collection, id).await
        }
    }
}
