//! Everything outside the engine, as traits (engineering standards §1, decision E2).
//!
//! The engine never touches a disk, a network or a clock directly. The daemon provides real
//! implementations; `oxisoft-drive-testkit` provides in-memory ones with failure injection.
//! Methods return `impl Future + Send`, so implementations may be async (HTTP) or immediate
//! (memory), and the engine runs on any executor.

use std::future::Future;

use oxisoft_drive_proto::api::{AppendResult, Commits, Head, Missing};
use oxisoft_drive_proto::{ChunkId, CollectionId, Commit, LeaseId, Name, NodeId, Seq};

use crate::model::{BaseEntry, Stat};
use crate::path::RelPath;
use crate::reconcile::FsRules;
use crate::remote::RemoteEntry;

/// What an entry on disk is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsEntry {
    /// A file, with its stat.
    File(Stat),
    /// A folder, with its file ID.
    Folder {
        /// Inode (Unix) or file index (Windows).
        file_id: u64,
    },
}

/// One entry of a folder listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Its name.
    pub name: Name,
    /// What it is.
    pub entry: FsEntry,
}

/// A folder listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirList {
    /// Entries with valid names (symlinks and special files are left out).
    pub entries: Vec<DirEntry>,
    /// Names that aren't valid UTF-8 or aren't valid names; reported, never synced.
    pub unrepresentable: Vec<String>,
}

/// A temporary file being written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TempId(pub u64);

/// File system failures the engine distinguishes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FsError {
    /// The path doesn't exist.
    #[error("not found")]
    NotFound,
    /// The target already exists.
    #[error("already exists")]
    AlreadyExists,
    /// A folder to remove isn't empty.
    #[error("folder not empty")]
    NotEmpty,
    /// The entry no longer has the stat the engine expected: the user changed it.
    #[error("changed on disk")]
    Changed,
    /// Anything else.
    #[error("file system error: {0}")]
    Io(String),
}

/// The local folder of one collection. Paths are relative to its root.
pub trait FileSystem: Send + Sync {
    /// The name rules of this file system.
    fn rules(&self) -> FsRules;

    /// The entries of a folder.
    fn list(&self, dir: &RelPath) -> impl Future<Output = Result<DirList, FsError>> + Send;

    /// What is at `path`, or `None`.
    fn stat(&self, path: &RelPath)
    -> impl Future<Output = Result<Option<FsEntry>, FsError>> + Send;

    /// Up to `len` bytes of a file from `offset`; fewer only at the end.
    fn read(
        &self,
        path: &RelPath,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<Vec<u8>, FsError>> + Send;

    /// Creates a folder; returns its file ID. Fails if anything exists at `path`.
    fn create_dir(&self, path: &RelPath) -> impl Future<Output = Result<u64, FsError>> + Send;

    /// Renames a file or folder. Fails if `to` exists.
    fn rename(
        &self,
        from: &RelPath,
        to: &RelPath,
    ) -> impl Future<Output = Result<(), FsError>> + Send;

    /// Removes a file, only if it still has `expected` size and time. [`FsError::Changed`]
    /// if it doesn't, or if a folder is there now.
    fn remove_file(
        &self,
        path: &RelPath,
        expected: Stat,
    ) -> impl Future<Output = Result<(), FsError>> + Send;

    /// Removes an empty folder. [`FsError::Changed`] if a file is there now.
    fn remove_dir(&self, path: &RelPath) -> impl Future<Output = Result<(), FsError>> + Send;

    /// Starts a temporary file (inside `.oxidrive/tmp/`, decision X1).
    fn create_temp(&self) -> impl Future<Output = Result<TempId, FsError>> + Send;

    /// Appends to a temporary file.
    fn append_temp(
        &self,
        temp: TempId,
        data: &[u8],
    ) -> impl Future<Output = Result<(), FsError>> + Send;

    /// Atomically moves a temporary file to `target`, with the given time and executable bit.
    /// Only if `target` is absent (`expected` = `None`) or still has `expected` size and time.
    /// Returns the new stat.
    fn commit_temp(
        &self,
        temp: TempId,
        target: &RelPath,
        expected: Option<Stat>,
        mtime_ms: i64,
        executable: bool,
    ) -> impl Future<Output = Result<Stat, FsError>> + Send;

    /// Throws a temporary file away.
    fn discard_temp(&self, temp: TempId) -> impl Future<Output = Result<(), FsError>> + Send;
}

/// Server failures the engine distinguishes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServerError {
    /// The server couldn't be reached or didn't answer; try again later.
    #[error("server unavailable: {0}")]
    Unavailable(String),
    /// The object doesn't exist.
    #[error("not found")]
    NotFound,
    /// The server refused the request.
    #[error("rejected: {0}")]
    Rejected(String),
}

/// The server's view of one collection (server API §5, §6).
pub trait ServerApi: Send + Sync {
    /// The collection's head.
    fn head(
        &self,
        collection: CollectionId,
    ) -> impl Future<Output = Result<Option<Head>, ServerError>> + Send;

    /// Commits after `after`, oldest first, at most `limit`.
    fn commits_after(
        &self,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> impl Future<Output = Result<Commits, ServerError>> + Send;

    /// Appends a commit if the head is still `expected` (compare-and-swap).
    fn append(
        &self,
        collection: CollectionId,
        expected: Option<Head>,
        commit: Commit,
    ) -> impl Future<Output = Result<AppendResult, ServerError>> + Send;

    /// Which of `ids` the server lacks, with a lease protecting all of them.
    fn missing(
        &self,
        collection: CollectionId,
        ids: Vec<ChunkId>,
    ) -> impl Future<Output = Result<Missing, ServerError>> + Send;

    /// Stores a chunk object.
    fn put_chunk(
        &self,
        collection: CollectionId,
        lease: LeaseId,
        id: ChunkId,
        object: Vec<u8>,
    ) -> impl Future<Output = Result<(), ServerError>> + Send;

    /// Fetches a chunk object.
    fn get_chunk(
        &self,
        collection: CollectionId,
        id: ChunkId,
    ) -> impl Future<Output = Result<Vec<u8>, ServerError>> + Send;
}

/// Everything the index holds for one collection on one device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexState {
    /// The last synced state, per node.
    pub base: crate::model::Base,
    /// The replayed remote state (sync protocol §7: kept, not replayed on every start).
    pub remote: std::collections::BTreeMap<NodeId, RemoteEntry>,
    /// The newest verified head.
    pub head: Option<Head>,
    /// The device's version counter (sync protocol §1).
    pub counter: u64,
}

/// A change to the index, applied atomically.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexTxn {
    /// Base entries to store.
    pub put: Vec<(NodeId, BaseEntry)>,
    /// Base entries to drop.
    pub remove: Vec<NodeId>,
    /// Remote entries to store.
    pub remote: Vec<(NodeId, RemoteEntry)>,
    /// New verified head.
    pub head: Option<Head>,
    /// New version counter.
    pub counter: Option<u64>,
}

impl IndexTxn {
    /// Whether it changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.put.is_empty()
            && self.remove.is_empty()
            && self.remote.is_empty()
            && self.head.is_none()
            && self.counter.is_none()
    }

    /// Applies it to an in-memory state (what an index store does on disk).
    pub fn apply_to(&self, state: &mut IndexState) {
        for (node, entry) in &self.put {
            state.base.insert(*node, entry.clone());
        }
        for node in &self.remove {
            state.base.remove(node);
        }
        for (node, entry) in &self.remote {
            state.remote.insert(*node, entry.clone());
        }
        if let Some(head) = self.head {
            state.head = Some(head);
        }
        if let Some(counter) = self.counter {
            state.counter = counter;
        }
    }
}

/// Index failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("index error: {0}")]
pub struct IndexError(pub String);

/// The device's persistent index for one collection (core engine §4).
pub trait IndexStore: Send + Sync {
    /// Everything stored.
    fn load(&self) -> impl Future<Output = Result<IndexState, IndexError>> + Send;

    /// Applies a transaction atomically: all of it or nothing.
    fn apply(&self, txn: IndexTxn) -> impl Future<Output = Result<(), IndexError>> + Send;
}

/// Wall-clock time; only used for timestamps people see (sync protocol §10).
pub trait Clock: Send + Sync {
    /// Now, milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
}

// Shared implementations work through `Arc`, e.g. several devices using one test server.

impl<T: FileSystem> FileSystem for std::sync::Arc<T> {
    fn rules(&self) -> FsRules {
        (**self).rules()
    }

    fn list(&self, dir: &RelPath) -> impl Future<Output = Result<DirList, FsError>> + Send {
        (**self).list(dir)
    }

    fn stat(
        &self,
        path: &RelPath,
    ) -> impl Future<Output = Result<Option<FsEntry>, FsError>> + Send {
        (**self).stat(path)
    }

    fn read(
        &self,
        path: &RelPath,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<Vec<u8>, FsError>> + Send {
        (**self).read(path, offset, len)
    }

    fn create_dir(&self, path: &RelPath) -> impl Future<Output = Result<u64, FsError>> + Send {
        (**self).create_dir(path)
    }

    fn rename(
        &self,
        from: &RelPath,
        to: &RelPath,
    ) -> impl Future<Output = Result<(), FsError>> + Send {
        (**self).rename(from, to)
    }

    fn remove_file(
        &self,
        path: &RelPath,
        expected: Stat,
    ) -> impl Future<Output = Result<(), FsError>> + Send {
        (**self).remove_file(path, expected)
    }

    fn remove_dir(&self, path: &RelPath) -> impl Future<Output = Result<(), FsError>> + Send {
        (**self).remove_dir(path)
    }

    fn create_temp(&self) -> impl Future<Output = Result<TempId, FsError>> + Send {
        (**self).create_temp()
    }

    fn append_temp(
        &self,
        temp: TempId,
        data: &[u8],
    ) -> impl Future<Output = Result<(), FsError>> + Send {
        (**self).append_temp(temp, data)
    }

    fn commit_temp(
        &self,
        temp: TempId,
        target: &RelPath,
        expected: Option<Stat>,
        mtime_ms: i64,
        executable: bool,
    ) -> impl Future<Output = Result<Stat, FsError>> + Send {
        (**self).commit_temp(temp, target, expected, mtime_ms, executable)
    }

    fn discard_temp(&self, temp: TempId) -> impl Future<Output = Result<(), FsError>> + Send {
        (**self).discard_temp(temp)
    }
}

impl<T: ServerApi> ServerApi for std::sync::Arc<T> {
    fn head(
        &self,
        collection: CollectionId,
    ) -> impl Future<Output = Result<Option<Head>, ServerError>> + Send {
        (**self).head(collection)
    }

    fn commits_after(
        &self,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> impl Future<Output = Result<Commits, ServerError>> + Send {
        (**self).commits_after(collection, after, limit)
    }

    fn append(
        &self,
        collection: CollectionId,
        expected: Option<Head>,
        commit: Commit,
    ) -> impl Future<Output = Result<AppendResult, ServerError>> + Send {
        (**self).append(collection, expected, commit)
    }

    fn missing(
        &self,
        collection: CollectionId,
        ids: Vec<ChunkId>,
    ) -> impl Future<Output = Result<Missing, ServerError>> + Send {
        (**self).missing(collection, ids)
    }

    fn put_chunk(
        &self,
        collection: CollectionId,
        lease: LeaseId,
        id: ChunkId,
        object: Vec<u8>,
    ) -> impl Future<Output = Result<(), ServerError>> + Send {
        (**self).put_chunk(collection, lease, id, object)
    }

    fn get_chunk(
        &self,
        collection: CollectionId,
        id: ChunkId,
    ) -> impl Future<Output = Result<Vec<u8>, ServerError>> + Send {
        (**self).get_chunk(collection, id)
    }
}

impl<T: IndexStore> IndexStore for std::sync::Arc<T> {
    fn load(&self) -> impl Future<Output = Result<IndexState, IndexError>> + Send {
        (**self).load()
    }

    fn apply(&self, txn: IndexTxn) -> impl Future<Output = Result<(), IndexError>> + Send {
        (**self).apply(txn)
    }
}

impl<T: Clock> Clock for std::sync::Arc<T> {
    fn now_ms(&self) -> u64 {
        (**self).now_ms()
    }
}
