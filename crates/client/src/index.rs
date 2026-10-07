//! [`SqliteIndex`]: core's [`IndexStore`] in a SQLite file, one per collection (client
//! foundation §3, decision L3).
//!
//! Entries are CBOR with fixed field numbers (decision B3), so core's types carry no
//! encoding. The database holds the decrypted metadata of a folder that is decrypted on this
//! disk anyway, and no keys.

use std::future::Future;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use minicbor::{Decode, Encode};
use oxisoft_drive_core::{
    BaseEntry, BaseKind, FileMeta, IndexError, IndexState, IndexStore, IndexTxn, RelPath,
    RemoteEntry, RemoteKind, RemoteNode, Stat,
};
use oxisoft_drive_crypto::hash::Digest;
use oxisoft_drive_proto::api::Head;
use oxisoft_drive_proto::{ChunkRef, CommitHash, ContentHash, Name, NodeId, Version};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

/// The entry encoding this code reads and writes.
const FORMAT: i64 = 1;
/// How long a writer waits for the lock.
const BUSY_TIMEOUT: Duration = Duration::from_secs(30);

/// A collection's index on this device.
#[derive(Debug, Clone)]
pub struct SqliteIndex {
    pool: SqlitePool,
}

fn index_error(error: impl std::fmt::Display) -> IndexError {
    IndexError(error.to_string())
}

impl SqliteIndex {
    /// Opens (creating if needed) the index at `path` and brings its schema up to date.
    ///
    /// # Errors
    ///
    /// [`IndexError`] if it can't be opened, or was written by a newer version.
    pub async fn open(path: &Path) -> Result<Self, IndexError> {
        let options = SqliteConnectOptions::from_str("sqlite:")
            .map_err(index_error)?
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(BUSY_TIMEOUT);
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await
            .map_err(index_error)?;
        sqlx::migrate!().run(&pool).await.map_err(index_error)?;
        let format = sqlx::query_scalar!("SELECT format FROM state WHERE one = 1")
            .fetch_one(&pool)
            .await
            .map_err(index_error)?;
        if format != FORMAT {
            return Err(IndexError(format!(
                "index format {format}, this version reads {FORMAT}"
            )));
        }
        Ok(Self { pool })
    }

    async fn load_now(&self) -> Result<IndexState, IndexError> {
        let mut connection = self.pool.acquire().await.map_err(index_error)?;
        let state = sqlx::query!("SELECT head_seq, head_hash, counter FROM state WHERE one = 1")
            .fetch_one(&mut *connection)
            .await
            .map_err(index_error)?;
        let head = match (state.head_seq, state.head_hash) {
            (Some(seq), Some(hash)) => Some(Head {
                seq: u64::try_from(seq).map_err(index_error)?,
                hash: CommitHash(digest(&hash)?),
            }),
            _ => None,
        };
        let mut loaded = IndexState {
            head,
            counter: u64::try_from(state.counter).map_err(index_error)?,
            ..IndexState::default()
        };
        for row in sqlx::query!("SELECT node, entry FROM base")
            .fetch_all(&mut *connection)
            .await
            .map_err(index_error)?
        {
            let entry: StoredBase = minicbor::decode(&row.entry).map_err(index_error)?;
            loaded.base.insert(node_id(&row.node)?, entry.into_core());
        }
        for row in sqlx::query!("SELECT node, entry FROM remote")
            .fetch_all(&mut *connection)
            .await
            .map_err(index_error)?
        {
            let entry: StoredRemote = minicbor::decode(&row.entry).map_err(index_error)?;
            loaded.remote.insert(node_id(&row.node)?, entry.into_core());
        }
        Ok(loaded)
    }

    async fn apply_now(&self, txn: IndexTxn) -> Result<(), IndexError> {
        if txn.is_empty() {
            return Ok(());
        }
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(index_error)?;
        for (node, entry) in &txn.put {
            let (key, value) = (
                node.as_bytes().as_slice(),
                minicbor::to_vec(StoredBase::from_core(entry)).map_err(index_error)?,
            );
            sqlx::query!(
                "INSERT INTO base (node, entry) VALUES (?, ?)
                 ON CONFLICT (node) DO UPDATE SET entry = excluded.entry",
                key,
                value
            )
            .execute(&mut *tx)
            .await
            .map_err(index_error)?;
        }
        for node in &txn.remove {
            let key = node.as_bytes().as_slice();
            sqlx::query!("DELETE FROM base WHERE node = ?", key)
                .execute(&mut *tx)
                .await
                .map_err(index_error)?;
        }
        for (node, entry) in &txn.remote {
            let (key, value) = (
                node.as_bytes().as_slice(),
                minicbor::to_vec(StoredRemote::from_core(entry)).map_err(index_error)?,
            );
            sqlx::query!(
                "INSERT INTO remote (node, entry) VALUES (?, ?)
                 ON CONFLICT (node) DO UPDATE SET entry = excluded.entry",
                key,
                value
            )
            .execute(&mut *tx)
            .await
            .map_err(index_error)?;
        }
        if let Some(head) = txn.head {
            let (seq, hash) = (
                i64::try_from(head.seq).map_err(index_error)?,
                head.hash.0.as_bytes().as_slice(),
            );
            sqlx::query!(
                "UPDATE state SET head_seq = ?, head_hash = ? WHERE one = 1",
                seq,
                hash
            )
            .execute(&mut *tx)
            .await
            .map_err(index_error)?;
        }
        if let Some(counter) = txn.counter {
            let counter = i64::try_from(counter).map_err(index_error)?;
            sqlx::query!("UPDATE state SET counter = ? WHERE one = 1", counter)
                .execute(&mut *tx)
                .await
                .map_err(index_error)?;
        }
        tx.commit().await.map_err(index_error)
    }
}

impl IndexStore for SqliteIndex {
    fn load(&self) -> impl Future<Output = Result<IndexState, IndexError>> + Send {
        self.load_now()
    }

    fn apply(&self, txn: IndexTxn) -> impl Future<Output = Result<(), IndexError>> + Send {
        self.apply_now(txn)
    }
}

fn digest(bytes: &[u8]) -> Result<Digest, IndexError> {
    let fixed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| IndexError(format!("{} bytes where a hash belongs", bytes.len())))?;
    Ok(Digest::from_bytes(fixed))
}

fn node_id(bytes: &[u8]) -> Result<NodeId, IndexError> {
    let fixed = bytes
        .try_into()
        .map_err(|_| IndexError(format!("{} bytes where a node ID belongs", bytes.len())))?;
    Ok(NodeId::from_bytes(fixed))
}

// ── the stored forms ────────────────────────────────────────────────────────────────

#[derive(Encode, Decode)]
struct StoredStat {
    #[n(0)]
    size: u64,
    #[n(1)]
    mtime_ms: i64,
    #[n(2)]
    file_id: u64,
    #[n(3)]
    executable: bool,
    #[n(4)]
    change: u64,
}

impl StoredStat {
    const fn from_core(stat: &Stat) -> Self {
        Self {
            size: stat.size,
            mtime_ms: stat.mtime_ms,
            file_id: stat.file_id,
            executable: stat.executable,
            change: stat.change,
        }
    }

    const fn into_core(self) -> Stat {
        Stat {
            size: self.size,
            mtime_ms: self.mtime_ms,
            file_id: self.file_id,
            executable: self.executable,
            change: self.change,
        }
    }
}

#[derive(Encode, Decode)]
enum StoredBaseKind {
    #[n(0)]
    File {
        #[n(0)]
        stat: StoredStat,
        #[n(1)]
        content: ContentHash,
    },
    #[n(1)]
    Folder {
        #[n(0)]
        file_id: u64,
    },
}

#[derive(Encode, Decode)]
struct StoredBase {
    #[n(0)]
    path: Vec<Name>,
    #[n(1)]
    kind: StoredBaseKind,
    #[n(2)]
    version: Version,
}

impl StoredBase {
    fn from_core(entry: &BaseEntry) -> Self {
        Self {
            path: entry.path.components().to_vec(),
            kind: match &entry.kind {
                BaseKind::File { stat, content } => StoredBaseKind::File {
                    stat: StoredStat::from_core(stat),
                    content: *content,
                },
                BaseKind::Folder { file_id } => StoredBaseKind::Folder { file_id: *file_id },
            },
            version: entry.version,
        }
    }

    fn into_core(self) -> BaseEntry {
        let path = self
            .path
            .into_iter()
            .fold(RelPath::root(), |path, name| path.join(name));
        BaseEntry {
            path,
            kind: match self.kind {
                StoredBaseKind::File { stat, content } => BaseKind::File {
                    stat: stat.into_core(),
                    content,
                },
                StoredBaseKind::Folder { file_id } => BaseKind::Folder { file_id },
            },
            version: self.version,
        }
    }
}

#[derive(Encode, Decode)]
enum StoredRemoteKind {
    #[n(0)]
    File {
        #[n(0)]
        content: ContentHash,
        #[n(1)]
        size: u64,
    },
    #[n(1)]
    Folder,
    #[n(2)]
    Deleted,
}

#[derive(Encode, Decode)]
struct StoredFileMeta {
    #[n(0)]
    chunks: Vec<ChunkRef>,
    #[n(1)]
    mtime_ms: i64,
    #[n(2)]
    executable: bool,
    #[n(3)]
    epoch: u32,
}

#[derive(Encode, Decode)]
struct StoredRemote {
    #[n(0)]
    parent: Option<NodeId>,
    #[n(1)]
    name: Name,
    #[n(2)]
    kind: StoredRemoteKind,
    #[n(3)]
    version: Version,
    #[n(4)]
    file: Option<StoredFileMeta>,
}

impl StoredRemote {
    fn from_core(entry: &RemoteEntry) -> Self {
        let node = &entry.node;
        Self {
            parent: node.parent,
            name: node.name.clone(),
            kind: match &node.kind {
                RemoteKind::File { content, size } => StoredRemoteKind::File {
                    content: *content,
                    size: *size,
                },
                RemoteKind::Folder => StoredRemoteKind::Folder,
                RemoteKind::Deleted => StoredRemoteKind::Deleted,
            },
            version: node.version,
            file: entry.file.as_ref().map(|file| StoredFileMeta {
                chunks: file.chunks.clone(),
                mtime_ms: file.mtime_ms,
                executable: file.executable,
                epoch: file.epoch,
            }),
        }
    }

    fn into_core(self) -> RemoteEntry {
        RemoteEntry {
            node: RemoteNode {
                parent: self.parent,
                name: self.name,
                kind: match self.kind {
                    StoredRemoteKind::File { content, size } => RemoteKind::File { content, size },
                    StoredRemoteKind::Folder => RemoteKind::Folder,
                    StoredRemoteKind::Deleted => RemoteKind::Deleted,
                },
                version: self.version,
            },
            file: self.file.map(|file| FileMeta {
                chunks: file.chunks,
                mtime_ms: file.mtime_ms,
                executable: file.executable,
                epoch: file.epoch,
            }),
        }
    }
}
