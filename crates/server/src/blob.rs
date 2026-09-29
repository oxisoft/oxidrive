//! Chunk object storage (server storage §3): the [`BlobStore`] trait, the local file-system
//! backend, and an in-memory backend with failure injection for tests.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::future::Future;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use oxisoft_drive_crypto::hash::Digest;
use oxisoft_drive_proto::{AccountId, ChunkId, CollectionId};

/// Where one chunk object lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlobKey {
    /// The collection's account.
    pub account: AccountId,
    /// The collection.
    pub collection: CollectionId,
    /// The chunk (ordered by its bytes).
    pub chunk: ChunkBytes,
}

/// A chunk ID as ordered bytes (chunk IDs themselves have no order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChunkBytes(pub [u8; 32]);

impl From<ChunkId> for ChunkBytes {
    fn from(chunk: ChunkId) -> Self {
        Self(*chunk.0.as_bytes())
    }
}

impl From<ChunkBytes> for ChunkId {
    fn from(bytes: ChunkBytes) -> Self {
        Self(Digest::from_bytes(bytes.0))
    }
}

impl BlobKey {
    /// The key of a chunk.
    #[must_use]
    pub fn new(account: AccountId, collection: CollectionId, chunk: ChunkId) -> Self {
        Self {
            account,
            collection,
            chunk: chunk.into(),
        }
    }
}

/// Blob storage failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlobError {
    /// No such object.
    #[error("no such object")]
    NotFound,
    /// The storage failed.
    #[error("blob storage: {0}")]
    Io(String),
}

/// Stores chunk objects. Objects never change once written.
pub trait BlobStore: Send + Sync {
    /// Stores an object: atomically (all or nothing, even across a crash) and idempotently.
    fn put(
        &self,
        key: &BlobKey,
        object: &[u8],
    ) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// Reads an object.
    fn get(&self, key: &BlobKey) -> impl Future<Output = Result<Vec<u8>, BlobError>> + Send;

    /// An object's size in bytes (for fsck), without reading it.
    fn size(&self, key: &BlobKey) -> impl Future<Output = Result<u64, BlobError>> + Send;

    /// Deletes an object; deleting a missing one is fine.
    fn delete(&self, key: &BlobKey) -> impl Future<Output = Result<(), BlobError>> + Send;

    /// Up to `limit` keys after `after`, in key order.
    fn list(
        &self,
        after: Option<BlobKey>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<BlobKey>, BlobError>> + Send;
}

impl<T: BlobStore> BlobStore for std::sync::Arc<T> {
    fn put(
        &self,
        key: &BlobKey,
        object: &[u8],
    ) -> impl Future<Output = Result<(), BlobError>> + Send {
        T::put(self, key, object)
    }

    fn get(&self, key: &BlobKey) -> impl Future<Output = Result<Vec<u8>, BlobError>> + Send {
        T::get(self, key)
    }

    fn size(&self, key: &BlobKey) -> impl Future<Output = Result<u64, BlobError>> + Send {
        T::size(self, key)
    }

    fn delete(&self, key: &BlobKey) -> impl Future<Output = Result<(), BlobError>> + Send {
        T::delete(self, key)
    }

    fn list(
        &self,
        after: Option<BlobKey>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<BlobKey>, BlobError>> + Send {
        T::list(self, after, limit)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N {
        return None;
    }
    let mut out = [0; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * index..2 * index + 2)?, 16).ok()?;
    }
    Some(out)
}

fn io_error(error: &io::Error) -> BlobError {
    BlobError::Io(error.to_string())
}

/// Objects as files: `<root>/<account>/<collection>/<id[0..2]>/<id[2..4]>/<id>`, all hex.
#[derive(Debug, Clone)]
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    /// Stores objects below `root` (created if needed).
    ///
    /// # Errors
    ///
    /// If `root` can't be created.
    pub fn new(root: &Path) -> Result<Self, BlobError> {
        std::fs::create_dir_all(root).map_err(|error| io_error(&error))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn path(&self, key: &BlobKey) -> PathBuf {
        let id = hex(&key.chunk.0);
        self.root
            .join(hex(key.account.as_bytes()))
            .join(hex(key.collection.as_bytes()))
            .join(&id[0..2])
            .join(&id[2..4])
            .join(id)
    }

    fn put_now(path: &Path, object: &[u8]) -> io::Result<()> {
        if path.exists() {
            return Ok(());
        }
        let dir = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        // Written to a temporary file beside it, flushed, then renamed: never half an object.
        let mut file = tempfile::NamedTempFile::new_in(dir)?;
        file.write_all(object)?;
        file.as_file().sync_all()?;
        file.persist(path).map_err(|error| error.error)?;
        sync_dir(dir)
    }

    fn list_now(&self, after: Option<BlobKey>, limit: usize) -> io::Result<Vec<BlobKey>> {
        let mut keys = Vec::new();
        for account in sorted_dir(&self.root)? {
            let Some(account_id) = unhex(&account).map(AccountId::from_bytes) else {
                continue;
            };
            if after.is_some_and(|after| account_id < after.account) {
                continue;
            }
            let account_dir = self.root.join(&account);
            for collection in sorted_dir(&account_dir)? {
                let Some(collection_id) = unhex(&collection).map(CollectionId::from_bytes) else {
                    continue;
                };
                let collection_dir = account_dir.join(&collection);
                for first in sorted_dir(&collection_dir)? {
                    for second in sorted_dir(&collection_dir.join(&first))? {
                        let leaf = collection_dir.join(&first).join(&second);
                        for name in sorted_dir(&leaf)? {
                            let Some(chunk) = unhex(&name).map(ChunkBytes) else {
                                continue;
                            };
                            let key = BlobKey {
                                account: account_id,
                                collection: collection_id,
                                chunk,
                            };
                            if after.is_none_or(|after| key > after) {
                                keys.push(key);
                                if keys.len() == limit {
                                    return Ok(keys);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(keys)
    }
}

/// Names in a directory, sorted; a missing directory is empty.
fn sorted_dir(dir: &Path) -> io::Result<Vec<String>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut names = Vec::new();
    for entry in entries {
        if let Ok(name) = entry?.file_name().into_string() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Makes a rename durable. Windows can't open directories and journals renames itself.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, BlobError> + Send + 'static,
) -> Result<T, BlobError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| BlobError::Io(error.to_string()))?
}

impl BlobStore for FsBlobStore {
    async fn put(&self, key: &BlobKey, object: &[u8]) -> Result<(), BlobError> {
        let (path, object) = (self.path(key), object.to_vec());
        blocking(move || Self::put_now(&path, &object).map_err(|error| io_error(&error))).await
    }

    async fn get(&self, key: &BlobKey) -> Result<Vec<u8>, BlobError> {
        let path = self.path(key);
        blocking(move || match std::fs::read(&path) {
            Ok(object) => Ok(object),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(BlobError::NotFound),
            Err(error) => Err(io_error(&error)),
        })
        .await
    }

    async fn size(&self, key: &BlobKey) -> Result<u64, BlobError> {
        let path = self.path(key);
        blocking(move || match std::fs::metadata(&path) {
            Ok(metadata) => Ok(metadata.len()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(BlobError::NotFound),
            Err(error) => Err(io_error(&error)),
        })
        .await
    }

    async fn delete(&self, key: &BlobKey) -> Result<(), BlobError> {
        let path = self.path(key);
        blocking(move || match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(&error)),
        })
        .await
    }

    async fn list(&self, after: Option<BlobKey>, limit: usize) -> Result<Vec<BlobKey>, BlobError> {
        let store = self.clone();
        blocking(move || {
            store
                .list_now(after, limit)
                .map_err(|error| io_error(&error))
        })
        .await
    }
}

/// A blob store operation, for failure injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobOp {
    /// `put`.
    Put,
    /// `get`.
    Get,
    /// `size`.
    Size,
    /// `delete`.
    Delete,
    /// `list`.
    List,
}

#[derive(Debug, Default)]
struct MemInner {
    objects: BTreeMap<BlobKey, Vec<u8>>,
    failures: Vec<BlobOp>,
}

/// Objects in memory, with injectable failures (for tests).
#[derive(Debug, Default)]
pub struct MemBlobStore {
    inner: Mutex<MemInner>,
}

impl MemBlobStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, MemInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes the next call of `op` fail.
    pub fn fail_next(&self, op: BlobOp) {
        self.lock().failures.push(op);
    }

    /// How many objects are stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().objects.len()
    }

    /// Whether nothing is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Stores an object behind the service's back (to corrupt a store in tests).
    pub fn insert(&self, key: BlobKey, object: Vec<u8>) {
        self.lock().objects.insert(key, object);
    }

    /// Removes an object behind the service's back (to corrupt a store in tests).
    pub fn remove(&self, key: &BlobKey) {
        self.lock().objects.remove(key);
    }

    fn check(&self, op: BlobOp) -> Result<MutexGuard<'_, MemInner>, BlobError> {
        let mut inner = self.lock();
        if let Some(index) = inner.failures.iter().position(|failing| *failing == op) {
            inner.failures.remove(index);
            return Err(BlobError::Io("injected failure".into()));
        }
        Ok(inner)
    }
}

impl BlobStore for MemBlobStore {
    fn put(
        &self,
        key: &BlobKey,
        object: &[u8],
    ) -> impl Future<Output = Result<(), BlobError>> + Send {
        let result = self.check(BlobOp::Put).map(|mut inner| {
            inner.objects.entry(*key).or_insert_with(|| object.to_vec());
        });
        std::future::ready(result)
    }

    fn get(&self, key: &BlobKey) -> impl Future<Output = Result<Vec<u8>, BlobError>> + Send {
        let result = self
            .check(BlobOp::Get)
            .and_then(|inner| inner.objects.get(key).cloned().ok_or(BlobError::NotFound));
        std::future::ready(result)
    }

    fn size(&self, key: &BlobKey) -> impl Future<Output = Result<u64, BlobError>> + Send {
        let result = self.check(BlobOp::Size).and_then(|inner| {
            inner
                .objects
                .get(key)
                .map(|object| object.len() as u64)
                .ok_or(BlobError::NotFound)
        });
        std::future::ready(result)
    }

    fn delete(&self, key: &BlobKey) -> impl Future<Output = Result<(), BlobError>> + Send {
        let result = self.check(BlobOp::Delete).map(|mut inner| {
            inner.objects.remove(key);
        });
        std::future::ready(result)
    }

    fn list(
        &self,
        after: Option<BlobKey>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<BlobKey>, BlobError>> + Send {
        let result = self.check(BlobOp::List).map(|inner| {
            inner
                .objects
                .keys()
                .filter(|key| after.is_none_or(|after| **key > after))
                .take(limit)
                .copied()
                .collect()
        });
        std::future::ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(account: u8, collection: u8, chunk: u8) -> BlobKey {
        BlobKey {
            account: AccountId::from_bytes([account; 16]),
            collection: CollectionId::from_bytes([collection; 16]),
            chunk: ChunkBytes([chunk; 32]),
        }
    }

    async fn round_trip<B: BlobStore>(store: &B) {
        let keys = [key(2, 1, 9), key(1, 2, 3), key(1, 1, 7), key(1, 1, 5)];
        for (index, key) in keys.iter().enumerate() {
            store
                .put(key, &[u8::try_from(index).unwrap(); 10])
                .await
                .unwrap();
        }
        // Idempotent: a second put of the same object (or any) keeps the first.
        store.put(&keys[0], b"other").await.unwrap();
        assert_eq!(store.get(&keys[0]).await.unwrap(), [0; 10]);
        assert_eq!(store.size(&keys[0]).await.unwrap(), 10);
        assert_eq!(store.size(&key(9, 9, 9)).await, Err(BlobError::NotFound));
        assert_eq!(store.get(&key(9, 9, 9)).await, Err(BlobError::NotFound));

        let mut listed = Vec::new();
        let mut after = None;
        loop {
            let page = store.list(after, 3).await.unwrap();
            let Some(last) = page.last() else {
                break;
            };
            after = Some(*last);
            listed.extend(page);
        }
        let mut sorted = keys.to_vec();
        sorted.sort();
        assert_eq!(listed, sorted);

        store.delete(&keys[1]).await.unwrap();
        store.delete(&keys[1]).await.unwrap();
        assert_eq!(store.get(&keys[1]).await, Err(BlobError::NotFound));
        assert_eq!(store.list(None, 10).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn file_system_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlobStore::new(&dir.path().join("blobs")).unwrap();
        round_trip(&store).await;
        // Stray files and unknown names are not objects.
        let stray = dir.path().join("blobs").join("not-hex");
        std::fs::create_dir_all(&stray).unwrap();
        std::fs::write(stray.join("x"), b"x").unwrap();
        assert_eq!(store.list(None, 10).await.unwrap().len(), 3);
        // No temporary files are left behind.
        let leftovers = walk(dir.path())
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".tmp"))
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    #[tokio::test]
    async fn memory_store_and_failures() {
        let store = MemBlobStore::new();
        round_trip(&store).await;
        assert_eq!(store.len(), 3);
        for op in [
            BlobOp::Put,
            BlobOp::Get,
            BlobOp::Size,
            BlobOp::Delete,
            BlobOp::List,
        ] {
            store.fail_next(op);
        }
        let first = key(1, 1, 5);
        assert!(store.put(&key(3, 3, 3), b"x").await.is_err());
        assert!(store.get(&first).await.is_err());
        assert!(store.size(&first).await.is_err());
        assert!(store.delete(&first).await.is_err());
        assert!(store.list(None, 1).await.is_err());
        assert!(store.get(&first).await.is_ok());
        store.remove(&first);
        store.insert(key(4, 4, 4), vec![4]);
        assert!(!store.is_empty());
        assert_eq!(store.get(&key(4, 4, 4)).await.unwrap(), [4]);
    }

    #[test]
    fn hex_round_trips_and_rejects_bad_text() {
        assert_eq!(hex(&[0, 171, 255]), "00abff");
        assert_eq!(unhex::<3>("00abff"), Some([0, 171, 255]));
        assert_eq!(unhex::<3>("00abf"), None);
        assert_eq!(unhex::<1>("zz"), None);
        let chunk = ChunkId(Digest::from_bytes([6; 32]));
        assert_eq!(ChunkId::from(ChunkBytes::from(chunk)), chunk);
    }
}
