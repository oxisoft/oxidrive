//! The scanner: builds the local tree from the file system (core executor §1).

use std::collections::BTreeMap;

use oxisoft_drive_crypto::hash::KeyedHasher;
use oxisoft_drive_crypto::keys::IdKey;
use oxisoft_drive_proto::{ContentHash, Name};

use crate::model::{Base, BaseKind, LocalEntry, LocalTree, Stat};
use crate::path::RelPath;
use crate::traits::{FileSystem, FsEntry, FsError};

/// The engine's own folder at each synced root (decision X1); never scanned or synced.
pub const ENGINE_DIR: &str = ".oxidrive";
/// The folder marker inside it (sync protocol §10).
pub const MARKER: &str = "marker";

/// How much of a file is read per request while hashing.
const READ_BLOCK: usize = 1024 * 1024;

/// The scanned folder.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    /// Everything found (except the engine folder).
    pub local: LocalTree,
    /// Names the file system reported that can't be synced (not UTF-8, invalid names).
    pub unrepresentable: Vec<String>,
}

/// Whether `path` is the engine's own folder or inside it.
#[must_use]
pub fn is_engine_path(path: &RelPath) -> bool {
    path.components()
        .first()
        .is_some_and(|name| name.as_str() == ENGINE_DIR)
}

/// The marker path, `.oxidrive/marker`.
///
/// # Panics
///
/// Never: both names are fixed and valid.
#[must_use]
pub fn marker_path() -> RelPath {
    let engine = Name::new(ENGINE_DIR).unwrap_or_else(|_| unreachable!("valid constant"));
    let marker = Name::new(MARKER).unwrap_or_else(|_| unreachable!("valid constant"));
    RelPath::root().join(engine).join(marker)
}

/// Walks the folder. Files whose size or time differ from the base at the same path, and new
/// files, are hashed (keyed, whole file) so the reconciler can compare contents.
///
/// # Errors
///
/// File system failures. A file that disappears while being hashed is simply left out.
pub async fn scan<F: FileSystem>(fs: &F, base: &Base, id_key: &IdKey) -> Result<Scan, FsError> {
    let synced: BTreeMap<&RelPath, Stat> = base
        .values()
        .filter_map(|entry| match entry.kind {
            BaseKind::File { stat, .. } => Some((&entry.path, stat)),
            BaseKind::Folder { .. } => None,
        })
        .collect();
    let mut result = Scan::default();
    let mut pending = vec![RelPath::root()];
    while let Some(dir) = pending.pop() {
        let listing = match fs.list(&dir).await {
            Ok(listing) => listing,
            // Removed while scanning: it will show up as deleted.
            Err(FsError::NotFound) => continue,
            Err(error) => return Err(error),
        };
        result.unrepresentable.extend(
            listing
                .unrepresentable
                .into_iter()
                .map(|name| format!("{dir}/{name}")),
        );
        for entry in listing.entries {
            let path = dir.join(entry.name);
            if is_engine_path(&path) {
                continue;
            }
            match entry.entry {
                FsEntry::Folder { file_id } => {
                    result
                        .local
                        .insert(path.clone(), LocalEntry::Folder { file_id });
                    pending.push(path);
                }
                FsEntry::File(stat) => {
                    let unchanged = synced.get(&path).is_some_and(|synced| {
                        synced.size == stat.size && synced.mtime_ms == stat.mtime_ms
                    });
                    let content = if unchanged {
                        None
                    } else {
                        match content_hash(fs, &path, stat.size, id_key).await {
                            Ok(hash) => Some(hash),
                            Err(FsError::NotFound) => continue,
                            Err(error) => return Err(error),
                        }
                    };
                    result
                        .local
                        .insert(path, LocalEntry::File { stat, content });
                }
            }
        }
    }
    Ok(result)
}

/// Keyed hash of a whole file, read in blocks.
///
/// # Errors
///
/// File system failures.
pub async fn content_hash<F: FileSystem>(
    fs: &F,
    path: &RelPath,
    size: u64,
    id_key: &IdKey,
) -> Result<ContentHash, FsError> {
    let mut hasher = KeyedHasher::new(id_key);
    let mut offset = 0;
    loop {
        let block = fs.read(path, offset, READ_BLOCK).await?;
        hasher.update(&block);
        offset += block.len() as u64;
        if block.len() < READ_BLOCK || offset >= size {
            break;
        }
    }
    Ok(ContentHash(hasher.finalize()))
}
