//! [`OsFs`]: core's [`FileSystem`] on a real folder (client foundation §2).
//!
//! Calls do their disk work directly and return finished futures, as the in-memory file
//! system does: run the engine where blocking is fine.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oxisoft_drive_core::{
    DirEntry, DirList, ENGINE_DIR, FileSystem, FsEntry, FsError, FsRules, RelPath, Stat, TempId,
    windows_allows,
};
use oxisoft_drive_proto::Name;

/// Where temporary files live, inside the engine's folder (core decision X1).
const TEMP_DIR: &str = "tmp";

/// A synced folder on the local disk.
#[derive(Debug)]
pub struct OsFs {
    root: PathBuf,
    rules: FsRules,
    next_temp: AtomicU64,
    temps: Mutex<BTreeMap<u64, PathBuf>>,
}

fn io_error(error: &io::Error) -> FsError {
    match error.kind() {
        io::ErrorKind::NotFound => FsError::NotFound,
        io::ErrorKind::AlreadyExists => FsError::AlreadyExists,
        io::ErrorKind::DirectoryNotEmpty => FsError::NotEmpty,
        _ => FsError::Io(error.to_string()),
    }
}

/// Milliseconds since the Unix epoch, negative before it.
fn millis(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

fn system_time(mtime_ms: i64) -> SystemTime {
    let magnitude = Duration::from_millis(mtime_ms.unsigned_abs());
    if mtime_ms >= 0 {
        UNIX_EPOCH + magnitude
    } else {
        UNIX_EPOCH - magnitude
    }
}

/// Names a file system keeps in another Unicode form than the one it was given, so a name
/// read from disk that isn't NFC still finds its file. Only macOS's file systems do.
const NORMALIZATION_INSENSITIVE: bool = cfg!(target_os = "macos");

#[cfg(unix)]
fn file_id(_path: &Path, metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

#[cfg(windows)]
fn file_id(path: &Path, _metadata: &std::fs::Metadata) -> u64 {
    match file_id::get_low_res_file_id(path) {
        Ok(file_id::FileId::LowRes { file_index, .. }) => file_index,
        Ok(file_id::FileId::HighRes { file_id, .. }) => {
            u64::try_from(file_id & u128::from(u64::MAX)).unwrap_or(0)
        }
        Ok(file_id::FileId::Inode { inode_number, .. }) => inode_number,
        Err(_) => 0,
    }
}

#[cfg(unix)]
fn executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
const fn executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// The change time as an opaque stamp: ctime in nanoseconds (core decision M4).
#[cfg(unix)]
fn change(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let seconds = u64::try_from(metadata.ctime()).unwrap_or(0);
    let nanos = u64::try_from(metadata.ctime_nsec()).unwrap_or(0);
    seconds.wrapping_mul(1_000_000_000).wrapping_add(nanos)
}

/// Windows has no change time without unsafe code (client foundation B1): 0, which core
/// accepts as "none".
#[cfg(not(unix))]
const fn change(_metadata: &std::fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn set_executable(file: &std::fs::File, executable: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = file.metadata()?.permissions();
    let mode = permissions.mode();
    let mode = if executable {
        // Executable for whoever may read it.
        mode | ((mode & 0o444) >> 2)
    } else {
        mode & !0o111
    };
    permissions.set_mode(mode);
    file.set_permissions(permissions)
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the Unix version, which can fail"
)]
fn set_executable(_file: &std::fs::File, _executable: bool) -> io::Result<()> {
    Ok(())
}

/// Makes a rename durable. Windows can't open folders and journals renames itself.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the Unix version, which can fail"
)]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

impl OsFs {
    /// The folder at `root`, which must exist. Leftover temporary files of an earlier run
    /// are removed, and the folder's name rules are probed.
    ///
    /// # Errors
    ///
    /// [`FsError`] if `root` isn't a folder or the engine's folder can't be prepared.
    pub fn open(root: &Path) -> Result<Self, FsError> {
        if !std::fs::metadata(root)
            .map_err(|error| io_error(&error))?
            .is_dir()
        {
            return Err(FsError::Io(format!("{} isn't a folder", root.display())));
        }
        let temp_dir = root.join(ENGINE_DIR).join(TEMP_DIR);
        match std::fs::remove_dir_all(&temp_dir) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(io_error(&error));
            }
            _ => {}
        }
        std::fs::create_dir_all(&temp_dir).map_err(|error| io_error(&error))?;
        let case_insensitive = probe_case(&temp_dir).map_err(|error| io_error(&error))?;
        Ok(Self {
            root: root.to_path_buf(),
            rules: FsRules {
                case_insensitive,
                windows_names: cfg!(windows) || case_insensitive,
            },
            next_temp: AtomicU64::new(0),
            temps: Mutex::new(BTreeMap::new()),
        })
    }

    /// The folder's root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, path: &RelPath) -> PathBuf {
        let mut full = self.root.clone();
        for name in path.components() {
            full.push(name.as_str());
        }
        full
    }

    fn allowed(&self, path: &RelPath) -> Result<(), FsError> {
        if !self.rules.windows_names || path.name().is_none_or(windows_allows) {
            Ok(())
        } else {
            Err(FsError::Io(format!("name not allowed: {path}")))
        }
    }

    fn is_folder(&self, path: &RelPath) -> bool {
        std::fs::symlink_metadata(self.path(path)).is_ok_and(|metadata| metadata.is_dir())
    }

    /// What is at `full`: a file, a folder, or nothing (symlinks and special files count as
    /// nothing, F12).
    fn entry(full: &Path) -> Result<Option<FsEntry>, FsError> {
        let metadata = match std::fs::symlink_metadata(full) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(&error)),
        };
        let kind = metadata.file_type();
        Ok(if kind.is_dir() {
            Some(FsEntry::Folder {
                file_id: file_id(full, &metadata),
            })
        } else if kind.is_file() {
            Some(FsEntry::File(Stat {
                size: metadata.len(),
                mtime_ms: metadata.modified().map_or(0, millis),
                file_id: file_id(full, &metadata),
                executable: executable(&metadata),
                change: change(&metadata),
            }))
        } else {
            None
        })
    }

    fn temp_path(&self, temp: TempId) -> Result<PathBuf, FsError> {
        self.temps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&temp.0)
            .cloned()
            .ok_or(FsError::NotFound)
    }

    fn list_now(&self, dir: &RelPath) -> Result<DirList, FsError> {
        let entries = std::fs::read_dir(self.path(dir)).map_err(|error| io_error(&error))?;
        let mut list = DirList::default();
        for entry in entries {
            let entry = entry.map_err(|error| io_error(&error))?;
            let raw = entry.file_name();
            let Some(text) = raw.to_str() else {
                list.unrepresentable
                    .push(raw.to_string_lossy().into_owned());
                continue;
            };
            let name = match Name::new(text) {
                Ok(name) if name.as_str() == text || NORMALIZATION_INSENSITIVE => name,
                // Not its NFC form, where the file system tells the forms apart: the name
                // we would sync couldn't find the file again.
                _ => {
                    list.unrepresentable.push(text.to_owned());
                    continue;
                }
            };
            if let Some(found) = Self::entry(&entry.path())? {
                list.entries.push(DirEntry { name, entry: found });
            }
        }
        list.entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(list)
    }

    fn read_now(&self, path: &RelPath, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        let full = self.path(path);
        if !std::fs::symlink_metadata(&full).is_ok_and(|metadata| metadata.is_file()) {
            return Err(FsError::NotFound);
        }
        let mut file = std::fs::File::open(&full).map_err(|error| io_error(&error))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| io_error(&error))?;
        let mut bytes = Vec::with_capacity(len.min(16 * 1024 * 1024));
        file.take(len as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error(&error))?;
        Ok(bytes)
    }

    fn create_dir_now(&self, path: &RelPath) -> Result<u64, FsError> {
        self.allowed(path)?;
        if !self.is_folder(&path.parent().unwrap_or_default()) {
            return Err(FsError::NotFound);
        }
        let full = self.path(path);
        std::fs::create_dir(&full).map_err(|error| io_error(&error))?;
        match Self::entry(&full)? {
            Some(FsEntry::Folder { file_id }) => Ok(file_id),
            _ => Err(FsError::Changed),
        }
    }

    fn rename_now(&self, from: &RelPath, to: &RelPath) -> Result<(), FsError> {
        self.allowed(to)?;
        let (source, target) = (self.path(from), self.path(to));
        let Some(moving) = Self::entry(&source)? else {
            return Err(FsError::NotFound);
        };
        if !self.is_folder(&to.parent().unwrap_or_default()) {
            return Err(FsError::NotFound);
        }
        if to.starts_with(from) && to != from {
            return Err(FsError::Io("move into itself".into()));
        }
        // Checked, then renamed (client foundation B2). On a case-insensitive file system,
        // another case of the same name is the same entry, which may be renamed.
        if let Some(existing) = Self::entry(&target)? {
            let same = file_identity(&existing) == file_identity(&moving)
                && from.fold_case() == to.fold_case();
            if !same {
                return Err(FsError::AlreadyExists);
            }
        }
        std::fs::rename(&source, &target).map_err(|error| io_error(&error))?;
        sync_dir(target.parent().unwrap_or(&self.root)).map_err(|error| io_error(&error))
    }

    fn remove_file_now(&self, path: &RelPath, expected: Stat) -> Result<(), FsError> {
        let full = self.path(path);
        match Self::entry(&full)? {
            Some(FsEntry::File(stat)) if stat.same_version(&expected) => {
                std::fs::remove_file(&full).map_err(|error| io_error(&error))
            }
            Some(_) => Err(FsError::Changed),
            None => Err(FsError::NotFound),
        }
    }

    fn remove_dir_now(&self, path: &RelPath) -> Result<(), FsError> {
        let full = self.path(path);
        match Self::entry(&full)? {
            Some(FsEntry::Folder { .. }) => {
                let mut entries = std::fs::read_dir(&full).map_err(|error| io_error(&error))?;
                if entries.next().is_some() {
                    return Err(FsError::NotEmpty);
                }
                std::fs::remove_dir(&full).map_err(|error| io_error(&error))
            }
            Some(FsEntry::File(_)) => Err(FsError::Changed),
            None => Err(FsError::NotFound),
        }
    }

    fn create_temp_now(&self) -> Result<TempId, FsError> {
        let dir = self.root.join(ENGINE_DIR).join(TEMP_DIR);
        std::fs::create_dir_all(&dir).map_err(|error| io_error(&error))?;
        let id = self.next_temp.fetch_add(1, Ordering::Relaxed) + 1;
        let path = dir.join(format!("{id}.part"));
        std::fs::File::create_new(&path).map_err(|error| io_error(&error))?;
        self.temps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, path);
        Ok(TempId(id))
    }

    fn append_temp_now(&self, temp: TempId, data: &[u8]) -> Result<(), FsError> {
        let path = self.temp_path(temp)?;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|error| io_error(&error))?;
        file.write_all(data).map_err(|error| io_error(&error))
    }

    fn commit_temp_now(
        &self,
        temp: TempId,
        target: &RelPath,
        expected: Option<Stat>,
        mtime_ms: i64,
        executable: bool,
    ) -> Result<Stat, FsError> {
        self.allowed(target)?;
        if !self.is_folder(&target.parent().unwrap_or_default()) {
            return Err(FsError::NotFound);
        }
        let full = self.path(target);
        // Checked, then renamed (client foundation B2).
        match (Self::entry(&full)?, expected) {
            (None, None) => {}
            (Some(FsEntry::File(stat)), Some(expected)) if stat.same_version(&expected) => {}
            (Some(_), None) => return Err(FsError::AlreadyExists),
            _ => return Err(FsError::Changed),
        }
        let source = self.temp_path(temp)?;
        {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&source)
                .map_err(|error| io_error(&error))?;
            file.set_modified(system_time(mtime_ms))
                .and_then(|()| set_executable(&file, executable))
                .and_then(|()| file.sync_all())
                .map_err(|error| io_error(&error))?;
        }
        std::fs::rename(&source, &full).map_err(|error| io_error(&error))?;
        self.temps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&temp.0);
        sync_dir(full.parent().unwrap_or(&self.root)).map_err(|error| io_error(&error))?;
        match Self::entry(&full)? {
            Some(FsEntry::File(stat)) => Ok(stat),
            _ => Err(FsError::Changed),
        }
    }

    fn discard_temp_now(&self, temp: TempId) -> Result<(), FsError> {
        let path = self
            .temps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&temp.0);
        match path.map(std::fs::remove_file) {
            Some(Err(error)) if error.kind() != io::ErrorKind::NotFound => Err(io_error(&error)),
            _ => Ok(()),
        }
    }
}

/// What identifies an entry across names: its file ID, and whether it is a folder.
fn file_identity(entry: &FsEntry) -> (u64, bool) {
    match entry {
        FsEntry::File(stat) => (stat.file_id, false),
        FsEntry::Folder { file_id } => (*file_id, true),
    }
}

/// Whether the file system at `dir` ignores case: a file created as `CaseProbe` is found as
/// `caseprobe`.
fn probe_case(dir: &Path) -> io::Result<bool> {
    let upper = dir.join("CaseProbe");
    let lower = dir.join("caseprobe");
    std::fs::File::create(&upper)?;
    let insensitive = std::fs::symlink_metadata(&lower).is_ok();
    std::fs::remove_file(&upper)?;
    Ok(insensitive)
}

impl FileSystem for OsFs {
    fn rules(&self) -> FsRules {
        self.rules
    }

    fn list(&self, dir: &RelPath) -> impl Future<Output = Result<DirList, FsError>> + Send {
        std::future::ready(self.list_now(dir))
    }

    fn stat(
        &self,
        path: &RelPath,
    ) -> impl Future<Output = Result<Option<FsEntry>, FsError>> + Send {
        std::future::ready(Self::entry(&self.path(path)))
    }

    fn read(
        &self,
        path: &RelPath,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<Vec<u8>, FsError>> + Send {
        std::future::ready(self.read_now(path, offset, len))
    }

    fn create_dir(&self, path: &RelPath) -> impl Future<Output = Result<u64, FsError>> + Send {
        std::future::ready(self.create_dir_now(path))
    }

    fn rename(
        &self,
        from: &RelPath,
        to: &RelPath,
    ) -> impl Future<Output = Result<(), FsError>> + Send {
        std::future::ready(self.rename_now(from, to))
    }

    fn remove_file(
        &self,
        path: &RelPath,
        expected: Stat,
    ) -> impl Future<Output = Result<(), FsError>> + Send {
        std::future::ready(self.remove_file_now(path, expected))
    }

    fn remove_dir(&self, path: &RelPath) -> impl Future<Output = Result<(), FsError>> + Send {
        std::future::ready(self.remove_dir_now(path))
    }

    fn create_temp(&self) -> impl Future<Output = Result<TempId, FsError>> + Send {
        std::future::ready(self.create_temp_now())
    }

    fn append_temp(
        &self,
        temp: TempId,
        data: &[u8],
    ) -> impl Future<Output = Result<(), FsError>> + Send {
        std::future::ready(self.append_temp_now(temp, data))
    }

    fn commit_temp(
        &self,
        temp: TempId,
        target: &RelPath,
        expected: Option<Stat>,
        mtime_ms: i64,
        executable: bool,
    ) -> impl Future<Output = Result<Stat, FsError>> + Send {
        std::future::ready(self.commit_temp_now(temp, target, expected, mtime_ms, executable))
    }

    fn discard_temp(&self, temp: TempId) -> impl Future<Output = Result<(), FsError>> + Send {
        std::future::ready(self.discard_temp_now(temp))
    }
}
