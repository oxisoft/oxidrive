//! [`OsFs`] on real temporary folders: the file system conformance suite, and what only a
//! real disk has (symlinks, names that aren't UTF-8, leftovers of an earlier run).

#![cfg(test)]

use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use oxisoft_drive_client::OsFs;
use oxisoft_drive_core::{FileSystem, FsError, RelPath};
use oxisoft_drive_testkit::block_on;
use oxisoft_drive_testkit::fs_conformance::Folder;

/// A real folder and [`OsFs`] on it.
struct DiskFolder {
    root: PathBuf,
    fs: OsFs,
}

impl DiskFolder {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            fs: OsFs::open(root).unwrap(),
        }
    }

    fn full(&self, at: &str) -> PathBuf {
        at.split('/')
            .fold(self.root.clone(), |full, part| full.join(part))
    }
}

impl Folder for DiskFolder {
    type Fs = OsFs;

    fn fs(&self) -> &OsFs {
        &self.fs
    }

    fn write(&self, at: &str, bytes: &[u8]) {
        let full = self.full(at);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, bytes).unwrap();
    }

    fn mkdir(&self, at: &str) {
        std::fs::create_dir_all(self.full(at)).unwrap();
    }

    fn set_mtime(&self, at: &str, mtime_ms: i64) {
        let time = UNIX_EPOCH + Duration::from_millis(u64::try_from(mtime_ms).unwrap());
        std::fs::File::options()
            .write(true)
            .open(self.full(at))
            .unwrap()
            .set_modified(time)
            .unwrap();
    }

    fn keeps_executable(&self) -> bool {
        cfg!(unix)
    }

    fn has_change_time(&self) -> bool {
        cfg!(unix)
    }
}

fn fresh() -> (DiskFolder, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    (DiskFolder::new(dir.path()), dir)
}

oxisoft_drive_testkit::fs_conformance_tests!(fresh());

fn path(text: &str) -> RelPath {
    RelPath::parse(text).unwrap()
}

#[test]
fn the_name_rules_are_probed() {
    let (folder, _dir) = fresh();
    let rules = folder.fs.rules();
    // The CI systems' default file systems: case-sensitive on Linux, insensitive on macOS
    // (APFS) and Windows (NTFS).
    assert_eq!(rules.case_insensitive, !cfg!(target_os = "linux"));
    assert_eq!(rules.windows_names, !cfg!(target_os = "linux"));
    assert_eq!(folder.fs.root(), folder.root);
}

#[test]
fn opening_needs_a_folder_and_clears_old_temporary_files() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        OsFs::open(&dir.path().join("missing")).err(),
        Some(FsError::NotFound)
    );
    let file = dir.path().join("file");
    std::fs::write(&file, b"x").unwrap();
    assert!(matches!(OsFs::open(&file), Err(FsError::Io(_))));
    let leftover = dir.path().join(".oxidrive").join("tmp").join("7.part");
    let fs = OsFs::open(dir.path()).unwrap();
    let temp = block_on(fs.create_temp()).unwrap();
    block_on(fs.append_temp(temp, b"half")).unwrap();
    std::fs::write(&leftover, b"from a crash").unwrap();
    drop(fs);
    OsFs::open(dir.path()).unwrap();
    let left: Vec<_> = std::fs::read_dir(dir.path().join(".oxidrive").join("tmp"))
        .unwrap()
        .collect();
    assert!(left.is_empty());
}

#[cfg(unix)]
#[test]
fn symlinks_are_neither_listed_nor_followed() {
    let (folder, _dir) = fresh();
    folder.write("target.txt", b"t");
    folder.mkdir("target-dir");
    std::os::unix::fs::symlink(folder.full("target.txt"), folder.full("link")).unwrap();
    std::os::unix::fs::symlink(folder.full("target-dir"), folder.full("dir-link")).unwrap();
    let list = block_on(folder.fs.list(&RelPath::root())).unwrap();
    let names: Vec<&str> = list.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, [".oxidrive", "target-dir", "target.txt"]);
    assert_eq!(block_on(folder.fs.stat(&path("link"))).unwrap(), None);
    assert_eq!(
        block_on(folder.fs.read(&path("link"), 0, 10)),
        Err(FsError::NotFound)
    );
    assert_eq!(
        block_on(folder.fs.list(&path("dir-link"))).map(|list| list.entries.len()),
        Ok(0)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn names_that_cant_be_synced_are_reported() {
    use std::os::unix::ffi::OsStrExt;
    let (folder, _dir) = fresh();
    let invalid = std::ffi::OsStr::from_bytes(b"bad\xffname");
    std::fs::write(folder.root.join(invalid), b"x").unwrap();
    // "é" decomposed: Linux keeps it apart from the composed name we would sync.
    std::fs::write(folder.root.join("cafe\u{301}"), b"y").unwrap();
    std::fs::write(folder.root.join("fine"), b"z").unwrap();
    let list = block_on(folder.fs.list(&RelPath::root())).unwrap();
    let names: Vec<&str> = list.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, [".oxidrive", "fine"]);
    let mut unrepresentable = list.unrepresentable.clone();
    unrepresentable.sort();
    assert_eq!(unrepresentable, ["bad\u{fffd}name", "cafe\u{301}"]);
}

#[cfg(target_os = "macos")]
#[test]
fn decomposed_names_are_found_again_on_macos() {
    let (folder, _dir) = fresh();
    std::fs::write(folder.root.join("cafe\u{301}"), b"y").unwrap();
    let list = block_on(folder.fs.list(&RelPath::root())).unwrap();
    let name = list
        .entries
        .iter()
        .find(|entry| entry.name.as_str() != ".oxidrive")
        .unwrap()
        .name
        .clone();
    assert_eq!(name.as_str(), "caf\u{e9}");
    let found = RelPath::root().join(name);
    assert_eq!(block_on(folder.fs.read(&found, 0, 10)).unwrap(), b"y");
}

#[cfg(unix)]
#[test]
fn the_executable_bit_follows_the_read_bits() {
    use std::os::unix::fs::PermissionsExt;
    let (folder, _dir) = fresh();
    let temp = block_on(folder.fs.create_temp()).unwrap();
    let stat = block_on(folder.fs.commit_temp(temp, &path("run.sh"), None, 0, true)).unwrap();
    assert!(stat.executable);
    let mode = std::fs::metadata(folder.full("run.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, (mode & 0o444) >> 2);
}

#[test]
fn times_before_1970_survive() {
    let (folder, _dir) = fresh();
    let temp = block_on(folder.fs.create_temp()).unwrap();
    let stat = block_on(
        folder
            .fs
            .commit_temp(temp, &path("old"), None, -86_400_000, false),
    )
    .unwrap();
    assert_eq!(stat.mtime_ms, -86_400_000);
}
