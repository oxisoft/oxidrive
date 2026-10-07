//! The tests every [`FileSystem`] passes (client foundation §5): the in-memory one here, the
//! real one in the client crate. Where they disagree, one of them is wrong.
//!
//! A [`Folder`] is a file system plus what a user does to it outside the engine (write a
//! file, make a folder, change a time). [`fs_conformance_tests!`](crate::fs_conformance_tests)
//! generates one test per case.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "a test suite: every case panics when the file system misbehaves"
)]

use std::collections::BTreeMap;

use oxisoft_drive_core::{FileSystem, FsEntry, FsError, RelPath, is_engine_path};

use crate::{MemFs, block_on};

/// A file system and what a user does to it.
pub trait Folder {
    /// The file system under test.
    type Fs: FileSystem;

    /// The file system.
    fn fs(&self) -> &Self::Fs;

    /// Writes a file (creating or overwriting it), as a user's program does.
    fn write(&self, path: &str, bytes: &[u8]);

    /// Makes a folder, as a user does.
    fn mkdir(&self, path: &str);

    /// Sets a file's modification time, as `touch -d` does.
    fn set_mtime(&self, path: &str, mtime_ms: i64);

    /// Whether the executable bit is kept (not on Windows).
    fn keeps_executable(&self) -> bool;

    /// Whether files have a change time (not on Windows, client foundation B1).
    fn has_change_time(&self) -> bool;
}

/// Generates one `#[test]` per case, each on a fresh folder made by `$fresh`: an expression
/// giving `(folder, guard)`, where the guard (say, a temporary directory) lives until the
/// test ends.
#[macro_export]
macro_rules! fs_conformance_tests {
    ($fresh:expr) => {
        $crate::fs_conformance_tests!(@cases $fresh;
            listing_and_stat, reading, creating_folders, renaming, removing_files,
            removing_folders, temporary_files, change_time, name_rules);
    };
    (@cases $fresh:expr; $($case:ident),*) => {
        $(
            #[test]
            fn $case() {
                let (folder, _guard) = $fresh;
                $crate::fs_conformance::$case(&folder);
            }
        )*
    };
}

fn path(text: &str) -> RelPath {
    RelPath::parse(text).unwrap()
}

/// A folder's entries by name, without the engine's own folder.
fn listing<F: Folder>(folder: &F, dir: &str) -> BTreeMap<String, FsEntry> {
    let dir = if dir.is_empty() {
        RelPath::root()
    } else {
        path(dir)
    };
    let list = block_on(folder.fs().list(&dir)).unwrap();
    list.entries
        .into_iter()
        .filter(|entry| !is_engine_path(&dir.join(entry.name.clone())))
        .map(|entry| (entry.name.to_string(), entry.entry))
        .collect()
}

fn stat<F: Folder>(folder: &F, at: &str) -> Option<FsEntry> {
    block_on(folder.fs().stat(&path(at))).unwrap()
}

fn file_stat<F: Folder>(folder: &F, at: &str) -> oxisoft_drive_core::Stat {
    match stat(folder, at) {
        Some(FsEntry::File(stat)) => stat,
        other => panic!("{at}: expected a file, got {other:?}"),
    }
}

fn read_all<F: Folder>(folder: &F, at: &str) -> Vec<u8> {
    block_on(folder.fs().read(&path(at), 0, 1 << 20)).unwrap()
}

/// Lists, stats, and what's missing.
pub fn listing_and_stat<F: Folder>(folder: &F) {
    folder.mkdir("docs");
    folder.write("docs/a.txt", b"hello");
    folder.write("b.bin", &[7; 3000]);
    let root = listing(folder, "");
    assert_eq!(root.keys().collect::<Vec<_>>(), ["b.bin", "docs"]);
    assert!(matches!(root["docs"], FsEntry::Folder { .. }));
    match root["b.bin"] {
        FsEntry::File(stat) => {
            assert_eq!(stat.size, 3000);
            assert!(!stat.executable);
        }
        FsEntry::Folder { .. } => panic!("b.bin is a file"),
    }
    let docs = listing(folder, "docs");
    assert_eq!(docs.keys().collect::<Vec<_>>(), ["a.txt"]);
    assert_eq!(file_stat(folder, "docs/a.txt").size, 5);
    assert_eq!(stat(folder, "nothing"), None);
    assert_eq!(stat(folder, "docs/nothing/deeper"), None);
    assert_eq!(
        block_on(folder.fs().list(&path("nothing"))),
        Err(FsError::NotFound)
    );
    // The file IDs of different entries differ.
    let (FsEntry::Folder { file_id: dir_id }, FsEntry::File(file)) = (root["docs"], root["b.bin"])
    else {
        panic!("kinds")
    };
    assert_ne!(dir_id, file.file_id);
}

/// Reads from offsets, short at the end.
pub fn reading<F: Folder>(folder: &F) {
    folder.write("ten", b"0123456789");
    let fs = folder.fs();
    assert_eq!(block_on(fs.read(&path("ten"), 0, 4)).unwrap(), b"0123");
    assert_eq!(block_on(fs.read(&path("ten"), 8, 10)).unwrap(), b"89");
    assert!(block_on(fs.read(&path("ten"), 20, 5)).unwrap().is_empty());
    assert_eq!(
        block_on(fs.read(&path("missing"), 0, 1)),
        Err(FsError::NotFound)
    );
    folder.mkdir("dir");
    assert_eq!(
        block_on(fs.read(&path("dir"), 0, 1)),
        Err(FsError::NotFound)
    );
}

/// Folders are made once, inside existing folders.
pub fn creating_folders<F: Folder>(folder: &F) {
    let fs = folder.fs();
    let id = block_on(fs.create_dir(&path("new"))).unwrap();
    assert_eq!(stat(folder, "new"), Some(FsEntry::Folder { file_id: id }));
    assert_eq!(
        block_on(fs.create_dir(&path("new"))),
        Err(FsError::AlreadyExists)
    );
    folder.write("file", b"x");
    assert_eq!(
        block_on(fs.create_dir(&path("file"))),
        Err(FsError::AlreadyExists)
    );
    assert_eq!(
        block_on(fs.create_dir(&path("missing/inner"))),
        Err(FsError::NotFound)
    );
    block_on(fs.create_dir(&path("new/inner"))).unwrap();
}

/// Renames keep file IDs; they never replace, and never move a folder into itself.
pub fn renaming<F: Folder>(folder: &F) {
    let fs = folder.fs();
    folder.write("a.txt", b"a");
    folder.write("taken", b"t");
    folder.mkdir("dir/sub");
    folder.write("dir/sub/inside", b"i");
    let id = file_stat(folder, "a.txt").file_id;
    block_on(fs.rename(&path("a.txt"), &path("dir/moved.txt"))).unwrap();
    assert_eq!(stat(folder, "a.txt"), None);
    assert_eq!(file_stat(folder, "dir/moved.txt").file_id, id);
    assert_eq!(read_all(folder, "dir/moved.txt"), b"a");
    assert_eq!(
        block_on(fs.rename(&path("dir/moved.txt"), &path("taken"))),
        Err(FsError::AlreadyExists)
    );
    assert_eq!(read_all(folder, "taken"), b"t");
    assert_eq!(
        block_on(fs.rename(&path("gone"), &path("there"))),
        Err(FsError::NotFound)
    );
    assert_eq!(
        block_on(fs.rename(&path("taken"), &path("missing/there"))),
        Err(FsError::NotFound)
    );
    assert!(matches!(
        block_on(fs.rename(&path("dir"), &path("dir/sub/dir"))),
        Err(FsError::Io(_))
    ));
    // A folder moves with everything inside.
    let Some(FsEntry::Folder { file_id: dir_id }) = stat(folder, "dir") else {
        panic!("dir is a folder")
    };
    block_on(fs.rename(&path("dir"), &path("renamed"))).unwrap();
    assert_eq!(
        stat(folder, "renamed"),
        Some(FsEntry::Folder { file_id: dir_id })
    );
    assert_eq!(read_all(folder, "renamed/sub/inside"), b"i");
    // Another case of the same name is a rename on every file system.
    block_on(fs.rename(&path("taken"), &path("Taken"))).unwrap();
    assert_eq!(
        listing(folder, "")
            .keys()
            .filter(|name| name.as_str() == "Taken")
            .count(),
        1
    );
}

/// Files are removed only in the version the engine expects.
pub fn removing_files<F: Folder>(folder: &F) {
    let fs = folder.fs();
    folder.write("f", b"one");
    let old = file_stat(folder, "f");
    folder.write("f", b"other content");
    assert_eq!(
        block_on(fs.remove_file(&path("f"), old)),
        Err(FsError::Changed)
    );
    let current = file_stat(folder, "f");
    block_on(fs.remove_file(&path("f"), current)).unwrap();
    assert_eq!(stat(folder, "f"), None);
    assert_eq!(
        block_on(fs.remove_file(&path("f"), current)),
        Err(FsError::NotFound)
    );
    folder.mkdir("f");
    assert_eq!(
        block_on(fs.remove_file(&path("f"), current)),
        Err(FsError::Changed)
    );
}

/// Folders are removed only when empty.
pub fn removing_folders<F: Folder>(folder: &F) {
    let fs = folder.fs();
    folder.mkdir("full");
    folder.write("full/x", b"x");
    assert_eq!(
        block_on(fs.remove_dir(&path("full"))),
        Err(FsError::NotEmpty)
    );
    folder.mkdir("empty");
    block_on(fs.remove_dir(&path("empty"))).unwrap();
    assert_eq!(stat(folder, "empty"), None);
    assert_eq!(
        block_on(fs.remove_dir(&path("empty"))),
        Err(FsError::NotFound)
    );
    assert_eq!(
        block_on(fs.remove_dir(&path("full/x"))),
        Err(FsError::Changed)
    );
}

/// Temporary files: written, then moved into place only over what the engine expects.
pub fn temporary_files<F: Folder>(folder: &F) {
    let fs = folder.fs();
    let temp = block_on(fs.create_temp()).unwrap();
    block_on(fs.append_temp(temp, b"hello ")).unwrap();
    block_on(fs.append_temp(temp, b"world")).unwrap();
    let mtime = 1_700_000_000_123;
    let stat = block_on(fs.commit_temp(temp, &path("new.txt"), None, mtime, true)).unwrap();
    assert_eq!(read_all(folder, "new.txt"), b"hello world");
    assert_eq!(file_stat(folder, "new.txt"), stat);
    assert_eq!((stat.size, stat.mtime_ms), (11, mtime));
    assert_eq!(stat.executable, folder.keeps_executable());
    // Moving one into place doesn't leave it among the folder's entries.
    assert_eq!(listing(folder, "").keys().collect::<Vec<_>>(), ["new.txt"]);

    // Never over something unexpected.
    let again = block_on(fs.create_temp()).unwrap();
    block_on(fs.append_temp(again, b"2")).unwrap();
    assert_eq!(
        block_on(fs.commit_temp(again, &path("new.txt"), None, mtime, false)),
        Err(FsError::AlreadyExists)
    );
    let mut wrong = stat;
    wrong.size += 1;
    assert_eq!(
        block_on(fs.commit_temp(again, &path("new.txt"), Some(wrong), mtime, false)),
        Err(FsError::Changed)
    );
    assert_eq!(
        block_on(fs.commit_temp(again, &path("missing/x"), None, mtime, false)),
        Err(FsError::NotFound)
    );
    // Over the expected version: replaced, with a new file ID.
    let replaced =
        block_on(fs.commit_temp(again, &path("new.txt"), Some(stat), mtime + 1, false)).unwrap();
    assert_eq!(read_all(folder, "new.txt"), b"2");
    assert!(!replaced.executable);
    assert_ne!(replaced.file_id, stat.file_id);

    // Thrown away: gone, and not committable.
    let dropped = block_on(fs.create_temp()).unwrap();
    block_on(fs.discard_temp(dropped)).unwrap();
    assert_eq!(
        block_on(fs.append_temp(dropped, b"x")),
        Err(FsError::NotFound)
    );
    block_on(fs.discard_temp(dropped)).unwrap();
}

/// A rewrite that keeps size and time still moves the change time (core decision M4).
pub fn change_time<F: Folder>(folder: &F) {
    folder.write("f", b"version 1");
    let before = file_stat(folder, "f");
    folder.write("f", b"version 2");
    folder.set_mtime("f", before.mtime_ms);
    let after = file_stat(folder, "f");
    assert_eq!((after.size, after.mtime_ms), (before.size, before.mtime_ms));
    if folder.has_change_time() {
        assert_ne!(after.change, before.change);
        assert!(!after.same_version(&before));
    } else {
        assert_eq!((after.change, before.change), (0, 0));
    }
}

/// Case and Windows names, as the file system's rules say.
pub fn name_rules<F: Folder>(folder: &F) {
    let rules = folder.fs().rules();
    folder.write("Mixed.txt", b"m");
    assert_eq!(stat(folder, "mixed.txt").is_some(), rules.case_insensitive);
    let refused = block_on(folder.fs().create_dir(&path("CON")));
    if rules.windows_names {
        assert!(matches!(refused, Err(FsError::Io(_))), "{refused:?}");
    } else {
        refused.unwrap();
    }
}

/// [`MemFs`] as a [`Folder`].
#[derive(Debug)]
pub struct MemFolder(pub MemFs);

impl Folder for MemFolder {
    type Fs = MemFs;

    fn fs(&self) -> &MemFs {
        &self.0
    }

    fn write(&self, at: &str, bytes: &[u8]) {
        self.0.write(&path(at), bytes);
    }

    fn mkdir(&self, at: &str) {
        self.0.mkdir(&path(at));
    }

    fn set_mtime(&self, at: &str, mtime_ms: i64) {
        self.0.set_mtime(&path(at), mtime_ms);
    }

    fn keeps_executable(&self) -> bool {
        true
    }

    fn has_change_time(&self) -> bool {
        true
    }
}
