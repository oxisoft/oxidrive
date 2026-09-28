//! An in-memory file system.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};

use oxisoft_drive_core::{
    DirEntry, DirList, FileSystem, FsEntry, FsError, FsRules, RelPath, Stat, TempId, windows_allows,
};
use oxisoft_drive_proto::Name;

/// A file system operation, for failure injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsOp {
    /// `list`.
    List,
    /// `stat`.
    Stat,
    /// `read`.
    Read,
    /// `create_dir`.
    CreateDir,
    /// `rename`.
    Rename,
    /// `remove_file`.
    RemoveFile,
    /// `remove_dir`.
    RemoveDir,
    /// `create_temp`.
    CreateTemp,
    /// `append_temp`.
    AppendTemp,
    /// `commit_temp`.
    CommitTemp,
}

#[derive(Debug, Clone)]
enum Data {
    File { bytes: Vec<u8>, stat: Stat },
    Folder { file_id: u64 },
}

#[derive(Debug, Clone)]
struct Node {
    path: RelPath,
    data: Data,
}

#[derive(Debug, Default)]
struct Inner {
    /// Keyed by path, case-folded if the file system ignores case.
    nodes: BTreeMap<String, Node>,
    temps: BTreeMap<u64, Vec<u8>>,
    next_id: u64,
    next_temp: u64,
    clock: i64,
    failures: Vec<(FsOp, FsError)>,
    operations: usize,
    fail_at: Option<(usize, FsError)>,
    act_at: Option<(usize, UserAction)>,
}

/// Something the user does to the folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserAction {
    /// Write a file.
    Write(RelPath, Vec<u8>),
    /// Delete a file or folder.
    Remove(RelPath),
    /// Rename or move a file or folder.
    Move(RelPath, RelPath),
}

/// An in-memory file system (core executor §5).
#[derive(Debug)]
pub struct MemFs {
    rules: FsRules,
    inner: Mutex<Inner>,
}

impl MemFs {
    /// An empty file system with the given name rules.
    #[must_use]
    pub fn new(rules: FsRules) -> Self {
        Self {
            rules,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn key(&self, path: &RelPath) -> String {
        if self.rules.case_insensitive {
            path.fold_case()
        } else {
            path.to_string()
        }
    }

    fn allowed(&self, path: &RelPath) -> Result<(), FsError> {
        let ok = !self.rules.windows_names || path.name().is_none_or(windows_allows);
        if ok {
            Ok(())
        } else {
            Err(FsError::Io(format!("name not allowed: {path}")))
        }
    }

    /// Makes the next call of `op` fail with `error`.
    pub fn fail_next(&self, op: FsOp, error: FsError) {
        self.lock().failures.push((op, error));
    }

    /// Makes the operation `count` operations from now fail with `error` (whatever it is).
    pub fn fail_after(&self, count: usize, error: FsError) {
        let mut inner = self.lock();
        let at = inner.operations + count;
        inner.fail_at = Some((at, error));
    }

    /// Makes the user do `action` right before the operation `count` operations from now: a
    /// race with the engine at an exact point.
    pub fn act_after(&self, count: usize, action: UserAction) {
        let mut inner = self.lock();
        let at = inner.operations + count;
        inner.act_at = Some((at, action));
    }

    /// Does what the user does.
    pub fn act(&self, action: &UserAction) {
        match action {
            UserAction::Write(path, bytes) => self.write(path, bytes),
            UserAction::Remove(path) => self.remove(path),
            UserAction::Move(from, to) => self.move_entry(from, to),
        }
    }

    /// Cancels every injected failure that hasn't fired.
    pub fn cancel_failures(&self) {
        let mut inner = self.lock();
        inner.fail_at = None;
        inner.act_at = None;
        inner.failures.clear();
    }

    /// How many trait operations ran so far (to inject failures at every point).
    #[must_use]
    pub fn operations(&self) -> usize {
        self.lock().operations
    }

    fn begin(&self, op: FsOp) -> Result<MutexGuard<'_, Inner>, FsError> {
        let action = {
            let mut inner = self.lock();
            let due = inner
                .act_at
                .as_ref()
                .is_some_and(|(at, _)| *at == inner.operations);
            if due { inner.act_at.take() } else { None }
        };
        if let Some((_, action)) = action {
            self.act(&action);
        }
        let mut inner = self.lock();
        inner.operations += 1;
        if inner
            .fail_at
            .as_ref()
            .is_some_and(|(at, _)| *at + 1 == inner.operations)
            && let Some((_, error)) = inner.fail_at.take()
        {
            return Err(error);
        }
        if let Some(index) = inner
            .failures
            .iter()
            .position(|(failing, _)| *failing == op)
        {
            let (_, error) = inner.failures.remove(index);
            return Err(error);
        }
        Ok(inner)
    }

    // ── what a user does (no preconditions, no failures) ───────────────────────────

    /// Writes a file, creating missing parent folders; a new file ID if the file is new.
    pub fn write(&self, path: &RelPath, bytes: &[u8]) {
        for ancestor in path.ancestors() {
            self.mkdir(&ancestor);
        }
        let key = self.key(path);
        let mut inner = self.lock();
        inner.clock += 1;
        let mtime_ms = inner.clock;
        let (file_id, executable) =
            if let Some(Data::File { stat, .. }) = inner.nodes.get(&key).map(|node| &node.data) {
                (stat.file_id, stat.executable)
            } else {
                inner.next_id += 1;
                (inner.next_id, false)
            };
        let stat = Stat {
            size: bytes.len() as u64,
            mtime_ms,
            file_id,
            executable,
        };
        inner.nodes.insert(
            key,
            Node {
                path: path.clone(),
                data: Data::File {
                    bytes: bytes.to_vec(),
                    stat,
                },
            },
        );
    }

    /// Creates a folder and its missing parents.
    pub fn mkdir(&self, path: &RelPath) {
        for folder in path.ancestors().into_iter().chain([path.clone()]) {
            let key = self.key(&folder);
            let mut inner = self.lock();
            if !inner.nodes.contains_key(&key) {
                inner.next_id += 1;
                let file_id = inner.next_id;
                inner.nodes.insert(
                    key,
                    Node {
                        path: folder,
                        data: Data::Folder { file_id },
                    },
                );
            }
        }
    }

    /// Deletes a file or folder with everything inside.
    pub fn remove(&self, path: &RelPath) {
        let prefix = self.key(path);
        self.lock()
            .nodes
            .retain(|key, _| key != &prefix && !key.starts_with(&format!("{prefix}/")));
    }

    /// Renames or moves an entry and everything inside, keeping file IDs.
    pub fn move_entry(&self, from: &RelPath, to: &RelPath) {
        let moved = self.take_subtree(from);
        let mut inner = self.lock();
        for mut node in moved {
            node.path = carry(&node.path, from, to);
            let key = if self.rules.case_insensitive {
                node.path.fold_case()
            } else {
                node.path.to_string()
            };
            inner.nodes.insert(key, node);
        }
    }

    /// Sets a file's executable bit.
    pub fn set_executable(&self, path: &RelPath, executable: bool) {
        let key = self.key(path);
        let mut inner = self.lock();
        inner.clock += 1;
        let clock = inner.clock;
        if let Some(Node {
            data: Data::File { stat, .. },
            ..
        }) = inner.nodes.get_mut(&key)
        {
            stat.executable = executable;
            stat.mtime_ms = clock;
        }
    }

    /// Everything except the engine's own folder: path → content (`None` for folders).
    #[must_use]
    pub fn tree(&self) -> BTreeMap<RelPath, Option<Vec<u8>>> {
        self.lock()
            .nodes
            .values()
            .filter(|node| !oxisoft_drive_core::is_engine_path(&node.path))
            .map(|node| {
                let content = match &node.data {
                    Data::File { bytes, .. } => Some(bytes.clone()),
                    Data::Folder { .. } => None,
                };
                (node.path.clone(), content)
            })
            .collect()
    }

    /// The content of a file.
    #[must_use]
    pub fn content(&self, path: &RelPath) -> Option<Vec<u8>> {
        match &self.lock().nodes.get(&self.key(path))?.data {
            Data::File { bytes, .. } => Some(bytes.clone()),
            Data::Folder { .. } => None,
        }
    }

    fn take_subtree(&self, root: &RelPath) -> Vec<Node> {
        let prefix = self.key(root);
        let mut inner = self.lock();
        let keys: Vec<String> = inner
            .nodes
            .keys()
            .filter(|key| *key == &prefix || key.starts_with(&format!("{prefix}/")))
            .cloned()
            .collect();
        keys.iter()
            .filter_map(|key| inner.nodes.remove(key))
            .collect()
    }

    fn entry(node: &Node) -> FsEntry {
        match &node.data {
            Data::File { stat, .. } => FsEntry::File(*stat),
            Data::Folder { file_id } => FsEntry::Folder { file_id: *file_id },
        }
    }

    fn is_folder(&self, inner: &Inner, path: &RelPath) -> bool {
        path.is_root()
            || matches!(
                inner.nodes.get(&self.key(path)).map(|node| &node.data),
                Some(Data::Folder { .. })
            )
    }
}

fn carry(path: &RelPath, from: &RelPath, to: &RelPath) -> RelPath {
    let mut result = to.clone();
    for name in &path.components()[from.components().len()..] {
        result = result.join(name.clone());
    }
    result
}

fn same_version(stat: &Stat, expected: &Stat) -> bool {
    stat.size == expected.size && stat.mtime_ms == expected.mtime_ms
}

impl FileSystem for MemFs {
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
        std::future::ready(self.stat_now(path))
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
        self.lock().temps.remove(&temp.0);
        std::future::ready(Ok(()))
    }
}

impl MemFs {
    fn list_now(&self, dir: &RelPath) -> Result<DirList, FsError> {
        let inner = self.begin(FsOp::List)?;
        if !self.is_folder(&inner, dir) {
            return Err(FsError::NotFound);
        }
        let parent_key = self.key(dir);
        let entries = inner
            .nodes
            .values()
            .filter(|node| {
                node.path
                    .parent()
                    .is_some_and(|parent| self.key(&parent) == parent_key)
            })
            .filter_map(|node| {
                node.path.name().map(|name: &Name| DirEntry {
                    name: name.clone(),
                    entry: Self::entry(node),
                })
            })
            .collect();
        Ok(DirList {
            entries,
            unrepresentable: Vec::new(),
        })
    }

    fn stat_now(&self, path: &RelPath) -> Result<Option<FsEntry>, FsError> {
        let inner = self.begin(FsOp::Stat)?;
        Ok(inner.nodes.get(&self.key(path)).map(Self::entry))
    }

    fn read_now(&self, path: &RelPath, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        let inner = self.begin(FsOp::Read)?;
        match inner.nodes.get(&self.key(path)).map(|node| &node.data) {
            Some(Data::File { bytes, .. }) => {
                let start = usize::try_from(offset)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                let end = start.saturating_add(len).min(bytes.len());
                Ok(bytes[start..end].to_vec())
            }
            _ => Err(FsError::NotFound),
        }
    }

    fn create_dir_now(&self, path: &RelPath) -> Result<u64, FsError> {
        self.allowed(path)?;
        let mut inner = self.begin(FsOp::CreateDir)?;
        let parent = path.parent().unwrap_or_default();
        if !self.is_folder(&inner, &parent) {
            return Err(FsError::NotFound);
        }
        let key = self.key(path);
        if inner.nodes.contains_key(&key) {
            return Err(FsError::AlreadyExists);
        }
        inner.next_id += 1;
        let file_id = inner.next_id;
        inner.nodes.insert(
            key,
            Node {
                path: path.clone(),
                data: Data::Folder { file_id },
            },
        );
        Ok(file_id)
    }

    fn rename_now(&self, from: &RelPath, to: &RelPath) -> Result<(), FsError> {
        self.allowed(to)?;
        {
            let inner = self.begin(FsOp::Rename)?;
            let (from_key, to_key) = (self.key(from), self.key(to));
            if !inner.nodes.contains_key(&from_key) {
                return Err(FsError::NotFound);
            }
            // On a case-insensitive file system, renaming to another case of the same name
            // is allowed.
            if from_key != to_key && inner.nodes.contains_key(&to_key) {
                return Err(FsError::AlreadyExists);
            }
            if !self.is_folder(&inner, &to.parent().unwrap_or_default()) {
                return Err(FsError::NotFound);
            }
            if to_key.starts_with(&format!("{from_key}/")) {
                return Err(FsError::Io("move into itself".into()));
            }
        }
        self.move_entry(from, to);
        Ok(())
    }

    fn remove_file_now(&self, path: &RelPath, expected: Stat) -> Result<(), FsError> {
        let mut inner = self.begin(FsOp::RemoveFile)?;
        let key = self.key(path);
        match inner.nodes.get(&key).map(|node| &node.data) {
            Some(Data::File { stat, .. }) if same_version(stat, &expected) => {
                inner.nodes.remove(&key);
                Ok(())
            }
            Some(Data::File { .. }) => Err(FsError::Changed),
            Some(Data::Folder { .. }) => Err(FsError::Io("not a file".into())),
            None => Err(FsError::NotFound),
        }
    }

    fn remove_dir_now(&self, path: &RelPath) -> Result<(), FsError> {
        let mut inner = self.begin(FsOp::RemoveDir)?;
        let key = self.key(path);
        match inner.nodes.get(&key).map(|node| &node.data) {
            Some(Data::Folder { .. }) => {
                let prefix = format!("{key}/");
                if inner.nodes.keys().any(|other| other.starts_with(&prefix)) {
                    return Err(FsError::NotEmpty);
                }
                inner.nodes.remove(&key);
                Ok(())
            }
            Some(Data::File { .. }) => Err(FsError::Io("not a folder".into())),
            None => Err(FsError::NotFound),
        }
    }

    fn create_temp_now(&self) -> Result<TempId, FsError> {
        let mut inner = self.begin(FsOp::CreateTemp)?;
        inner.next_temp += 1;
        let id = inner.next_temp;
        inner.temps.insert(id, Vec::new());
        Ok(TempId(id))
    }

    fn append_temp_now(&self, temp: TempId, data: &[u8]) -> Result<(), FsError> {
        let mut inner = self.begin(FsOp::AppendTemp)?;
        inner
            .temps
            .get_mut(&temp.0)
            .ok_or(FsError::NotFound)?
            .extend_from_slice(data);
        Ok(())
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
        let mut inner = self.begin(FsOp::CommitTemp)?;
        if !self.is_folder(&inner, &target.parent().unwrap_or_default()) {
            return Err(FsError::NotFound);
        }
        let key = self.key(target);
        match (inner.nodes.get(&key).map(|node| &node.data), expected) {
            (None, None) => {}
            (Some(Data::File { stat, .. }), Some(expected)) if same_version(stat, &expected) => {}
            (Some(_), None) => return Err(FsError::AlreadyExists),
            _ => return Err(FsError::Changed),
        }
        let bytes = inner.temps.remove(&temp.0).ok_or(FsError::NotFound)?;
        inner.next_id += 1;
        let stat = Stat {
            size: bytes.len() as u64,
            mtime_ms,
            // Replacing a file by renaming gives it a new file ID, as on real file systems.
            file_id: inner.next_id,
            executable,
        };
        inner.nodes.insert(
            key,
            Node {
                path: target.clone(),
                data: Data::File { bytes, stat },
            },
        );
        Ok(stat)
    }
}
