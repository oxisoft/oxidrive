//! The three trees the reconciler compares (core engine §2).

use std::collections::{BTreeMap, BTreeSet};

use oxisoft_drive_proto::{ContentHash, Name, NodeId, Version};

use crate::path::RelPath;

/// What a file looked like on disk, cheap to read without opening it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// Size in bytes.
    pub size: u64,
    /// Modification time, milliseconds since the Unix epoch.
    pub mtime_ms: i64,
    /// Inode (Unix) or file index (Windows): survives renames, so it detects them.
    pub file_id: u64,
    /// The Unix executable bit.
    pub executable: bool,
    /// Change time (ctime on Unix and macOS, `ChangeTime` on Windows) as an opaque stamp.
    /// Every write changes it and no tool can set it, so an edit that keeps size and
    /// modification time (coarse clocks, tools setting times) is still seen. 0 where a file
    /// system has none.
    pub change: u64,
}

impl Stat {
    /// Whether two stats show the same version of a file's content (the executable bit and
    /// the file ID aside).
    #[must_use]
    pub const fn same_version(&self, other: &Self) -> bool {
        self.size == other.size && self.mtime_ms == other.mtime_ms && self.change == other.change
    }
}

/// One entry found by scanning the local folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalEntry {
    /// A file.
    File {
        /// Its stat.
        stat: Stat,
        /// Its content hash. The scanner fills this in for every file whose stat differs
        /// from the base (and every new file), so the reconciler can tell a real conflict
        /// from both sides reaching the same content. `None` for files whose stat matches.
        content: Option<ContentHash>,
    },
    /// A folder.
    Folder {
        /// Its file ID, to detect folder renames.
        file_id: u64,
    },
}

/// The local folder as scanned now, without ignored or skipped entries.
pub type LocalTree = BTreeMap<RelPath, LocalEntry>;

/// What a node is on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteKind {
    /// A file.
    File {
        /// Its content hash.
        content: ContentHash,
        /// Its size.
        size: u64,
    },
    /// A folder.
    Folder,
    /// Deleted (a tombstone).
    Deleted,
}

/// One node of the collection as committed on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteNode {
    /// Containing folder, `None` for the collection root.
    pub parent: Option<NodeId>,
    /// Name inside the parent.
    pub name: Name,
    /// What it is now.
    pub kind: RemoteKind,
    /// Current version.
    pub version: Version,
}

/// The collection as replayed from verified commits.
pub type RemoteTree = BTreeMap<NodeId, RemoteNode>;

/// What this device last synced for one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseEntry {
    /// Where it was.
    pub path: RelPath,
    /// What it was.
    pub kind: BaseKind,
    /// The remote version it matched.
    pub version: Version,
}

/// The kind of a synced node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseKind {
    /// A file, with the stat it had on disk and its content hash.
    File {
        /// Stat after the last sync.
        stat: Stat,
        /// Content hash after the last sync.
        content: ContentHash,
    },
    /// A folder, with its file ID.
    Folder {
        /// File ID after the last sync.
        file_id: u64,
    },
}

/// The last synced state, per node.
pub type Base = BTreeMap<NodeId, BaseEntry>;

/// Why a remote tree can't be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeError {
    /// A node's parent chain loops.
    Cycle(NodeId),
    /// A node's parent doesn't exist.
    MissingParent(NodeId),
    /// A synced node changed between file and folder; writers never do that (a kind
    /// change is a delete plus a new node).
    KindChanged(NodeId),
}

/// The path of every node of a remote tree, including deleted ones (tombstones keep their
/// last parent and name).
///
/// # Errors
///
/// [`TreeError`] for a parent chain that loops or ends at an unknown node. Correct writers
/// never produce either (sync protocol §5), so the engine pauses rather than guessing.
pub fn remote_paths(tree: &RemoteTree) -> Result<BTreeMap<NodeId, RelPath>, TreeError> {
    let mut paths = BTreeMap::new();
    for &node in tree.keys() {
        let mut names = Vec::new();
        let mut seen = BTreeSet::new();
        let mut current = Some(node);
        while let Some(id) = current {
            if !seen.insert(id) {
                return Err(TreeError::Cycle(node));
            }
            let entry = tree.get(&id).ok_or(TreeError::MissingParent(node))?;
            names.push(entry.name.clone());
            current = entry.parent;
        }
        let mut path = RelPath::root();
        for name in names.into_iter().rev() {
            path = path.join(name);
        }
        paths.insert(node, path);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxisoft_drive_proto::DeviceId;

    fn version() -> Version {
        Version {
            device: DeviceId::from_bytes([1; 16]),
            counter: 1,
        }
    }

    fn node(parent: Option<u8>, name: &str) -> RemoteNode {
        RemoteNode {
            parent: parent.map(|p| NodeId::from_bytes([p; 16])),
            name: Name::new(name).unwrap(),
            kind: RemoteKind::Folder,
            version: version(),
        }
    }

    #[test]
    fn paths_follow_parents() {
        let tree: RemoteTree = [
            (NodeId::from_bytes([1; 16]), node(None, "a")),
            (NodeId::from_bytes([2; 16]), node(Some(1), "b")),
            (NodeId::from_bytes([3; 16]), node(Some(2), "c")),
        ]
        .into();
        let paths = remote_paths(&tree).unwrap();
        assert_eq!(
            paths[&NodeId::from_bytes([3; 16])],
            RelPath::parse("a/b/c").unwrap()
        );
    }

    #[test]
    fn cycles_and_missing_parents_are_errors() {
        let cycle: RemoteTree = [
            (NodeId::from_bytes([1; 16]), node(Some(2), "a")),
            (NodeId::from_bytes([2; 16]), node(Some(1), "b")),
        ]
        .into();
        assert!(matches!(remote_paths(&cycle), Err(TreeError::Cycle(_))));
        let orphan: RemoteTree = [(NodeId::from_bytes([1; 16]), node(Some(9), "a"))].into();
        assert_eq!(
            remote_paths(&orphan),
            Err(TreeError::MissingParent(NodeId::from_bytes([1; 16])))
        );
    }
}
