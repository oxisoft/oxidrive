//! What the reconciler decides: steps plus reports for the apps.
//!
//! Steps name **nodes**, not paths, wherever a node exists. The executor resolves where a
//! node is right now from its index, which it updates after every step, and places nodes
//! under their remote parent node with their remote name. So a folder moving earlier in the
//! same plan never invalidates later steps for its contents. Only new local entries, which
//! have no node yet, are named by path (as scanned).

use std::collections::BTreeMap;

use oxisoft_drive_proto::{Name, NodeId};

use crate::model::TreeError;
use crate::path::RelPath;

/// One thing the executor must do. Every step re-checks its preconditions before acting
/// (core engine §1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Rename a local entry in place to a conflict name, so a remote entry can take its
    /// name. What was set aside is uploaded by a later step (`UploadNew`, or `UploadChange`
    /// when it is a synced node).
    SetAside {
        /// The entry's path as scanned.
        from: RelPath,
        /// The conflict name.
        to: Name,
    },
    /// Create a remote folder locally, under its remote parent with its remote name.
    CreateLocalFolder {
        /// The folder.
        node: NodeId,
    },
    /// Move a node locally to its remote parent and name.
    MoveLocal {
        /// The node.
        node: NodeId,
    },
    /// Write a file's remote content: in place if the node exists locally, otherwise under
    /// its remote parent with its remote name.
    Download {
        /// The file.
        node: NodeId,
    },
    /// Delete a node deleted remotely; only if it still matches the base.
    DeleteLocal {
        /// The node.
        node: NodeId,
    },
    /// Upload a new local file or folder as a new node.
    UploadNew {
        /// Its path as scanned, after any `SetAside` of it or an ancestor. If an earlier
        /// `MoveLocal` moved one of its ancestors, the executor translates the path through
        /// that move.
        path: RelPath,
        /// Whether it is a folder.
        folder: bool,
    },
    /// Upload a new version of a node from where it is locally: its content (files) and its
    /// parent and name.
    UploadChange {
        /// The node.
        node: NodeId,
        /// The node is deleted remotely and comes back (an edit beats a delete).
        resurrect: bool,
    },
    /// Upload the deletion of a node deleted locally.
    UploadDelete {
        /// The node.
        node: NodeId,
    },
    /// Both sides agree; only record the node's current version in the index.
    Adopt {
        /// The node.
        node: NodeId,
    },
    /// A new local entry turned out to be an existing remote node (same folder, or same
    /// file content, at the same place): record it in the index without transferring.
    Bind {
        /// The local entry.
        path: RelPath,
        /// The remote node.
        node: NodeId,
    },
    /// Deleted on both sides; drop it from the index.
    Forget {
        /// The node.
        node: NodeId,
    },
}

/// A conflict resolved by keeping both versions (sync protocol §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The local path that was contested, as scanned.
    pub path: RelPath,
    /// The conflict name the local version got.
    pub renamed_to: Name,
}

/// A remote node this device can't represent (sync protocol §8, decision S2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The node.
    pub node: NodeId,
    /// Its remote path.
    pub path: RelPath,
    /// Why.
    pub reason: SkipReason,
}

/// Why a node is skipped on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Its name differs only in case from a sibling, and this file system ignores case.
    CaseClash,
    /// Its name is not allowed by Windows.
    WindowsName,
    /// An ancestor folder is skipped.
    InSkippedFolder,
}

/// Why nothing was planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pause {
    /// The folder marker is missing: the folder may be unmounted or moved (sync §10).
    MarkerMissing,
    /// The plan would delete more than the brake allows; the user must confirm.
    MassDelete {
        /// How many files would be deleted remotely.
        deletions: usize,
    },
    /// The remote tree is malformed.
    CorruptTree(TreeError),
}

/// The reconciler's result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Steps, in execution order.
    pub steps: Vec<Step>,
    /// Conflicts resolved by keeping both.
    pub conflicts: Vec<Conflict>,
    /// Remote nodes skipped on this device.
    pub skipped: Vec<Skipped>,
    /// Set when nothing may be done until the user acts.
    pub paused: Option<Pause>,
    /// Where each synced node was found locally when planning; the executor's starting
    /// point for resolving nodes to paths.
    pub located: BTreeMap<NodeId, RelPath>,
}

impl Plan {
    pub(crate) fn paused(pause: Pause) -> Self {
        Self {
            paused: Some(pause),
            ..Self::default()
        }
    }
}
