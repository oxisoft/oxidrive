//! The reconciler: a pure function from the base, local and remote trees to a plan
//! (core engine §1, §3; sync protocol §5–§10).
//!
//! Phases:
//! 1. filter ignored and unrepresentable entries;
//! 2. locate every synced node locally (folder moves carry their contents along) and
//!    observe how it changed on each side;
//! 3. decide per node, following the table in core engine §3;
//! 4. add new remote nodes and new local entries;
//! 5. resolve name collisions: the remote side keeps the name, the local side is set aside;
//! 6. keep ancestors alive on both sides;
//! 7. apply the mass-delete brake, and order the steps.
//!
//! Placement is compared as (parent, name), not as paths, so a folder moved on either side
//! doesn't make its whole content look moved.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use oxisoft_drive_proto::{ContentHash, Name, NodeId};

use crate::model::{
    Base, BaseEntry, BaseKind, LocalEntry, LocalTree, RemoteKind, RemoteTree, remote_paths,
};
use crate::names::{conflict_name, windows_allows};
use crate::path::RelPath;
use crate::plan::{Conflict, Pause, Plan, SkipReason, Skipped, Step};

/// When a plan deletes too much to proceed without the user (sync protocol §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MassDeleteBrake {
    /// Pause above this many remote file deletions…
    pub max_count: usize,
    /// …or above this share (percent) of the synced files…
    pub max_percent: usize,
    /// …but the share only counts once at least this many files are deleted.
    pub min_count: usize,
}

impl Default for MassDeleteBrake {
    fn default() -> Self {
        Self {
            max_count: 1000,
            max_percent: 20,
            min_count: 10,
        }
    }
}

/// Name rules of the local file system (sync protocol §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsRules {
    /// Names that differ only in case are the same name (macOS, Windows).
    pub case_insensitive: bool,
    /// Names Windows forbids can't be created.
    pub windows_names: bool,
}

/// Everything the reconciler needs besides the three trees.
pub struct Options<'a> {
    /// Whether the folder marker exists; if not, nothing is planned.
    pub marker_present: bool,
    /// The user confirmed deletions beyond the brake.
    pub allow_mass_delete: bool,
    /// The mass-delete brake.
    pub brake: MassDeleteBrake,
    /// Name rules of the local file system.
    pub fs: FsRules,
    /// Inserted into conflict names, e.g. `conflict 2026-09-28 14.30 laptop`.
    pub conflict_tag: &'a str,
    /// Ignore rules: path and whether it is a folder.
    pub is_ignored: &'a dyn Fn(&RelPath, bool) -> bool,
}

impl fmt::Debug for Options<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("marker_present", &self.marker_present)
            .field("allow_mass_delete", &self.allow_mass_delete)
            .field("brake", &self.brake)
            .field("fs", &self.fs)
            .field("conflict_tag", &self.conflict_tag)
            .finish_non_exhaustive()
    }
}

/// Computes the plan that brings the local folder and the collection back in step.
#[must_use]
pub fn reconcile(
    base: &Base,
    local: &LocalTree,
    remote: &RemoteTree,
    options: &Options<'_>,
) -> Plan {
    if !options.marker_present {
        return Plan::paused(Pause::MarkerMissing);
    }
    let paths = match remote_paths(remote) {
        Ok(paths) => paths,
        Err(error) => return Plan::paused(Pause::CorruptTree(error)),
    };
    Planner::new(base, local, remote, paths, options).run()
}

/// The folder something sits in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Parent {
    Root,
    Node(NodeId),
    /// A new local folder, not yet a node.
    New(RelPath),
}

/// Where something sits: its parent and its name (case-folded where names ignore case).
type Placement = (Parent, String);

/// How a file's content changed locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ContentChange {
    #[default]
    Same,
    /// Changed, to this content (`None` if the scanner didn't hash it).
    Changed(Option<ContentHash>),
}

/// How a node changed remotely, if it still exists there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum RemoteChange {
    #[default]
    Unchanged,
    Changed {
        /// It moved or was renamed.
        moved: bool,
        /// Its content differs from the base.
        content_changed: bool,
    },
}

/// How a synced node changed on each side.
#[derive(Debug, Default)]
struct Obs {
    /// Where it is locally, if it still exists.
    local: Option<RelPath>,
    /// It moved or was renamed locally (by itself, not as part of a moved folder).
    local_moved: bool,
    /// How its local content changed.
    local_change: ContentChange,
    /// It exists remotely (live or coming back).
    remote_live: bool,
    /// How it changed remotely.
    remote_change: RemoteChange,
    /// Its remote content, for files.
    remote_content: Option<ContentHash>,
}

impl Obs {
    const fn local_content_changed(&self) -> bool {
        matches!(self.local_change, ContentChange::Changed(_))
    }

    const fn remote_changed(&self) -> bool {
        matches!(self.remote_change, RemoteChange::Changed { .. })
    }

    const fn remote_moved(&self) -> bool {
        matches!(
            self.remote_change,
            RemoteChange::Changed { moved: true, .. }
        )
    }

    const fn remote_content_changed(&self) -> bool {
        matches!(
            self.remote_change,
            RemoteChange::Changed {
                content_changed: true,
                ..
            }
        )
    }
}

/// Something this device will upload, whose final place may collide with a remote one.
#[derive(Debug, Clone)]
enum Claim {
    New {
        path: RelPath,
        folder: bool,
        content: Option<ContentHash>,
    },
    Change {
        node: NodeId,
        path: RelPath,
        resurrect: bool,
        moved: bool,
    },
}

impl Claim {
    const fn path(&self) -> &RelPath {
        match self {
            Self::New { path, .. } | Self::Change { path, .. } => path,
        }
    }

    fn path_mut(&mut self) -> &mut RelPath {
        match self {
            Self::New { path, .. } | Self::Change { path, .. } => path,
        }
    }
}

struct Planner<'a> {
    options: &'a Options<'a>,
    remote: &'a RemoteTree,
    paths: BTreeMap<NodeId, RelPath>,
    base: BTreeMap<NodeId, &'a BaseEntry>,
    base_owner: BTreeMap<RelPath, NodeId>,
    local: LocalTree,
    /// Current local path of every located base node, and of new entries bound to nodes.
    local_owner: BTreeMap<RelPath, NodeId>,
    local_path: BTreeMap<NodeId, RelPath>,
    claimed_local: BTreeSet<RelPath>,
    live: BTreeSet<NodeId>,
    resurrect: BTreeSet<NodeId>,
    excluded: BTreeSet<NodeId>,
    skipped: Vec<Skipped>,
    remote_owned: BTreeMap<Placement, NodeId>,
    set_asides: Vec<Step>,
    local_steps: Vec<Step>,
    claims: Vec<Claim>,
    deletes: Vec<NodeId>,
    finals: Vec<Step>,
    conflicts: Vec<Conflict>,
}

impl<'a> Planner<'a> {
    fn new(
        base: &'a Base,
        local: &LocalTree,
        remote: &'a RemoteTree,
        paths: BTreeMap<NodeId, RelPath>,
        options: &'a Options<'a>,
    ) -> Self {
        let mut planner = Self {
            options,
            remote,
            paths,
            base: base.iter().map(|(id, entry)| (*id, entry)).collect(),
            base_owner: BTreeMap::new(),
            local: LocalTree::new(),
            local_owner: BTreeMap::new(),
            local_path: BTreeMap::new(),
            claimed_local: BTreeSet::new(),
            live: BTreeSet::new(),
            resurrect: BTreeSet::new(),
            excluded: BTreeSet::new(),
            skipped: Vec::new(),
            remote_owned: BTreeMap::new(),
            set_asides: Vec::new(),
            local_steps: Vec::new(),
            claims: Vec::new(),
            deletes: Vec::new(),
            finals: Vec::new(),
            conflicts: Vec::new(),
        };
        planner.local = planner.filter_local(local);
        planner
    }

    /// A synced node whose remote kind (file or folder) differs from the base.
    fn kind_changed(&self) -> Option<NodeId> {
        self.base.iter().find_map(|(node, entry)| {
            let remote = self.remote.get(node)?;
            let changed = matches!(
                (&entry.kind, &remote.kind),
                (BaseKind::File { .. }, RemoteKind::Folder)
                    | (BaseKind::Folder { .. }, RemoteKind::File { .. })
            );
            changed.then_some(*node)
        })
    }

    fn run(mut self) -> Plan {
        if let Some(node) = self.kind_changed() {
            return Plan::paused(Pause::CorruptTree(crate::model::TreeError::KindChanged(
                node,
            )));
        }
        self.find_live();
        self.find_excluded();
        let excluded = self.excluded.clone();
        self.base.retain(|id, _| !excluded.contains(id));
        self.base_owner = self
            .base
            .iter()
            .map(|(id, entry)| (entry.path.clone(), *id))
            .collect();
        self.locate_all();
        for &node in &self.live {
            if !self.excluded.contains(&node) {
                let placement = self.remote_placement(node);
                self.remote_owned.insert(placement, node);
            }
        }
        let nodes: Vec<(NodeId, &BaseEntry)> = self.base.iter().map(|(n, e)| (*n, *e)).collect();
        for (node, entry) in nodes {
            let obs = self.observe(node, entry);
            self.decide(node, &obs);
        }
        self.new_remote_nodes();
        self.new_local_entries();
        self.keep_local_ancestors();
        self.keep_remote_ancestors();
        self.drop_cyclic_moves();
        self.resolve_collisions();
        self.finish()
    }

    fn key(&self, name: &Name) -> String {
        if self.options.fs.case_insensitive {
            name.fold_case()
        } else {
            name.as_str().to_owned()
        }
    }

    // ── phase 1: filtering ─────────────────────────────────────────────────────────

    fn filter_local(&self, local: &LocalTree) -> LocalTree {
        let mut ignored_folders: Vec<&RelPath> = Vec::new();
        let mut kept = LocalTree::new();
        for (path, entry) in local {
            if path.is_root()
                || ignored_folders
                    .iter()
                    .any(|folder| path.starts_with(folder))
            {
                continue;
            }
            let folder = matches!(entry, LocalEntry::Folder { .. });
            if (self.options.is_ignored)(path, folder) {
                if folder {
                    ignored_folders.push(path);
                }
                continue;
            }
            kept.insert(path.clone(), entry.clone());
        }
        kept
    }

    /// Live nodes, plus deleted folders that still have live descendants: they must come
    /// back (an edit beats a delete).
    fn find_live(&mut self) {
        for (id, node) in self.remote {
            if node.kind != RemoteKind::Deleted {
                self.live.insert(*id);
            }
        }
        for id in self.live.clone() {
            let mut parent = self.remote.get(&id).and_then(|node| node.parent);
            while let Some(ancestor) = parent {
                if !self.live.contains(&ancestor) {
                    self.resurrect.insert(ancestor);
                }
                parent = self.remote.get(&ancestor).and_then(|node| node.parent);
            }
        }
        self.live.extend(self.resurrect.iter().copied());
    }

    fn remote_is_folder(&self, node: NodeId) -> bool {
        self.resurrect.contains(&node)
            || matches!(
                self.remote.get(&node).map(|n| &n.kind),
                Some(RemoteKind::Folder)
            )
    }

    /// Remote nodes this device can't or won't represent: ignored (silently), names Windows
    /// forbids, case clashes, and everything below them.
    fn find_excluded(&mut self) {
        let mut groups: BTreeMap<(Option<NodeId>, String), Vec<NodeId>> = BTreeMap::new();
        let live: Vec<NodeId> = self.live.iter().copied().collect();
        for &id in &live {
            let (Some(node), Some(path)) = (self.remote.get(&id), self.paths.get(&id)) else {
                continue;
            };
            if (self.options.is_ignored)(path, self.remote_is_folder(id)) {
                self.excluded.insert(id);
            } else if self.options.fs.windows_names && !windows_allows(&node.name) {
                self.skip(id, SkipReason::WindowsName);
            } else if self.options.fs.case_insensitive {
                groups
                    .entry((node.parent, node.name.fold_case()))
                    .or_default()
                    .push(id);
            }
        }
        for members in groups.into_values() {
            if members.len() < 2 {
                continue;
            }
            // Keep the one already synced at that path, otherwise the lowest ID.
            let keep = members
                .iter()
                .copied()
                .find(|id| {
                    self.base
                        .get(id)
                        .is_some_and(|entry| Some(&entry.path) == self.paths.get(id))
                })
                .unwrap_or(members[0]);
            for id in members.into_iter().filter(|&id| id != keep) {
                self.skip(id, SkipReason::CaseClash);
            }
        }
        for &id in &live {
            if self.excluded.contains(&id) {
                continue;
            }
            let mut parent = self.remote.get(&id).and_then(|node| node.parent);
            while let Some(ancestor) = parent {
                if self.excluded.contains(&ancestor) {
                    if self.skipped.iter().any(|skip| skip.node == ancestor) {
                        self.skip(id, SkipReason::InSkippedFolder);
                    } else {
                        self.excluded.insert(id);
                    }
                    break;
                }
                parent = self.remote.get(&ancestor).and_then(|node| node.parent);
            }
        }
    }

    fn skip(&mut self, node: NodeId, reason: SkipReason) {
        self.excluded.insert(node);
        if let Some(path) = self.paths.get(&node) {
            self.skipped.push(Skipped {
                node,
                path: path.clone(),
                reason,
            });
        }
    }

    // ── phase 2: locating and observing ────────────────────────────────────────────

    /// Where `path` is now, given local folder moves of it or its ancestors.
    fn carried(path: &RelPath, moves: &[(RelPath, RelPath)]) -> RelPath {
        for (old, new) in moves {
            if path.starts_with(old) {
                let mut result = new.clone();
                for name in &path.components()[old.components().len()..] {
                    result = result.join(name.clone());
                }
                return result;
            }
        }
        path.clone()
    }

    /// Finds every base node locally. File IDs first: an entry whose file ID belongs to a
    /// synced node of the same kind is that node, wherever it now is (moved, renamed, or
    /// taking a name another node left). Nodes not found that way fall back to their old
    /// path, carried along by moved ancestors: editors that save by replacing a file change
    /// its file ID but not its path.
    fn locate_all(&mut self) {
        let mut by_id: BTreeMap<(u64, bool), NodeId> = BTreeMap::new();
        for (node, entry) in &self.base {
            let key = match entry.kind {
                BaseKind::File { stat, .. } => (stat.file_id, false),
                BaseKind::Folder { file_id } => (file_id, true),
            };
            by_id.entry(key).or_insert(*node);
        }
        let found: Vec<(NodeId, RelPath)> = self
            .local
            .iter()
            .filter_map(|(path, entry)| {
                let key = match entry {
                    LocalEntry::File { stat, .. } => (stat.file_id, false),
                    LocalEntry::Folder { file_id } => (*file_id, true),
                };
                by_id.get(&key).map(|node| (*node, path.clone()))
            })
            .collect();
        for (node, path) in found {
            if !self.local_path.contains_key(&node) {
                self.place_local(node, path);
            }
        }
        let moves = self.folder_moves();
        let unresolved: Vec<(NodeId, RelPath, bool)> = self
            .base
            .iter()
            .filter(|(node, _)| !self.local_path.contains_key(node))
            .map(|(node, entry)| {
                let folder = matches!(entry.kind, BaseKind::Folder { .. });
                (*node, Self::carried(&entry.path, &moves), folder)
            })
            .collect();
        for (node, expected, folder) in unresolved {
            let same_kind = self
                .local
                .get(&expected)
                .is_some_and(|entry| matches!(entry, LocalEntry::Folder { .. }) == folder);
            if same_kind && !self.claimed_local.contains(&expected) {
                self.place_local(node, expected);
            }
        }
    }

    /// Where base folders are now, as found by file ID: old path → new path, deepest first.
    fn folder_moves(&self) -> Vec<(RelPath, RelPath)> {
        let mut moves: Vec<(RelPath, RelPath)> = self
            .base
            .iter()
            .filter(|(_, entry)| matches!(entry.kind, BaseKind::Folder { .. }))
            .filter_map(|(node, entry)| {
                let now = self.local_path.get(node)?;
                (*now != entry.path).then(|| (entry.path.clone(), now.clone()))
            })
            .collect();
        moves.sort_by_key(|(old, _)| std::cmp::Reverse(old.components().len()));
        moves
    }

    fn place_local(&mut self, node: NodeId, path: RelPath) {
        self.claimed_local.insert(path.clone());
        self.local_owner.insert(path.clone(), node);
        self.local_path.insert(node, path);
    }

    fn local_parent(&self, path: &RelPath) -> Parent {
        match path.parent() {
            Some(parent) if !parent.is_root() => self
                .local_owner
                .get(&parent)
                .map_or(Parent::New(parent), |id| Parent::Node(*id)),
            _ => Parent::Root,
        }
    }

    fn placement_of_path(&self, path: &RelPath) -> Option<Placement> {
        path.name()
            .map(|name| (self.local_parent(path), self.key(name)))
    }

    /// Placements for detecting moves and renames compare exact names: on a case-insensitive
    /// file system `a` → `A` is still a rename to sync. Collisions use [`Self::key`].
    fn exact<T>(placement: Option<(Parent, T)>, name: Option<&Name>) -> Option<(Parent, String)> {
        placement
            .zip(name)
            .map(|((parent, _), name)| (parent, name.as_str().to_owned()))
    }

    fn base_placement(&self, entry: &BaseEntry) -> Option<Placement> {
        let parent = match entry.path.parent() {
            Some(parent) if !parent.is_root() => self
                .base_owner
                .get(&parent)
                .map_or(Parent::New(parent), |id| Parent::Node(*id)),
            _ => Parent::Root,
        };
        entry.path.name().map(|name| (parent, self.key(name)))
    }

    fn remote_placement(&self, node: NodeId) -> Placement {
        self.remote
            .get(&node)
            .map_or((Parent::Root, String::new()), |remote| {
                let parent = remote.parent.map_or(Parent::Root, Parent::Node);
                (parent, self.key(&remote.name))
            })
    }

    fn observe(&self, node: NodeId, entry: &BaseEntry) -> Obs {
        let base_placement = Self::exact(self.base_placement(entry), entry.path.name());
        let mut obs = Obs::default();
        if let Some(path) = self.local_path.get(&node) {
            obs.local = Some(path.clone());
            obs.local_moved =
                Self::exact(self.placement_of_path(path), path.name()) != base_placement;
            if let (
                BaseKind::File { stat, content },
                Some(LocalEntry::File {
                    stat: now,
                    content: hash,
                }),
            ) = (&entry.kind, self.local.get(path))
            {
                let same_stat = now.size == stat.size && now.mtime_ms == stat.mtime_ms;
                if !same_stat && *hash != Some(*content) {
                    obs.local_change = ContentChange::Changed(*hash);
                }
            }
        }
        let remote = self.remote.get(&node);
        obs.remote_live = self.live.contains(&node);
        obs.remote_content = match remote.map(|remote| &remote.kind) {
            Some(RemoteKind::File { content, .. }) if obs.remote_live => Some(*content),
            _ => None,
        };
        let changed = remote
            .is_none_or(|remote| remote.version != entry.version || self.resurrect.contains(&node));
        if changed {
            obs.remote_change = RemoteChange::Changed {
                moved: obs.remote_live
                    && Self::exact(
                        Some(self.remote_placement(node)),
                        remote.map(|remote| &remote.name),
                    ) != base_placement,
                content_changed: match (&entry.kind, obs.remote_content) {
                    (BaseKind::File { content, .. }, Some(remote)) => remote != *content,
                    _ => false,
                },
            };
        }
        obs
    }

    // ── phase 3: decisions ─────────────────────────────────────────────────────────

    fn unregister(&mut self, node: NodeId) {
        self.remote_owned.retain(|_, owner| *owner != node);
    }

    fn change(&mut self, node: NodeId, path: &RelPath, resurrect: bool, moved: bool) {
        if moved {
            self.unregister(node);
        }
        self.claims.push(Claim::Change {
            node,
            path: path.clone(),
            resurrect,
            moved,
        });
    }

    fn decide(&mut self, node: NodeId, obs: &Obs) {
        if self.resurrect.contains(&node) {
            if let Some(path) = &obs.local {
                self.change(node, path, true, obs.local_moved);
            } else {
                self.local_steps.push(Step::CreateLocalFolder { node });
                self.claims.push(Claim::Change {
                    node,
                    path: self.paths.get(&node).cloned().unwrap_or_default(),
                    resurrect: true,
                    moved: false,
                });
            }
            return;
        }
        let local_changed = obs.local_content_changed() || obs.local_moved;
        match (&obs.local, obs.remote_live) {
            (None, false) => self.finals.push(Step::Forget { node }),
            (None, true) => {
                if obs.remote_content_changed() {
                    // An edit beats a delete: restore it.
                    self.local_steps.push(Step::Download { node });
                } else {
                    // The deleter saw this content; a rename alone isn't an edit.
                    self.unregister(node);
                    self.deletes.push(node);
                }
            }
            (Some(path), false) => {
                if local_changed {
                    self.change(node, path, true, true);
                } else {
                    self.local_steps.push(Step::DeleteLocal { node });
                }
            }
            (Some(path), true) => match (local_changed, obs.remote_changed()) {
                (false, false) => {}
                (true, false) => self.change(node, path, false, obs.local_moved),
                (false, true) => {
                    if obs.remote_moved() {
                        self.local_steps.push(Step::MoveLocal { node });
                    }
                    if obs.remote_content_changed() {
                        self.local_steps.push(Step::Download { node });
                    } else if !obs.remote_moved() {
                        self.finals.push(Step::Adopt { node });
                    }
                }
                (true, true) => self.decide_both_changed(node, obs, path),
            },
        }
    }

    fn decide_both_changed(&mut self, node: NodeId, obs: &Obs, path: &RelPath) {
        let same_content = matches!(
            obs.local_change,
            ContentChange::Changed(Some(hash)) if Some(hash) == obs.remote_content
        );
        if obs.local_content_changed() && obs.remote_content_changed() && !same_content {
            // Both edited: keep both. The node takes the remote version at its remote place;
            // the local version is set aside and uploaded as a new file.
            let aside = self.set_aside(path);
            self.local_owner.remove(path);
            self.local_path.remove(&node);
            self.claims.push(Claim::New {
                path: aside,
                folder: false,
                content: match obs.local_change {
                    ContentChange::Changed(hash) => hash,
                    ContentChange::Same => None,
                },
            });
            self.local_steps.push(Step::Download { node });
            return;
        }
        if obs.remote_moved() {
            // The remote location wins when both sides moved it.
            self.local_steps.push(Step::MoveLocal { node });
        }
        let upload_move = obs.local_moved && !obs.remote_moved();
        if obs.local_content_changed() {
            if same_content && !upload_move {
                self.finals.push(Step::Adopt { node });
            } else {
                self.change(node, path, false, upload_move);
            }
        } else if obs.remote_content_changed() {
            self.local_steps.push(Step::Download { node });
            if upload_move {
                self.change(node, path, false, true);
            }
        } else if upload_move {
            self.change(node, path, false, true);
        } else if !obs.remote_moved() {
            self.finals.push(Step::Adopt { node });
        }
    }

    // ── phase 4: new entries ───────────────────────────────────────────────────────

    fn new_remote_nodes(&mut self) {
        let new: Vec<NodeId> = self
            .live
            .iter()
            .copied()
            .filter(|id| !self.base.contains_key(id) && !self.excluded.contains(id))
            .collect();
        for node in new {
            if self.remote_is_folder(node) {
                self.local_steps.push(Step::CreateLocalFolder { node });
                if self.resurrect.contains(&node) {
                    self.claims.push(Claim::Change {
                        node,
                        path: self.paths.get(&node).cloned().unwrap_or_default(),
                        resurrect: true,
                        moved: false,
                    });
                }
            } else {
                self.local_steps.push(Step::Download { node });
            }
        }
    }

    fn new_local_entries(&mut self) {
        let new: Vec<Claim> = self
            .local
            .iter()
            .filter(|(path, _)| !self.claimed_local.contains(*path))
            .map(|(path, entry)| match entry {
                LocalEntry::Folder { .. } => Claim::New {
                    path: path.clone(),
                    folder: true,
                    content: None,
                },
                LocalEntry::File { content, .. } => Claim::New {
                    path: path.clone(),
                    folder: false,
                    content: *content,
                },
            })
            .collect();
        self.claims.extend(new);
    }

    // ── phase 5: move cycles and collisions ────────────────────────────────────────

    /// The node a local path's parent folder is, following new local folders up to the
    /// first existing node; `None` for the root.
    fn parent_node_of(&self, path: &RelPath) -> Option<NodeId> {
        let mut current = path.parent()?;
        loop {
            if current.is_root() {
                return None;
            }
            if let Some(node) = self.local_owner.get(&current) {
                return Some(*node);
            }
            current = current.parent()?;
        }
    }

    /// A local folder move that, combined with the remote tree, would put a folder inside
    /// itself is dropped: the remote placement wins (sync protocol §5).
    fn drop_cyclic_moves(&mut self) {
        let mut moved: BTreeMap<NodeId, Option<NodeId>> = BTreeMap::new();
        for claim in &self.claims {
            if let Claim::Change {
                node,
                path,
                moved: true,
                ..
            } = claim
            {
                moved.insert(*node, self.parent_node_of(path));
            }
        }
        let parent_of = |node: NodeId, moved: &BTreeMap<NodeId, Option<NodeId>>| {
            moved
                .get(&node)
                .copied()
                .unwrap_or_else(|| self.remote.get(&node).and_then(|n| n.parent))
        };
        // A move is dropped only when walking up from its new parent returns to the node
        // itself; a cycle among other nodes is broken when their own turn comes.
        let mut dropped = BTreeSet::new();
        for &node in moved.clone().keys() {
            let mut seen = BTreeSet::new();
            let mut current = parent_of(node, &moved);
            while let Some(ancestor) = current {
                if ancestor == node {
                    dropped.insert(node);
                    moved.remove(&node);
                    break;
                }
                if !seen.insert(ancestor) {
                    break;
                }
                current = parent_of(ancestor, &moved);
            }
        }
        if dropped.is_empty() {
            return;
        }
        // The node goes to its remote place; any content change is still uploaded.
        for claim in &mut self.claims {
            if let Claim::Change { node, moved, .. } = claim
                && dropped.contains(node)
            {
                *moved = false;
            }
        }
        for node in dropped {
            let placement = self.remote_placement(node);
            self.remote_owned.insert(placement, node);
            self.local_steps.push(Step::MoveLocal { node });
        }
    }

    fn resolve_collisions(&mut self) {
        self.claims.sort_by(|a, b| {
            (a.path().components().len(), a.path()).cmp(&(b.path().components().len(), b.path()))
        });
        let mut index = 0;
        while index < self.claims.len() {
            let claim = self.claims[index].clone();
            // A node coming back from deletion isn't registered remotely, so its place must be
            // checked like a move.
            let moving = match &claim {
                Claim::New { .. } => true,
                Claim::Change {
                    moved, resurrect, ..
                } => *moved || *resurrect,
            };
            let Some(placement) = self.placement_of_path(claim.path()).filter(|_| moving) else {
                index += 1;
                continue;
            };
            let owner = self.remote_owned.get(&placement).copied();
            let foreign = match (&claim, owner) {
                (Claim::Change { node, .. }, Some(owner)) => *node != owner,
                (Claim::New { .. }, Some(_)) => true,
                (_, None) => false,
            };
            match owner {
                Some(owner) if foreign && self.merge_new(&claim, owner) => {
                    self.claims.remove(index);
                }
                Some(_) if foreign => {
                    let old = claim.path().clone();
                    let aside = self.set_aside(&old);
                    for other in &mut self.claims {
                        let path = other.path_mut();
                        if path.starts_with(&old) {
                            *path = Self::carried(path, &[(old.clone(), aside.clone())]);
                        }
                    }
                    index += 1;
                }
                _ => index += 1,
            }
        }
    }

    /// A new local entry meets a new remote node at the same place: two folders merge, and
    /// two files with the same content are the same file. Returns whether it merged.
    fn merge_new(&mut self, claim: &Claim, owner: NodeId) -> bool {
        let Claim::New {
            path,
            folder,
            content,
        } = claim
        else {
            return false;
        };
        if self.base.contains_key(&owner) {
            return false;
        }
        let merges = match self.remote.get(&owner).map(|node| &node.kind) {
            Some(RemoteKind::Folder) => *folder,
            Some(RemoteKind::File {
                content: remote, ..
            }) => !*folder && *content == Some(*remote),
            _ => false,
        };
        if merges {
            self.local_steps.retain(|step| {
                !matches!(step,
                    Step::CreateLocalFolder { node } | Step::Download { node } if *node == owner)
            });
            self.local_owner.insert(path.clone(), owner);
            self.local_path.insert(owner, path.clone());
            self.finals.push(Step::Bind {
                path: path.clone(),
                node: owner,
            });
            // Merged by a case-insensitive match: take the remote name's exact case.
            let remote_name = self.remote.get(&owner).map(|node| &node.name);
            if path.name() != remote_name {
                self.local_steps.push(Step::MoveLocal { node: owner });
            }
        }
        merges
    }

    /// Renames `path` in place to a free conflict name; returns the new path.
    fn set_aside(&mut self, path: &RelPath) -> RelPath {
        let Some(original) = path.name().cloned() else {
            return path.clone();
        };
        let parent = self.local_parent(path);
        let mut attempt = 1;
        let (name, aside) = loop {
            let name = conflict_name(&original, self.options.conflict_tag, attempt);
            let candidate = path.with_name(name.clone());
            let key = self.key(&name);
            let taken_remote = self
                .remote_owned
                .contains_key(&(parent.clone(), key.clone()));
            let taken_local = self
                .local
                .keys()
                .chain(self.claimed_local.iter())
                .any(|other| {
                    other.parent() == candidate.parent()
                        && other.name().map(|n| self.key(n)) == Some(key.clone())
                });
            if !taken_remote && !taken_local {
                break (name, candidate);
            }
            attempt += 1;
        };
        self.claimed_local.insert(aside.clone());
        // Everything located at or below the old path is now below the new one.
        let moves = [(path.clone(), aside.clone())];
        self.local_owner = std::mem::take(&mut self.local_owner)
            .into_iter()
            .map(|(located, node)| (Self::carried(&located, &moves), node))
            .collect();
        for located in self.local_path.values_mut() {
            *located = Self::carried(located, &moves);
        }
        self.set_asides.push(Step::SetAside {
            from: path.clone(),
            to: name.clone(),
        });
        self.conflicts.push(Conflict {
            path: path.clone(),
            renamed_to: name,
        });
        aside
    }

    // ── phase 6: ancestors ─────────────────────────────────────────────────────────

    /// A folder deleted locally is recreated if something arrives inside it. Runs before
    /// collision resolution, so a new local entry in its place is set aside.
    fn keep_local_ancestors(&mut self) {
        let mut needed: BTreeSet<NodeId> = BTreeSet::new();
        for step in &self.local_steps {
            if let Step::CreateLocalFolder { node }
            | Step::MoveLocal { node }
            | Step::Download { node } = step
            {
                let mut parent = self.remote.get(node).and_then(|n| n.parent);
                while let Some(ancestor) = parent {
                    needed.insert(ancestor);
                    parent = self.remote.get(&ancestor).and_then(|n| n.parent);
                }
            }
        }
        let restored: Vec<NodeId> = self
            .deletes
            .iter()
            .copied()
            .filter(|node| needed.contains(node))
            .collect();
        self.deletes.retain(|node| !needed.contains(node));
        for node in restored {
            let placement = self.remote_placement(node);
            self.remote_owned.insert(placement, node);
            self.local_steps.push(Step::CreateLocalFolder { node });
        }
    }

    /// A folder deleted remotely comes back if something is uploaded inside it. Runs before
    /// collision resolution, so its place is checked too.
    fn keep_remote_ancestors(&mut self) {
        let mut resurrected = BTreeSet::new();
        for claim in &self.claims {
            for ancestor in claim.path().ancestors() {
                if let Some(&node) = self.local_owner.get(&ancestor) {
                    let deleted_remotely = self
                        .local_steps
                        .iter()
                        .any(|step| matches!(step, Step::DeleteLocal { node: n } if *n == node));
                    if deleted_remotely {
                        resurrected.insert(node);
                    }
                }
            }
        }
        self.local_steps.retain(
            |step| !matches!(step, Step::DeleteLocal { node } if resurrected.contains(node)),
        );
        for node in resurrected {
            let path = self.local_path.get(&node).cloned().unwrap_or_default();
            self.claims.push(Claim::Change {
                node,
                path,
                resurrect: true,
                moved: false,
            });
        }
    }

    // ── phase 7: brake and order ───────────────────────────────────────────────────

    /// Remote file deletions in the plan, if they exceed the brake and weren't confirmed.
    fn braked_deletions(&self) -> Option<usize> {
        let file_deletions = self
            .deletes
            .iter()
            .filter(|node| {
                matches!(
                    self.base.get(node).map(|e| &e.kind),
                    Some(BaseKind::File { .. })
                )
            })
            .count();
        let files = self
            .base
            .values()
            .filter(|entry| matches!(entry.kind, BaseKind::File { .. }))
            .count();
        let brake = self.options.brake;
        let over = file_deletions > brake.max_count
            || (file_deletions >= brake.min_count
                && file_deletions * 100 > files * brake.max_percent);
        (over && !self.options.allow_mass_delete).then_some(file_deletions)
    }

    fn finish(mut self) -> Plan {
        if let Some(deletions) = self.braked_deletions() {
            return Plan {
                skipped: self.skipped,
                ..Plan::paused(Pause::MassDelete { deletions })
            };
        }

        let remote_depth = |node: &NodeId| {
            self.paths
                .get(node)
                .map_or(0, |path| path.components().len())
        };
        let local_depth = |node: &NodeId| {
            self.local_path
                .get(node)
                .map_or(0, |path| path.components().len())
        };
        let of_kind = |steps: &[Step], pick: fn(&Step) -> Option<NodeId>| -> Vec<NodeId> {
            steps.iter().filter_map(pick).collect()
        };
        let mut folders = of_kind(&self.local_steps, |s| match s {
            Step::CreateLocalFolder { node } => Some(*node),
            _ => None,
        });
        folders.sort_by_key(remote_depth);
        folders.dedup();
        let mut moves = of_kind(&self.local_steps, |s| match s {
            Step::MoveLocal { node } => Some(*node),
            _ => None,
        });
        moves.sort_by_key(remote_depth);
        let downloads = of_kind(&self.local_steps, |s| match s {
            Step::Download { node } => Some(*node),
            _ => None,
        });
        let mut local_deletes = of_kind(&self.local_steps, |s| match s {
            Step::DeleteLocal { node } => Some(*node),
            _ => None,
        });
        local_deletes.sort_by_key(|node| std::cmp::Reverse(local_depth(node)));

        let mut steps = std::mem::take(&mut self.set_asides);
        // Merged entries are nodes from now on: record them before anything is placed in them.
        let (binds, finals): (Vec<Step>, Vec<Step>) = std::mem::take(&mut self.finals)
            .into_iter()
            .partition(|step| matches!(step, Step::Bind { .. }));
        steps.extend(binds);
        steps.extend(
            folders
                .into_iter()
                .map(|node| Step::CreateLocalFolder { node }),
        );
        steps.extend(moves.into_iter().map(|node| Step::MoveLocal { node }));
        steps.extend(downloads.into_iter().map(|node| Step::Download { node }));
        steps.extend(
            local_deletes
                .into_iter()
                .map(|node| Step::DeleteLocal { node }),
        );
        let mut claims = std::mem::take(&mut self.claims);
        claims.sort_by(|a, b| {
            (a.path().components().len(), a.path()).cmp(&(b.path().components().len(), b.path()))
        });
        let mut uploaded = BTreeSet::new();
        for claim in claims {
            match claim {
                Claim::New { path, folder, .. } => steps.push(Step::UploadNew { path, folder }),
                Claim::Change {
                    node, resurrect, ..
                } => {
                    if uploaded.insert(node) {
                        steps.push(Step::UploadChange { node, resurrect });
                    }
                }
            }
        }
        steps.extend(self.deletes.iter().map(|&node| Step::UploadDelete { node }));
        steps.extend(finals);
        Plan {
            steps,
            conflicts: self.conflicts,
            skipped: self.skipped,
            paused: None,
            located: self.local_path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RemoteNode, Stat, TreeError};
    use oxisoft_drive_crypto::hash;
    use oxisoft_drive_proto::{DeviceId, Version};

    fn name(text: &str) -> Name {
        Name::new(text).unwrap()
    }

    fn path(text: &str) -> RelPath {
        RelPath::parse(text).unwrap()
    }

    fn id(n: u8) -> NodeId {
        NodeId::from_bytes([n; 16])
    }

    fn version(counter: u64) -> Version {
        Version {
            device: DeviceId::from_bytes([9; 16]),
            counter,
        }
    }

    fn content(n: u8) -> ContentHash {
        ContentHash(hash::hash(&[n]))
    }

    fn stat(n: u8, file_id: u64) -> Stat {
        Stat {
            size: u64::from(n),
            mtime_ms: i64::from(n),
            file_id,
            executable: false,
        }
    }

    fn remote_file(parent: Option<u8>, file: &str, n: u8, counter: u64) -> RemoteNode {
        RemoteNode {
            parent: parent.map(id),
            name: name(file),
            kind: RemoteKind::File {
                content: content(n),
                size: u64::from(n),
            },
            version: version(counter),
        }
    }

    fn remote_folder(parent: Option<u8>, folder: &str, counter: u64) -> RemoteNode {
        RemoteNode {
            parent: parent.map(id),
            name: name(folder),
            kind: RemoteKind::Folder,
            version: version(counter),
        }
    }

    fn base_file(at: &str, n: u8, file_id: u64, counter: u64) -> BaseEntry {
        BaseEntry {
            path: path(at),
            kind: BaseKind::File {
                stat: stat(n, file_id),
                content: content(n),
            },
            version: version(counter),
        }
    }

    fn local_file(n: u8, file_id: u64) -> LocalEntry {
        LocalEntry::File {
            stat: stat(n, file_id),
            content: Some(content(n)),
        }
    }

    struct Setup {
        base: Base,
        local: LocalTree,
        remote: RemoteTree,
    }

    /// One synced file `f` (node 1, content 1) on both sides.
    fn synced_file() -> Setup {
        Setup {
            base: [(id(1), base_file("f", 1, 100, 1))].into(),
            local: [(path("f"), local_file(1, 100))].into(),
            remote: [(id(1), remote_file(None, "f", 1, 1))].into(),
        }
    }

    fn never(_: &RelPath, _: bool) -> bool {
        false
    }

    fn plan_with<'a>(setup: &Setup, tweak: impl FnOnce(&mut Options<'a>)) -> Plan {
        let mut options = Options {
            marker_present: true,
            allow_mass_delete: false,
            brake: MassDeleteBrake::default(),
            fs: FsRules::default(),
            conflict_tag: "conflict T",
            is_ignored: &never,
        };
        tweak(&mut options);
        reconcile(&setup.base, &setup.local, &setup.remote, &options)
    }

    fn plan_of(setup: &Setup) -> Plan {
        plan_with(setup, |_| {})
    }

    #[test]
    fn nothing_to_do_when_in_step() {
        let plan = plan_of(&synced_file());
        assert!(plan.steps.is_empty() && plan.conflicts.is_empty() && plan.paused.is_none());
        assert_eq!(plan.located[&id(1)], path("f"));
    }

    #[test]
    fn a_missing_marker_pauses() {
        let plan = plan_with(&synced_file(), |o| o.marker_present = false);
        assert_eq!(plan.paused, Some(Pause::MarkerMissing));
        assert!(plan.steps.is_empty());
        let text = format!(
            "{:?}",
            Options {
                marker_present: true,
                allow_mass_delete: false,
                brake: MassDeleteBrake::default(),
                fs: FsRules::default(),
                conflict_tag: "t",
                is_ignored: &|_, _| false,
            }
        );
        assert!(
            text.starts_with("Options {") && text.contains("conflict_tag"),
            "{text}"
        );
    }

    #[test]
    fn a_corrupt_remote_tree_pauses() {
        let mut setup = synced_file();
        setup
            .remote
            .insert(id(2), remote_file(Some(9), "orphan", 2, 1));
        assert_eq!(
            plan_of(&setup).paused,
            Some(Pause::CorruptTree(TreeError::MissingParent(id(2))))
        );
    }

    #[test]
    fn the_mass_delete_brake() {
        let mut setup = Setup {
            base: Base::new(),
            local: LocalTree::new(),
            remote: RemoteTree::new(),
        };
        for n in 1..=20 {
            let file = format!("f{n}");
            setup
                .base
                .insert(id(n), base_file(&file, n, u64::from(n), 1));
            setup.remote.insert(id(n), remote_file(None, &file, n, 1));
            // Files 1–10 are deleted locally.
            if n > 10 {
                setup.local.insert(path(&file), local_file(n, u64::from(n)));
            }
        }
        // 10 of 20 deleted: at the minimum count and over 20 %.
        assert_eq!(
            plan_of(&setup).paused,
            Some(Pause::MassDelete { deletions: 10 })
        );
        let allowed = plan_with(&setup, |o| o.allow_mass_delete = true);
        assert_eq!(allowed.paused, None);
        assert_eq!(allowed.steps.len(), 10);
        // Below the minimum count, the share doesn't matter.
        setup.local.insert(path("f1"), local_file(1, 1));
        assert_eq!(plan_of(&setup).paused, None);
        // Above the absolute maximum, it always pauses.
        let strict = plan_with(&setup, |o| {
            o.brake = MassDeleteBrake {
                max_count: 5,
                max_percent: 100,
                min_count: 100,
            };
        });
        assert_eq!(strict.paused, Some(Pause::MassDelete { deletions: 9 }));
    }

    #[test]
    fn both_edited_keeps_both() {
        let mut setup = synced_file();
        setup.local.insert(path("f"), local_file(2, 100));
        setup.remote.insert(id(1), remote_file(None, "f", 3, 2));
        let plan = plan_of(&setup);
        let aside = name("f (conflict T)");
        assert_eq!(
            plan.steps,
            vec![
                Step::SetAside {
                    from: path("f"),
                    to: aside.clone()
                },
                Step::Download { node: id(1) },
                Step::UploadNew {
                    path: path("f (conflict T)"),
                    folder: false
                },
            ]
        );
        assert_eq!(
            plan.conflicts,
            vec![Conflict {
                path: path("f"),
                renamed_to: aside
            }]
        );
    }

    #[test]
    fn same_edit_on_both_sides_is_no_conflict() {
        let mut setup = synced_file();
        setup.local.insert(path("f"), local_file(2, 100));
        setup.remote.insert(id(1), remote_file(None, "f", 2, 2));
        assert_eq!(plan_of(&setup).steps, vec![Step::Adopt { node: id(1) }]);
    }

    #[test]
    fn an_edit_beats_a_delete_in_both_directions() {
        let mut local_edit = synced_file();
        local_edit.local.insert(path("f"), local_file(2, 100));
        local_edit.remote.get_mut(&id(1)).unwrap().kind = RemoteKind::Deleted;
        assert_eq!(
            plan_of(&local_edit).steps,
            vec![Step::UploadChange {
                node: id(1),
                resurrect: true
            }]
        );
        let mut remote_edit = synced_file();
        remote_edit.local.clear();
        remote_edit
            .remote
            .insert(id(1), remote_file(None, "f", 3, 2));
        assert_eq!(
            plan_of(&remote_edit).steps,
            vec![Step::Download { node: id(1) }]
        );
    }

    #[test]
    fn new_entries_meeting_new_nodes() {
        // Same content: the local file is bound to the remote node, nothing transferred.
        let setup = Setup {
            base: Base::new(),
            local: [
                (path("x"), local_file(5, 1)),
                (path("d"), LocalEntry::Folder { file_id: 2 }),
            ]
            .into(),
            remote: [
                (id(1), remote_file(None, "x", 5, 1)),
                (id(2), remote_folder(None, "d", 1)),
            ]
            .into(),
        };
        let plan = plan_of(&setup);
        assert!(plan.steps.contains(&Step::Bind {
            path: path("x"),
            node: id(1)
        }));
        assert!(plan.steps.contains(&Step::Bind {
            path: path("d"),
            node: id(2)
        }));
        assert_eq!(plan.steps.len(), 2);
        // Different content: the local file is set aside.
        let clash = Setup {
            base: Base::new(),
            local: [(path("x"), local_file(6, 1))].into(),
            remote: [(id(1), remote_file(None, "x", 5, 1))].into(),
        };
        let plan = plan_of(&clash);
        assert!(matches!(plan.steps[0], Step::SetAside { .. }));
        assert!(plan.steps.contains(&Step::Download { node: id(1) }));
    }

    #[test]
    fn case_clashes_and_windows_names_are_skipped() {
        let setup = Setup {
            base: Base::new(),
            local: LocalTree::new(),
            remote: [
                (id(1), remote_file(None, "Report.txt", 1, 1)),
                (id(2), remote_file(None, "report.txt", 2, 1)),
                (id(3), remote_folder(None, "aux", 1)),
                (id(4), remote_file(Some(3), "inside", 4, 1)),
            ]
            .into(),
        };
        let plan = plan_with(&setup, |o| {
            o.fs = FsRules {
                case_insensitive: true,
                windows_names: true,
            };
        });
        let skipped: Vec<(NodeId, SkipReason)> =
            plan.skipped.iter().map(|s| (s.node, s.reason)).collect();
        assert!(skipped.contains(&(id(2), SkipReason::CaseClash)));
        assert!(skipped.contains(&(id(3), SkipReason::WindowsName)));
        assert!(skipped.contains(&(id(4), SkipReason::InSkippedFolder)));
        assert_eq!(plan.steps, vec![Step::Download { node: id(1) }]);
        // A case-sensitive Linux file system takes them all.
        assert_eq!(
            reconcile(
                &setup.base,
                &setup.local,
                &setup.remote,
                &Options {
                    marker_present: true,
                    allow_mass_delete: false,
                    brake: MassDeleteBrake::default(),
                    fs: FsRules::default(),
                    conflict_tag: "t",
                    is_ignored: &|_, _| false,
                }
            )
            .skipped,
            vec![]
        );
    }

    #[test]
    fn ignored_entries_are_invisible_on_both_sides() {
        let setup = Setup {
            base: Base::new(),
            local: [
                (path("build"), LocalEntry::Folder { file_id: 1 }),
                (path("build/out.o"), local_file(1, 2)),
                (path("notes.txt"), local_file(2, 3)),
                (path(".DS_Store"), local_file(3, 4)),
            ]
            .into(),
            remote: [
                (id(1), remote_file(None, "cache.tmp", 4, 1)),
                (id(2), remote_folder(None, "cache.dir", 1)),
                (id(3), remote_file(Some(2), "inside", 5, 1)),
            ]
            .into(),
        };
        let ignored = |p: &RelPath, _: bool| {
            let text = p.to_string();
            text == "build" || text == ".DS_Store" || text.starts_with("cache.")
        };
        let plan = plan_with(&setup, |o| o.is_ignored = &ignored);
        assert_eq!(
            plan.steps,
            vec![Step::UploadNew {
                path: path("notes.txt"),
                folder: false
            }]
        );
        assert!(plan.skipped.is_empty());
    }

    #[test]
    fn remote_moves_and_renames_are_applied_locally() {
        let setup = Setup {
            base: [
                (
                    id(1),
                    BaseEntry {
                        path: path("d"),
                        kind: BaseKind::Folder { file_id: 10 },
                        version: version(1),
                    },
                ),
                (id(2), base_file("d/f", 2, 20, 1)),
            ]
            .into(),
            local: [
                (path("d"), LocalEntry::Folder { file_id: 10 }),
                (path("d/f"), local_file(2, 20)),
            ]
            .into(),
            remote: [
                (id(1), remote_folder(None, "renamed", 2)),
                (id(2), remote_file(None, "f", 2, 2)),
            ]
            .into(),
        };
        let plan = plan_of(&setup);
        assert!(plan.steps.contains(&Step::MoveLocal { node: id(1) }));
        assert!(plan.steps.contains(&Step::MoveLocal { node: id(2) }));
        assert_eq!(plan.steps.len(), 2);
    }

    #[test]
    fn a_kind_change_pauses() {
        let mut setup = synced_file();
        setup.remote.insert(id(1), remote_folder(None, "f", 2));
        assert_eq!(
            plan_of(&setup).paused,
            Some(Pause::CorruptTree(TreeError::KindChanged(id(1))))
        );
        let mut folder = synced_file();
        folder.base.insert(
            id(1),
            BaseEntry {
                path: path("f"),
                kind: BaseKind::Folder { file_id: 100 },
                version: version(1),
            },
        );
        assert_eq!(
            plan_of(&folder).paused,
            Some(Pause::CorruptTree(TreeError::KindChanged(id(1))))
        );
    }

    /// A live node under a deleted folder (never written by a correct device) brings the
    /// folder back rather than losing the node.
    #[test]
    fn orphans_bring_their_folder_back() {
        let deleted_folder = RemoteNode {
            kind: RemoteKind::Deleted,
            ..remote_folder(None, "d", 2)
        };
        // Synced here and still present locally: upload it again.
        let present = Setup {
            base: [(
                id(1),
                BaseEntry {
                    path: path("d"),
                    kind: BaseKind::Folder { file_id: 10 },
                    version: version(1),
                },
            )]
            .into(),
            local: [(path("d"), LocalEntry::Folder { file_id: 10 })].into(),
            remote: [
                (id(1), deleted_folder.clone()),
                (id(2), remote_file(Some(1), "f", 2, 1)),
            ]
            .into(),
        };
        let plan = plan_of(&present);
        assert!(plan.steps.contains(&Step::UploadChange {
            node: id(1),
            resurrect: true
        }));
        assert!(plan.steps.contains(&Step::Download { node: id(2) }));
        // Synced here but deleted locally too: recreate it, then upload it again.
        let absent = Setup {
            local: LocalTree::new(),
            ..present
        };
        let plan = plan_of(&absent);
        assert!(
            plan.steps
                .contains(&Step::CreateLocalFolder { node: id(1) })
        );
        assert!(plan.steps.contains(&Step::UploadChange {
            node: id(1),
            resurrect: true
        }));
        // Never synced here: create it and upload it again.
        let unknown = Setup {
            base: Base::new(),
            local: LocalTree::new(),
            remote: [
                (id(1), deleted_folder),
                (id(2), remote_file(Some(1), "f", 2, 1)),
            ]
            .into(),
        };
        let plan = plan_of(&unknown);
        assert!(
            plan.steps
                .contains(&Step::CreateLocalFolder { node: id(1) })
        );
        assert!(plan.steps.contains(&Step::UploadChange {
            node: id(1),
            resurrect: true
        }));
    }

    #[test]
    fn remote_metadata_changes_are_adopted() {
        // Same content and place, new version (another device touched it).
        let mut setup = synced_file();
        setup.remote.insert(id(1), remote_file(None, "f", 1, 2));
        assert_eq!(plan_of(&setup).steps, vec![Step::Adopt { node: id(1) }]);
        // …while the local side renamed it: the rename is uploaded.
        setup.local = [(path("g"), local_file(1, 100))].into();
        assert_eq!(
            plan_of(&setup).steps,
            vec![Step::UploadChange {
                node: id(1),
                resurrect: false
            }]
        );
    }

    #[test]
    fn local_edits_with_remote_moves() {
        // Edited here, renamed there: move here, then upload the content.
        let mut setup = synced_file();
        setup.local.insert(path("f"), local_file(2, 100));
        setup.remote.insert(id(1), remote_file(None, "g", 1, 2));
        let plan = plan_of(&setup);
        assert_eq!(
            plan.steps,
            vec![
                Step::MoveLocal { node: id(1) },
                Step::UploadChange {
                    node: id(1),
                    resurrect: false
                }
            ]
        );
        // Renamed here, edited there: download in place, then upload the rename.
        let mut setup = synced_file();
        setup.local = [(path("g"), local_file(1, 100))].into();
        setup.remote.insert(id(1), remote_file(None, "f", 3, 2));
        assert_eq!(
            plan_of(&setup).steps,
            vec![
                Step::Download { node: id(1) },
                Step::UploadChange {
                    node: id(1),
                    resurrect: false
                }
            ]
        );
    }

    #[test]
    fn local_folder_renames_upload_only_the_folder() {
        let setup = Setup {
            base: [
                (
                    id(1),
                    BaseEntry {
                        path: path("d"),
                        kind: BaseKind::Folder { file_id: 10 },
                        version: version(1),
                    },
                ),
                (id(2), base_file("d/f", 2, 20, 1)),
            ]
            .into(),
            local: [
                (path("e"), LocalEntry::Folder { file_id: 10 }),
                (path("e/f"), local_file(2, 20)),
            ]
            .into(),
            remote: [
                (id(1), remote_folder(None, "d", 1)),
                (id(2), remote_file(Some(1), "f", 2, 1)),
            ]
            .into(),
        };
        assert_eq!(
            plan_of(&setup).steps,
            vec![Step::UploadChange {
                node: id(1),
                resurrect: false
            }]
        );
    }
}
