//! Model-based test of the reconciler: two devices and a server, all in memory.
//!
//! Random edits happen on both devices, then both sync in turns until neither has anything
//! left to do. A small model executor carries out each plan the way the real executor will
//! (resolving nodes to paths through a live location map). Checked after every cycle:
//!
//! 1. **Convergence:** both devices and the server hold the same tree.
//! 2. **No data loss:** every content a device wrote itself and still had when it synced
//!    survives somewhere in the final tree (as the file, or as a conflict copy).

#![cfg(test)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use oxisoft_drive_core::{
    Base, BaseEntry, BaseKind, FsRules, LocalEntry, LocalTree, MassDeleteBrake, Options, Plan,
    RelPath, RemoteKind, RemoteNode, RemoteTree, Stat, Step, reconcile, remote_paths,
};
use oxisoft_drive_crypto::hash;
use oxisoft_drive_proto::{ContentHash, DeviceId, Name, NodeId, Version};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    File {
        content: u64,
        file_id: u64,
        mtime: i64,
    },
    Folder {
        file_id: u64,
    },
}

/// What a tree looks like, ignoring file IDs and times: path → Some(content) or None (folder).
type Shape = BTreeMap<RelPath, Option<u64>>;

struct Device {
    id: DeviceId,
    tag: String,
    fs: BTreeMap<RelPath, Entry>,
    base: Base,
    counter: u64,
    next_file_id: u64,
    clock: i64,
}

#[derive(Default)]
struct Server {
    tree: RemoteTree,
    contents: BTreeMap<NodeId, u64>,
    next_node: u8,
    next_node_hi: u8,
}

fn content_hash(content: u64) -> ContentHash {
    ContentHash(hash::hash(&content.to_le_bytes()))
}

fn stat(content: u64, file_id: u64, mtime: i64) -> Stat {
    Stat {
        size: content,
        mtime_ms: mtime,
        file_id,
        executable: false,
    }
}

impl Device {
    fn new(seed: u8, tag: &str) -> Self {
        Self {
            id: DeviceId::from_bytes([seed; 16]),
            tag: tag.to_owned(),
            fs: BTreeMap::new(),
            base: Base::new(),
            counter: 0,
            next_file_id: u64::from(seed) << 32,
            clock: 0,
        }
    }

    fn file_id(&mut self) -> u64 {
        self.next_file_id += 1;
        self.next_file_id
    }

    fn tick(&mut self) -> i64 {
        self.clock += 1;
        self.clock
    }

    fn version(&mut self) -> Version {
        self.counter += 1;
        Version {
            device: self.id,
            counter: self.counter,
        }
    }

    fn scan(&self) -> LocalTree {
        self.fs
            .iter()
            .map(|(path, entry)| {
                let local = match entry {
                    Entry::File {
                        content,
                        file_id,
                        mtime,
                    } => LocalEntry::File {
                        stat: stat(*content, *file_id, *mtime),
                        content: Some(content_hash(*content)),
                    },
                    Entry::Folder { file_id } => LocalEntry::Folder { file_id: *file_id },
                };
                (path.clone(), local)
            })
            .collect()
    }

    fn shape(&self) -> Shape {
        self.fs
            .iter()
            .map(|(path, entry)| {
                let content = match entry {
                    Entry::File { content, .. } => Some(*content),
                    Entry::Folder { .. } => None,
                };
                (path.clone(), content)
            })
            .collect()
    }

    /// Contents this device wrote since its last sync: they must survive.
    fn own_contents(&self) -> BTreeSet<u64> {
        let synced: HashSet<ContentHash> = self
            .base
            .values()
            .filter_map(|entry| match entry.kind {
                BaseKind::File { content, .. } => Some(content),
                BaseKind::Folder { .. } => None,
            })
            .collect();
        self.fs
            .values()
            .filter_map(|entry| match entry {
                Entry::File { content, .. } if !synced.contains(&content_hash(*content)) => {
                    Some(*content)
                }
                _ => None,
            })
            .collect()
    }
}

impl Server {
    fn new_node(&mut self) -> NodeId {
        self.next_node = self.next_node.wrapping_add(1);
        if self.next_node == 0 {
            self.next_node_hi += 1;
        }
        let mut bytes = [0; 16];
        bytes[0] = self.next_node_hi;
        bytes[1] = self.next_node;
        NodeId::from_bytes(bytes)
    }

    fn shape(&self) -> Shape {
        let paths = remote_paths(&self.tree).expect("remote tree is well-formed");
        self.tree
            .iter()
            .filter_map(|(id, node)| match node.kind {
                RemoteKind::File { .. } => Some((paths[id].clone(), Some(self.contents[id]))),
                RemoteKind::Folder => Some((paths[id].clone(), None)),
                RemoteKind::Deleted => None,
            })
            .collect()
    }
}

thread_local! {
    /// What happened in the current run; printed when a check fails.
    static TRACE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn trace(line: String) {
    TRACE.with(|t| t.borrow_mut().push(line));
}

/// Fails with the trace attached.
fn ensure(ok: bool, message: impl FnOnce() -> String) {
    assert!(ok, "{}\ntrace:\n{}", message(), take_trace());
}

fn take_trace() -> String {
    TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()).join("\n"))
}

// ── the model executor ─────────────────────────────────────────────────────────────

fn move_subtree(fs: &mut BTreeMap<RelPath, Entry>, from: &RelPath, to: &RelPath) {
    let moved: Vec<RelPath> = fs.keys().filter(|p| p.starts_with(from)).cloned().collect();
    for path in moved {
        let entry = fs.remove(&path).expect("listed");
        let mut target = to.clone();
        for name in &path.components()[from.components().len()..] {
            target = target.join(name.clone());
        }
        fs.insert(target, entry);
    }
}

fn rewrite(locations: &mut BTreeMap<NodeId, RelPath>, from: &RelPath, to: &RelPath) {
    for path in locations.values_mut() {
        if path.starts_with(from) {
            let mut target = to.clone();
            for name in &path.components()[from.components().len()..] {
                target = target.join(name.clone());
            }
            *path = target;
        }
    }
}

fn placed_path(node: NodeId, server: &Server, locations: &BTreeMap<NodeId, RelPath>) -> RelPath {
    let remote = &server.tree[&node];
    let parent = remote.parent.map_or_else(RelPath::root, |parent| {
        locations
            .get(&parent)
            .unwrap_or_else(|| {
                panic!(
                    "parent {parent:?} of {node:?} not placed locally\ntrace:\n{}",
                    take_trace()
                )
            })
            .clone()
    });
    parent.join(remote.name.clone())
}

fn parent_node(path: &RelPath, locations: &BTreeMap<NodeId, RelPath>) -> Option<NodeId> {
    let parent = path.parent().filter(|p| !p.is_root())?;
    let found = locations
        .iter()
        .find(|(_, location)| **location == parent)
        .map(|(id, _)| *id);
    Some(found.unwrap_or_else(|| {
        panic!(
            "parent folder {parent} of {path} is not a node\ntrace:\n{}",
            take_trace()
        )
    }))
}

fn remote_kind(entry: &Entry) -> (RemoteKind, Option<u64>) {
    match entry {
        Entry::File { content, .. } => (
            RemoteKind::File {
                content: content_hash(*content),
                size: *content,
            },
            Some(*content),
        ),
        Entry::Folder { .. } => (RemoteKind::Folder, None),
    }
}

/// `path` after the moves the executor performed (in order).
fn translate(path: &RelPath, moves: &[(RelPath, RelPath)]) -> RelPath {
    let mut current = path.clone();
    for (from, to) in moves {
        if current.starts_with(from) {
            let mut target = to.clone();
            for name in &current.components()[from.components().len()..] {
                target = target.join(name.clone());
            }
            current = target;
        }
    }
    current
}

fn apply(device: &mut Device, server: &mut Server, plan: &Plan) {
    let mut locations = plan.located.clone();
    let mut moves: Vec<(RelPath, RelPath)> = Vec::new();

    // Local steps run until their preconditions hold (parent present, target free), in
    // passes, as the real executor schedules them. Folders are deleted only when empty.
    let (mut pending, uploads): (Vec<&Step>, Vec<&Step>) = plan.steps.iter().partition(|step| {
        matches!(
            step,
            Step::SetAside { .. }
                | Step::Bind { .. }
                | Step::CreateLocalFolder { .. }
                | Step::MoveLocal { .. }
                | Step::Download { .. }
                | Step::DeleteLocal { .. }
        )
    });
    while !pending.is_empty() {
        let before = pending.len();
        pending.retain(|step| !try_local(device, server, &mut locations, &mut moves, step));
        if pending.len() == before
            && break_cycle(device, server, &mut locations, &mut moves, &pending)
        {
            continue;
        }
        if pending.len() == before {
            // Only non-empty folders deleted remotely may be left: the executor keeps them.
            let stuck: Vec<_> = pending
                .iter()
                .filter(|step| !matches!(step, Step::DeleteLocal { .. }))
                .collect();
            ensure(stuck.is_empty(), || {
                format!(
                    "local steps stuck: {stuck:?}\n  fs: {:?}\n  locations: {locations:?}",
                    device.shape()
                )
            });
            for step in &pending {
                if let Step::DeleteLocal { node } = step {
                    locations.remove(node);
                }
            }
            break;
        }
    }
    let mut new_nodes = Vec::new();
    for step in uploads {
        new_nodes.extend(upload(device, server, &mut locations, &moves, step));
    }
    // The executor records each completed step in the index: nodes a step touched get their
    // new state; every other node keeps its previous entry, only its location updated.
    let touched: BTreeSet<NodeId> = plan
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::Download { node }
            | Step::UploadChange { node, .. }
            | Step::Bind { node, .. }
            | Step::CreateLocalFolder { node }
            | Step::Adopt { node } => Some(*node),
            _ => None,
        })
        .chain(new_nodes.iter().copied())
        .collect();
    let previous = std::mem::take(&mut device.base);
    device.base = locations
        .into_iter()
        .filter_map(|(node, path)| {
            let remote = server.tree.get(&node)?;
            if !touched.contains(&node) {
                let entry = previous.get(&node)?;
                return Some((
                    node,
                    BaseEntry {
                        path,
                        ..entry.clone()
                    },
                ));
            }
            let kind = match (device.fs.get(&path)?, &remote.kind) {
                (
                    Entry::File {
                        content,
                        file_id,
                        mtime,
                    },
                    RemoteKind::File { .. },
                ) => BaseKind::File {
                    stat: stat(*content, *file_id, *mtime),
                    content: content_hash(*content),
                },
                (Entry::Folder { file_id }, RemoteKind::Folder) => {
                    BaseKind::Folder { file_id: *file_id }
                }
                _ => return None,
            };
            Some((
                node,
                BaseEntry {
                    path,
                    kind,
                    version: remote.version,
                },
            ))
        })
        .collect();
}

fn parent_ready(
    node: NodeId,
    server: &Server,
    locations: &BTreeMap<NodeId, RelPath>,
    device: &Device,
) -> bool {
    server.tree[&node].parent.is_none_or(|parent| {
        locations
            .get(&parent)
            .is_some_and(|path| matches!(device.fs.get(path), Some(Entry::Folder { .. })))
    })
}

/// Placements blocked by an entry that is itself waiting to move (a swap, or a folder whose
/// place is taken by a file moving into it) are unblocked by moving that entry to a
/// temporary name in its folder, as the real executor does. Returns whether it did.
fn break_cycle(
    device: &mut Device,
    server: &Server,
    locations: &mut BTreeMap<NodeId, RelPath>,
    moves: &mut Vec<(RelPath, RelPath)>,
    pending: &[&Step],
) -> bool {
    let moving: BTreeSet<NodeId> = pending
        .iter()
        .filter_map(|step| match step {
            Step::MoveLocal { node } => Some(*node),
            _ => None,
        })
        .collect();
    let placing: Vec<NodeId> = pending
        .iter()
        .filter_map(|step| match step {
            Step::MoveLocal { node } | Step::CreateLocalFolder { node } => Some(*node),
            Step::Download { node } if !locations.contains_key(node) => Some(*node),
            _ => None,
        })
        .collect();
    for node in placing {
        if !parent_ready(node, server, locations, device) {
            continue;
        }
        let target = placed_path(node, server, locations);
        let occupant = locations
            .iter()
            .find(|(other, path)| **path == target && moving.contains(other) && **other != node)
            .map(|(other, _)| *other);
        if let Some(occupant) = occupant {
            let name = Name::new(&format!(".oxidrive-tmp-{occupant:?}")).expect("valid");
            let temporary = target.with_name(name);
            move_subtree(&mut device.fs, &target, &temporary);
            rewrite(locations, &target, &temporary);
            moves.push((target, temporary));
            return true;
        }
    }
    // Otherwise stage a blocked moving node at the root under a temporary name: the folder it
    // leaves may then empty and be deleted, freeing the target (a folder deleted remotely that
    // held the node, whose name the node now takes).
    for node in &moving {
        let Some(from) = locations.get(node).cloned() else {
            continue;
        };
        let name = Name::new(&format!(".oxidrive-stage-{node:?}")).expect("valid");
        let staged = RelPath::root().join(name);
        if from != staged && !device.fs.contains_key(&staged) {
            move_subtree(&mut device.fs, &from, &staged);
            rewrite(locations, &from, &staged);
            moves.push((from, staged));
            return true;
        }
    }
    false
}

/// Writes a node's remote content: in place, or at its remote placement once that is free.
fn download(
    device: &mut Device,
    server: &Server,
    locations: &mut BTreeMap<NodeId, RelPath>,
    node: NodeId,
) -> bool {
    let content = server.contents[&node];
    let own = locations
        .get(&node)
        .filter(|path| device.fs.contains_key(*path))
        .cloned();
    let path = if let Some(path) = own {
        path
    } else {
        if !parent_ready(node, server, locations, device) {
            return false;
        }
        let path = placed_path(node, server, locations);
        if device.fs.contains_key(&path) {
            return false;
        }
        path
    };
    let file_id = match device.fs.get(&path) {
        Some(Entry::File { file_id, .. }) => *file_id,
        _ => device.file_id(),
    };
    let mtime = device.tick();
    device.fs.insert(
        path.clone(),
        Entry::File {
            content,
            file_id,
            mtime,
        },
    );
    locations.insert(node, path);
    true
}

/// Tries one local step; returns whether it ran (or will never need to).
fn try_local(
    device: &mut Device,
    server: &Server,
    locations: &mut BTreeMap<NodeId, RelPath>,
    moves: &mut Vec<(RelPath, RelPath)>,
    step: &Step,
) -> bool {
    match step {
        Step::SetAside { from, to } => {
            let target = from.with_name(to.clone());
            move_subtree(&mut device.fs, from, &target);
            rewrite(locations, from, &target);
            true
        }
        Step::Bind { path, node } => {
            locations.insert(*node, path.clone());
            true
        }
        Step::CreateLocalFolder { node } => {
            if !parent_ready(*node, server, locations, device) {
                return false;
            }
            let path = placed_path(*node, server, locations);
            // An existing folder is reused only if no other node owns it.
            let owned_by_other = locations
                .iter()
                .any(|(other, location)| *location == path && other != node);
            if owned_by_other {
                return false;
            }
            match device.fs.get(&path) {
                Some(Entry::Folder { .. }) => {}
                Some(Entry::File { .. }) => return false,
                None => {
                    let file_id = device.file_id();
                    device.fs.insert(path.clone(), Entry::Folder { file_id });
                }
            }
            locations.insert(*node, path);
            true
        }
        Step::MoveLocal { node } => {
            if !parent_ready(*node, server, locations, device) {
                return false;
            }
            let from = locations[node].clone();
            let to = placed_path(*node, server, locations);
            if from == to {
                return true;
            }
            // Never into its own subtree, and never onto an existing entry.
            if to.starts_with(&from) || device.fs.contains_key(&to) {
                return false;
            }
            move_subtree(&mut device.fs, &from, &to);
            rewrite(locations, &from, &to);
            moves.push((from, to));
            true
        }
        Step::Download { node } => download(device, server, locations, *node),
        Step::DeleteLocal { node } => {
            let Some(path) = locations.get(node).cloned() else {
                return true;
            };
            let has_children = device
                .fs
                .keys()
                .any(|other| other != &path && other.starts_with(&path));
            if has_children {
                return false;
            }
            device.fs.remove(&path);
            locations.remove(node);
            true
        }
        _ => true,
    }
}

/// Carries out one upload step, as the executor does after the local steps.
fn upload(
    device: &mut Device,
    server: &mut Server,
    locations: &mut BTreeMap<NodeId, RelPath>,
    moves: &[(RelPath, RelPath)],
    step: &Step,
) -> Option<NodeId> {
    match step {
        Step::UploadNew { path, .. } => {
            let path = &translate(path, moves);
            let entry = device
                .fs
                .get(path)
                .unwrap_or_else(|| panic!("UploadNew of missing {path}\ntrace:\n{}", take_trace()))
                .clone();
            let parent = parent_node(path, locations);
            let node = server.new_node();
            let (kind, content) = remote_kind(&entry);
            let version = device.version();
            let name = path.name().expect("not the root").clone();
            server.tree.insert(
                node,
                RemoteNode {
                    parent,
                    name,
                    kind,
                    version,
                },
            );
            if let Some(content) = content {
                server.contents.insert(node, content);
            }
            locations.insert(node, path.clone());
            Some(node)
        }
        Step::UploadChange { node, .. } => {
            let path = locations[node].clone();
            let entry = device
                .fs
                .get(&path)
                .unwrap_or_else(|| {
                    panic!("UploadChange of missing {path}\ntrace:\n{}", take_trace())
                })
                .clone();
            let parent = parent_node(&path, locations);
            let (kind, content) = remote_kind(&entry);
            let version = device.version();
            let name = path.name().expect("not the root").clone();
            server.tree.insert(
                *node,
                RemoteNode {
                    parent,
                    name,
                    kind,
                    version,
                },
            );
            if let Some(content) = content {
                server.contents.insert(*node, content);
            }
            None
        }
        Step::UploadDelete { node } => {
            let version = device.version();
            if let Some(remote) = server.tree.get_mut(node) {
                remote.kind = RemoteKind::Deleted;
                remote.version = version;
            }
            server.contents.remove(node);
            locations.remove(node);
            None
        }
        _ => None,
    }
}

fn sync(device: &mut Device, server: &mut Server) -> usize {
    let local = device.scan();
    let tag = device.tag.clone();
    let never = |_: &RelPath, _: bool| false;
    let options = Options {
        marker_present: true,
        allow_mass_delete: true,
        brake: MassDeleteBrake::default(),
        fs: FsRules::default(),
        conflict_tag: &tag,
        is_ignored: &never,
    };
    let plan = reconcile(&device.base, &local, &server.tree, &options);
    assert_eq!(plan.paused, None);
    trace(format!("{} syncs: {:?}", device.tag, plan.steps));
    apply(device, server, &plan);
    let paths = remote_paths(&server.tree).expect("well-formed");
    let live: Vec<String> = server
        .tree
        .iter()
        .filter(|(_, node)| node.kind != RemoteKind::Deleted)
        .map(|(id, _)| format!("{}={}", paths[id], id.as_bytes()[1]))
        .collect();
    trace(format!("  server now: {}", live.join(" ")));
    plan.steps
        .iter()
        .filter(|step| !matches!(step, Step::Adopt { .. } | Step::Forget { .. }))
        .count()
}

// ── random edits ───────────────────────────────────────────────────────────────────

const NAMES: [&str; 5] = ["a", "b", "c.txt", "d.txt", "e"];

fn random_name(rng: &mut ChaCha20Rng) -> Name {
    let index = usize::try_from(rng.next_u32() % 5).expect("small");
    Name::new(NAMES[index]).expect("valid")
}

fn pick<T: Clone>(rng: &mut ChaCha20Rng, items: &[T]) -> Option<T> {
    if items.is_empty() {
        return None;
    }
    let index = usize::try_from(rng.next_u64() % items.len() as u64).expect("small");
    Some(items[index].clone())
}

fn edit(device: &mut Device, rng: &mut ChaCha20Rng, next_content: &mut u64) {
    let before = device.shape();
    edit_inner(device, rng, next_content);
    let after = device.shape();
    if before != after {
        let removed: Vec<_> = before
            .iter()
            .filter(|(p, c)| after.get(*p) != Some(c))
            .map(|(p, c)| format!("-{p}={c:?}"))
            .collect();
        let added: Vec<_> = after
            .iter()
            .filter(|(p, c)| before.get(*p) != Some(c))
            .map(|(p, c)| format!("+{p}={c:?}"))
            .collect();
        trace(format!(
            "{} edits: {} {}",
            device.tag,
            removed.join(" "),
            added.join(" ")
        ));
    }
}

fn edit_inner(device: &mut Device, rng: &mut ChaCha20Rng, next_content: &mut u64) {
    let folders: Vec<RelPath> = std::iter::once(RelPath::root())
        .chain(
            device
                .fs
                .iter()
                .filter(|(_, e)| matches!(e, Entry::Folder { .. }))
                .map(|(p, _)| p.clone()),
        )
        .collect();
    let files: Vec<RelPath> = device
        .fs
        .iter()
        .filter(|(_, e)| matches!(e, Entry::File { .. }))
        .map(|(p, _)| p.clone())
        .collect();
    let all: Vec<RelPath> = device.fs.keys().cloned().collect();
    match rng.next_u32() % 10 {
        0..=2 => {
            let Some(folder) = pick(rng, &folders) else {
                return;
            };
            let path = folder.join(random_name(rng));
            if !device.fs.contains_key(&path) {
                *next_content += 1;
                let (file_id, mtime) = (device.file_id(), device.tick());
                device.fs.insert(
                    path,
                    Entry::File {
                        content: *next_content,
                        file_id,
                        mtime,
                    },
                );
            }
        }
        3..=4 => {
            let Some(path) = pick(rng, &files) else {
                return;
            };
            *next_content += 1;
            let mtime = device.tick();
            // Some editors save by writing a new file and renaming it over the old one.
            let fresh_id = rng.next_u32().is_multiple_of(3);
            let new_id = device.file_id();
            if let Some(Entry::File {
                content,
                file_id,
                mtime: time,
            }) = device.fs.get_mut(&path)
            {
                *content = *next_content;
                *time = mtime;
                if fresh_id {
                    *file_id = new_id;
                }
            }
        }
        5 => {
            let Some(folder) = pick(rng, &folders) else {
                return;
            };
            let path = folder.join(random_name(rng));
            if !device.fs.contains_key(&path) {
                let file_id = device.file_id();
                device.fs.insert(path, Entry::Folder { file_id });
            }
        }
        6 => {
            let Some(path) = pick(rng, &all) else { return };
            device.fs.retain(|p, _| !p.starts_with(&path));
        }
        _ => {
            // Rename or move a file or folder, never into itself.
            let Some(path) = pick(rng, &all) else { return };
            let Some(folder) = pick(rng, &folders) else {
                return;
            };
            let target = folder.join(random_name(rng));
            if !folder.starts_with(&path) && !device.fs.contains_key(&target) {
                move_subtree(&mut device.fs, &path, &target);
            }
        }
    }
}

fn check(a: &Device, b: &Device, server: &Server, survivors: &BTreeSet<u64>) {
    let remote = server.shape();
    let present: BTreeSet<u64> = remote.values().filter_map(|c| *c).collect();
    let lost: Vec<&u64> = survivors.iter().filter(|c| !present.contains(c)).collect();
    let converged = a.shape() == remote && b.shape() == remote;
    assert!(
        converged && lost.is_empty(),
        "check failed\n  lost: {lost:?}\n  A: {:?}\n  B: {:?}\n  server: {remote:?}\ntrace:\n{}",
        a.shape(),
        b.shape(),
        take_trace()
    );
}

fn run(seed: u64, cycles: usize, edits: usize) {
    let _ = take_trace();
    trace(format!("seed {seed}"));
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut server = Server::default();
    let mut a = Device::new(1, "conflict A");
    let mut b = Device::new(2, "conflict B");
    let mut next_content = 0;
    for _ in 0..cycles {
        for _ in 0..edits {
            edit(&mut a, &mut rng, &mut next_content);
            edit(&mut b, &mut rng, &mut next_content);
        }
        let mut survivors = a.own_contents();
        survivors.extend(b.own_contents());
        let mut quiet = false;
        for _ in 0..10 {
            let done_a = sync(&mut a, &mut server);
            let done_b = sync(&mut b, &mut server);
            if done_a == 0 && done_b == 0 {
                quiet = true;
                break;
            }
        }
        assert!(quiet, "devices did not settle");
        check(&a, &b, &server, &survivors);
    }
}

#[test]
fn a_single_device_uploads_everything() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let mut server = Server::default();
    let mut a = Device::new(1, "conflict A");
    let mut next = 0;
    for _ in 0..30 {
        edit(&mut a, &mut rng, &mut next);
    }
    sync(&mut a, &mut server);
    assert_eq!(a.shape(), server.shape());
    assert_eq!(
        sync(&mut a, &mut server),
        0,
        "a second sync has nothing to do"
    );
}

#[test]
fn fixed_seeds() {
    for seed in 0..200 {
        run(seed, 4, 6);
    }
}

/// Seeds that once failed, kept so they stay fixed (scenarios of 3 cycles × 8 edits).
const REGRESSIONS: [u64; 5] = [
    11_172_440_840_926_552_823,
    6_720_702_890_496_155_765,
    2_189_064_106_473_240_928,
    13_595_444_043_270_902_350,
    5_508_473_773_878_050_850,
];

#[test]
fn regression_seeds() {
    for seed in REGRESSIONS {
        run(seed, 3, 8);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn random_seeds(seed in any::<u64>()) {
        run(seed, 3, 8);
    }
}

/// Long scenarios; run explicitly (`cargo nextest run --run-ignored only`) or nightly.
#[test]
#[ignore = "long-running stress; nightly job"]
fn long_scenarios() {
    for seed in 0..2000 {
        run(seed, 6, 12);
    }
}
