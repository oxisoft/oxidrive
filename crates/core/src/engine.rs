//! The engine: one synced folder of one collection on one device (core executor §1).
//!
//! `sync_once` fetches and verifies new commits, scans the folder, reconciles, and executes
//! the plan. Execution follows the rules in core engine §8: local steps run when their
//! preconditions hold, in passes, with cycles broken through temporary names; the index is
//! updated only for completed steps; uploads are grouped into bounded commits appended with
//! compare-and-swap, and a lost race means fetching and planning again.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use oxisoft_drive_chunking::{
    ChunkKeys, ChunkParams, Chunker, object_epoch, open_chunk, seal_chunk,
};
use oxisoft_drive_crypto::CryptoRng;
use oxisoft_drive_crypto::hash::KeyedHasher;
use oxisoft_drive_crypto::sign::{SigningKey, VerifyingKey};
use oxisoft_drive_proto::api::{AppendResult, Head};
use oxisoft_drive_proto::{
    ChunkId, ChunkRef, CollectionId, Commit, CommitDraft, ContentHash, DeviceId, FileInfo,
    NODE_FORMAT, Name, NodeId, NodeKind, NodePayload, NodeRecord, RecordContext, Version,
};

use crate::error::EngineError;
use crate::model::{BaseEntry, BaseKind, RemoteKind, Stat};
use crate::path::RelPath;
use crate::plan::{Conflict, Pause, Plan, Skipped, Step};
use crate::reconcile::{MassDeleteBrake, Options, reconcile};
use crate::remote::{CollectionKeys, RemoteEntry, RemoteState};
use crate::scan::{marker_path, scan};
use crate::traits::{
    Clock, FileSystem, FsEntry, FsError, IndexState, IndexStore, IndexTxn, ServerApi,
};

/// How often a sync attempt fetches and plans again after losing a commit race.
const MAX_ATTEMPTS: usize = 8;
/// Largest number of records per commit (decision X2).
const MAX_RECORDS: usize = 1000;
/// Largest total size of sealed records per commit (decision X2).
const MAX_COMMIT_BYTES: usize = 1024 * 1024;
/// Bytes read per file request while chunking.
const READ_BLOCK: usize = 1024 * 1024;
/// Plaintext held before asking the server which chunks it lacks.
const UPLOAD_BATCH_BYTES: usize = 32 * 1024 * 1024;

/// Ignore rules: path and whether it is a folder.
pub type IgnoreRule = Box<dyn Fn(&RelPath, bool) -> bool + Send + Sync>;
/// The conflict tag for a moment (milliseconds since the Unix epoch).
pub type ConflictTag = Box<dyn Fn(u64) -> String + Send + Sync>;

/// Everything the engine needs to know besides its traits.
pub struct EngineConfig {
    /// The collection this folder syncs.
    pub collection: CollectionId,
    /// This device's signing key (commits).
    pub signing_key: SigningKey,
    /// The collection's keys.
    pub keys: CollectionKeys,
    /// Devices whose commits are trusted, by ID.
    pub trusted: BTreeMap<DeviceId, VerifyingKey>,
    /// Chunking parameters of the collection.
    pub chunk_params: ChunkParams,
    /// The conflict tag for a moment in time, e.g. `conflict 2026-09-29 14.30 laptop`.
    pub conflict_tag: ConflictTag,
    /// Ignore rules.
    pub is_ignored: IgnoreRule,
    /// The mass-delete brake.
    pub brake: MassDeleteBrake,
}

impl fmt::Debug for EngineConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineConfig")
            .field("collection", &self.collection)
            .field("keys", &self.keys)
            .field("trusted", &self.trusted.len())
            .field("chunk_params", &self.chunk_params)
            .field("brake", &self.brake)
            .finish_non_exhaustive()
    }
}

/// What one sync did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Steps planned in the last attempt.
    pub planned: usize,
    /// Conflicts resolved by keeping both.
    pub conflicts: Vec<Conflict>,
    /// Remote nodes skipped on this device.
    pub skipped: Vec<Skipped>,
    /// Local names that can't be synced.
    pub unrepresentable: Vec<String>,
    /// Set when nothing was done because the user must act.
    pub paused: Option<Pause>,
    /// Local steps that couldn't run and wait for the next sync.
    pub deferred: usize,
    /// Commits appended.
    pub commits: usize,
    /// Races lost to other devices before succeeding.
    pub retries: usize,
}

/// A record prepared for a commit, sealed per batch.
struct Pending {
    node: NodeId,
    payload: NodePayload,
    /// The index entry once committed (`None` for a deletion).
    base: Option<BaseEntry>,
}

/// Mutable bookkeeping while one plan executes.
struct Run {
    /// Where each node is now.
    locations: BTreeMap<NodeId, RelPath>,
    /// Moves performed, in order, for translating paths of new entries.
    moves: Vec<(RelPath, RelPath)>,
}

enum StepOutcome {
    Done(IndexTxn),
    Blocked,
    Skipped,
}

/// The sync engine for one folder.
pub struct Engine<F, S, I, C, R> {
    fs: F,
    server: S,
    index: I,
    clock: C,
    rng: R,
    config: EngineConfig,
    state: IndexState,
    remote: RemoteState,
}

impl<F, S, I, C, R> fmt::Debug for Engine<F, S, I, C, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("config", &self.config)
            .field("head", &self.state.head)
            .field("nodes", &self.state.base.len())
            .finish_non_exhaustive()
    }
}

impl<F, S, I, C, R> Engine<F, S, I, C, R>
where
    F: FileSystem,
    S: ServerApi,
    I: IndexStore,
    C: Clock,
    R: CryptoRng + Send,
{
    /// Opens the engine on an existing (possibly empty) index.
    ///
    /// # Errors
    ///
    /// If the index can't be loaded.
    pub async fn open(
        fs: F,
        server: S,
        index: I,
        clock: C,
        rng: R,
        config: EngineConfig,
    ) -> Result<Self, EngineError> {
        let state = index.load().await?;
        let remote = RemoteState {
            head: state.head,
            entries: state.remote.clone(),
        };
        Ok(Self {
            fs,
            server,
            index,
            clock,
            rng,
            config,
            state,
            remote,
        })
    }

    /// The last synced state (for inspection and tests).
    #[must_use]
    pub const fn state(&self) -> &IndexState {
        &self.state
    }

    /// Makes the folder a synced folder: creates `.oxidrive/` and its marker.
    ///
    /// # Errors
    ///
    /// File system failures.
    pub async fn init_folder(&self) -> Result<(), EngineError> {
        let marker = marker_path();
        if self.fs.stat(&marker).await?.is_some() {
            return Ok(());
        }
        let engine_dir = marker.parent().unwrap_or_default();
        if self.fs.stat(&engine_dir).await?.is_none() {
            self.fs.create_dir(&engine_dir).await?;
        }
        let temp = self.fs.create_temp().await?;
        self.fs.append_temp(temp, b"oxidrive\n").await?;
        let now = i64::try_from(self.clock.now_ms()).unwrap_or(i64::MAX);
        self.fs.commit_temp(temp, &marker, None, now, false).await?;
        Ok(())
    }

    /// One sync: fetch, scan, reconcile, execute, retrying lost commit races.
    ///
    /// # Errors
    ///
    /// Any failure of the traits or of verification. The index stays consistent: completed
    /// steps are recorded, the rest is planned again next time.
    pub async fn sync_once(&mut self, allow_mass_delete: bool) -> Result<SyncReport, EngineError> {
        let mut report = SyncReport::default();
        for attempt in 0..MAX_ATTEMPTS {
            report.retries = attempt;
            let txn = self
                .remote
                .refresh(
                    &self.server,
                    self.config.collection,
                    &self.config.keys,
                    &self.config.trusted,
                )
                .await?;
            self.commit_index(txn).await?;

            let marker_present = self.fs.stat(&marker_path()).await?.is_some();
            let id_key = self.config.keys.current().id();
            let scanned = scan(&self.fs, &self.state.base, &id_key).await?;
            report.unrepresentable = scanned.unrepresentable;
            let tag = (self.config.conflict_tag)(self.clock.now_ms());
            let is_ignored = |path: &RelPath, folder: bool| (self.config.is_ignored)(path, folder);
            let options = Options {
                marker_present,
                allow_mass_delete,
                brake: self.config.brake,
                fs: self.fs.rules(),
                conflict_tag: &tag,
                is_ignored: &is_ignored,
            };
            let plan = reconcile(
                &self.state.base,
                &scanned.local,
                &self.remote.tree(),
                &options,
            );
            report.planned = plan.steps.len();
            report.conflicts = plan.conflicts.clone();
            report.skipped = plan.skipped.clone();
            report.paused = plan.paused;
            if plan.paused.is_some() {
                return Ok(report);
            }
            if self.execute(&plan, &mut report).await? {
                return Ok(report);
            }
        }
        Err(EngineError::TooManyRetries)
    }

    /// Stores a transaction in the index, then mirrors it in memory.
    async fn commit_index(&mut self, txn: IndexTxn) -> Result<(), EngineError> {
        if txn.is_empty() {
            return Ok(());
        }
        self.index.apply(txn.clone()).await?;
        txn.apply_to(&mut self.state);
        Ok(())
    }

    /// Executes a plan. Returns `false` if a commit lost a race (plan again).
    async fn execute(&mut self, plan: &Plan, report: &mut SyncReport) -> Result<bool, EngineError> {
        let mut run = Run {
            locations: plan.located.clone(),
            moves: Vec::new(),
        };
        let (local, uploads): (Vec<&Step>, Vec<&Step>) = plan.steps.iter().partition(|step| {
            !matches!(
                step,
                Step::UploadNew { .. } | Step::UploadChange { .. } | Step::UploadDelete { .. }
            )
        });
        report.deferred = self.run_local(&local, &mut run).await?;
        let pending = self.prepare_uploads(&uploads, &mut run).await?;
        self.commit_uploads(pending, report).await
    }

    // ── local steps ────────────────────────────────────────────────────────────────

    /// Runs local steps in passes until none can progress. Returns how many are deferred.
    async fn run_local(&mut self, steps: &[&Step], run: &mut Run) -> Result<usize, EngineError> {
        let mut pending: Vec<&Step> = steps.to_vec();
        while !pending.is_empty() {
            let mut blocked = Vec::new();
            let mut progressed = false;
            for step in pending {
                match self.local_step(step, run).await? {
                    StepOutcome::Done(txn) => {
                        self.commit_index(txn).await?;
                        progressed = true;
                    }
                    StepOutcome::Skipped => progressed = true,
                    StepOutcome::Blocked => blocked.push(step),
                }
            }
            if blocked.is_empty() {
                return Ok(0);
            }
            if !progressed && !self.break_cycle(&blocked, run).await? {
                return Ok(blocked.len());
            }
            pending = blocked;
        }
        Ok(0)
    }

    fn remote_entry(&self, node: NodeId) -> Option<&RemoteEntry> {
        self.remote.entries.get(&node)
    }

    /// Where a node goes locally: under its remote parent's current location. `None` while
    /// the parent isn't there yet.
    async fn placed_path(&self, node: NodeId, run: &Run) -> Result<Option<RelPath>, EngineError> {
        let Some(entry) = self.remote_entry(node) else {
            return Ok(None);
        };
        let parent = match entry.node.parent {
            None => RelPath::root(),
            Some(parent) => {
                let Some(path) = run.locations.get(&parent) else {
                    return Ok(None);
                };
                if !matches!(self.fs.stat(path).await?, Some(FsEntry::Folder { .. })) {
                    return Ok(None);
                }
                path.clone()
            }
        };
        Ok(Some(parent.join(entry.node.name.clone())))
    }

    fn owner_of(run: &Run, path: &RelPath) -> Option<NodeId> {
        run.locations
            .iter()
            .find(|(_, location)| *location == path)
            .map(|(node, _)| *node)
    }

    /// Moves `from` (and everything below) to `to`, keeping locations and the index in step.
    async fn relocate(
        &mut self,
        from: &RelPath,
        to: &RelPath,
        run: &mut Run,
    ) -> Result<IndexTxn, EngineError> {
        self.fs.rename(from, to).await?;
        let moved = [(from.clone(), to.clone())];
        for path in run.locations.values_mut() {
            *path = carry(path, &moved);
        }
        run.moves.push((from.clone(), to.clone()));
        let mut txn = IndexTxn::default();
        for (node, entry) in &self.state.base {
            if entry.path.starts_with(from) {
                txn.put.push((
                    *node,
                    BaseEntry {
                        path: carry(&entry.path, &moved),
                        ..entry.clone()
                    },
                ));
            }
        }
        Ok(txn)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one match arm per step kind; splitting it would scatter the step rules"
    )]
    async fn local_step(&mut self, step: &Step, run: &mut Run) -> Result<StepOutcome, EngineError> {
        match step {
            Step::SetAside { from, to } => {
                let target = from.with_name(to.clone());
                match self.relocate(from, &target, run).await {
                    Ok(txn) => Ok(StepOutcome::Done(txn)),
                    Err(EngineError::Fs(FsError::NotFound | FsError::AlreadyExists)) => {
                        Ok(StepOutcome::Skipped)
                    }
                    Err(error) => Err(error),
                }
            }
            Step::Bind { path, node } => {
                run.locations.insert(*node, path.clone());
                Ok(self
                    .record_local(*node, path)
                    .await?
                    .map_or(StepOutcome::Skipped, StepOutcome::Done))
            }
            Step::CreateLocalFolder { node } => {
                let Some(path) = self.placed_path(*node, run).await? else {
                    return Ok(StepOutcome::Blocked);
                };
                if Self::owner_of(run, &path).is_some_and(|owner| owner != *node) {
                    return Ok(StepOutcome::Blocked);
                }
                match self.fs.stat(&path).await? {
                    Some(FsEntry::Folder { .. }) => {}
                    Some(FsEntry::File(_)) => return Ok(StepOutcome::Blocked),
                    None => {
                        self.fs.create_dir(&path).await?;
                    }
                }
                run.locations.insert(*node, path.clone());
                Ok(self
                    .record_local(*node, &path)
                    .await?
                    .map_or(StepOutcome::Skipped, StepOutcome::Done))
            }
            Step::MoveLocal { node } => {
                let Some(from) = run.locations.get(node).cloned() else {
                    return Ok(StepOutcome::Skipped);
                };
                let Some(to) = self.placed_path(*node, run).await? else {
                    return Ok(StepOutcome::Blocked);
                };
                if from != to {
                    // On a case-insensitive file system, `to` may be `from` in another case.
                    let same_entry =
                        self.fs.rules().case_insensitive && to.fold_case() == from.fold_case();
                    if to.starts_with(&from) || (!same_entry && self.fs.stat(&to).await?.is_some())
                    {
                        return Ok(StepOutcome::Blocked);
                    }
                    let txn = match self.relocate(&from, &to, run).await {
                        Ok(txn) => txn,
                        Err(EngineError::Fs(FsError::NotFound)) => return Ok(StepOutcome::Skipped),
                        Err(EngineError::Fs(FsError::AlreadyExists)) => {
                            return Ok(StepOutcome::Blocked);
                        }
                        Err(error) => return Err(error),
                    };
                    self.commit_index(txn).await?;
                }
                // The node is now where the remote side has it: adopt that version.
                Ok(self
                    .record_local(*node, &to)
                    .await?
                    .map_or(StepOutcome::Skipped, StepOutcome::Done))
            }
            Step::Download { node } => self.download(*node, run).await,
            Step::DeleteLocal { node } => {
                let Some(path) = run.locations.get(node).cloned() else {
                    return Ok(StepOutcome::Skipped);
                };
                let result = match self.state.base.get(node).map(|entry| entry.kind.clone()) {
                    Some(BaseKind::File { stat, .. }) => self.fs.remove_file(&path, stat).await,
                    _ => self.fs.remove_dir(&path).await,
                };
                match result {
                    Ok(()) | Err(FsError::NotFound) => {
                        run.locations.remove(node);
                        Ok(StepOutcome::Done(IndexTxn {
                            remove: vec![*node],
                            ..IndexTxn::default()
                        }))
                    }
                    Err(FsError::NotEmpty) => Ok(StepOutcome::Blocked),
                    // Edited meanwhile: keep it; the next sync uploads it (an edit wins).
                    Err(FsError::Changed) => Ok(StepOutcome::Skipped),
                    Err(error) => Err(error.into()),
                }
            }
            Step::Adopt { node } => {
                let Some(path) = run.locations.get(node).cloned() else {
                    return Ok(StepOutcome::Skipped);
                };
                Ok(self
                    .record_local(*node, &path)
                    .await?
                    .map_or(StepOutcome::Skipped, StepOutcome::Done))
            }
            Step::Forget { node } => {
                run.locations.remove(node);
                Ok(StepOutcome::Done(IndexTxn {
                    remove: vec![*node],
                    ..IndexTxn::default()
                }))
            }
            Step::UploadNew { .. } | Step::UploadChange { .. } | Step::UploadDelete { .. } => {
                Ok(StepOutcome::Skipped)
            }
        }
    }

    /// The index entry saying `node` is synced at `path` with its current remote version.
    async fn record_local(
        &self,
        node: NodeId,
        path: &RelPath,
    ) -> Result<Option<IndexTxn>, EngineError> {
        let Some(remote) = self.remote_entry(node) else {
            return Ok(None);
        };
        let kind = match (self.fs.stat(path).await?, &remote.node.kind) {
            (Some(FsEntry::File(stat)), RemoteKind::File { content, .. }) => BaseKind::File {
                stat,
                content: *content,
            },
            (Some(FsEntry::Folder { file_id }), RemoteKind::Folder | RemoteKind::Deleted) => {
                BaseKind::Folder { file_id }
            }
            _ => return Ok(None),
        };
        Ok(Some(IndexTxn {
            put: vec![(
                node,
                BaseEntry {
                    path: path.clone(),
                    kind,
                    version: remote.node.version,
                },
            )],
            ..IndexTxn::default()
        }))
    }

    /// Unblocks steps waiting on each other: moves an entry that is itself waiting to move out
    /// of a blocked target to a temporary name, or stages a blocked moving node at the root.
    /// Temporary names are ordinary entries (not ignored) and recorded in the index, so a
    /// crash leaves nothing unaccounted for.
    async fn break_cycle(&mut self, blocked: &[&Step], run: &mut Run) -> Result<bool, EngineError> {
        let moving: BTreeSet<NodeId> = blocked
            .iter()
            .filter_map(|step| match step {
                Step::MoveLocal { node } => Some(*node),
                _ => None,
            })
            .collect();
        for step in blocked {
            let node = match step {
                Step::MoveLocal { node }
                | Step::CreateLocalFolder { node }
                | Step::Download { node } => *node,
                _ => continue,
            };
            let Some(target) = self.placed_path(node, run).await? else {
                continue;
            };
            let occupant = Self::owner_of(run, &target)
                .filter(|other| *other != node && moving.contains(other));
            if let Some(occupant) = occupant {
                let temporary = target.with_name(temporary_name("tmp", occupant));
                let txn = self.relocate(&target, &temporary, run).await?;
                self.commit_index(txn).await?;
                return Ok(true);
            }
        }
        for node in moving {
            let Some(from) = run.locations.get(&node).cloned() else {
                continue;
            };
            let staged = RelPath::root().join(temporary_name("stage", node));
            if from != staged && self.fs.stat(&staged).await?.is_none() {
                let txn = self.relocate(&from, &staged, run).await?;
                self.commit_index(txn).await?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ── downloads ──────────────────────────────────────────────────────────────────

    async fn download(&mut self, node: NodeId, run: &mut Run) -> Result<StepOutcome, EngineError> {
        let Some(remote) = self.remote_entry(node).cloned() else {
            return Ok(StepOutcome::Skipped);
        };
        let (Some(meta), RemoteKind::File { content, .. }) = (&remote.file, &remote.node.kind)
        else {
            return Ok(StepOutcome::Skipped);
        };
        let own = match run.locations.get(&node) {
            Some(path) if self.fs.stat(path).await?.is_some() => Some(path.clone()),
            _ => None,
        };
        let (target, expected) = if let Some(path) = own {
            let expected = match self.state.base.get(&node).map(|entry| &entry.kind) {
                Some(BaseKind::File { stat, .. }) => Some(*stat),
                _ => return Ok(StepOutcome::Blocked),
            };
            (path, expected)
        } else {
            let Some(path) = self.placed_path(node, run).await? else {
                return Ok(StepOutcome::Blocked);
            };
            if self.fs.stat(&path).await?.is_some() {
                return Ok(StepOutcome::Blocked);
            }
            (path, None)
        };

        let key = self.config.keys.get(meta.epoch)?;
        let chunk_keys = ChunkKeys::new(key);
        let mut hasher = KeyedHasher::new(&key.id());
        let temp = self.fs.create_temp().await?;
        for chunk in &meta.chunks {
            let object = self
                .server
                .get_chunk(self.config.collection, chunk.id)
                .await?;
            if object_epoch(&object)? != meta.epoch {
                self.fs.discard_temp(temp).await?;
                return Err(EngineError::ContentMismatch);
            }
            let plaintext = open_chunk(
                &chunk_keys,
                self.config.collection.as_bytes(),
                &chunk.id.0,
                &object,
            )?;
            hasher.update(&plaintext);
            self.fs.append_temp(temp, &plaintext).await?;
        }
        if ContentHash(hasher.finalize()) != *content {
            self.fs.discard_temp(temp).await?;
            return Err(EngineError::ContentMismatch);
        }
        let stat = match self
            .fs
            .commit_temp(temp, &target, expected, meta.mtime_ms, meta.executable)
            .await
        {
            Ok(stat) => stat,
            Err(FsError::Changed | FsError::AlreadyExists) => {
                // Edited or created meanwhile: keep it; the next sync resolves it.
                self.fs.discard_temp(temp).await?;
                return Ok(StepOutcome::Skipped);
            }
            Err(error) => return Err(error.into()),
        };
        run.locations.insert(node, target.clone());
        Ok(StepOutcome::Done(IndexTxn {
            put: vec![(
                node,
                BaseEntry {
                    path: target,
                    kind: BaseKind::File {
                        stat,
                        content: *content,
                    },
                    version: remote.node.version,
                },
            )],
            ..IndexTxn::default()
        }))
    }

    // ── uploads ────────────────────────────────────────────────────────────────────

    fn next_version(&mut self) -> Version {
        self.state.counter += 1;
        Version {
            device: DeviceId::from_key(&self.config.signing_key.verifying_key()),
            counter: self.state.counter,
        }
    }

    /// The parent of a local path as a node (`None` for the root); `Err` if the parent
    /// folder isn't a node (its own upload didn't happen).
    fn parent_node(run: &Run, path: &RelPath) -> Result<Option<NodeId>, ()> {
        match path.parent() {
            Some(parent) if !parent.is_root() => Self::owner_of(run, &parent).map(Some).ok_or(()),
            _ => Ok(None),
        }
    }

    /// Builds the records of the plan's upload steps, uploading file contents on the way.
    async fn prepare_uploads(
        &mut self,
        steps: &[&Step],
        run: &mut Run,
    ) -> Result<Vec<Pending>, EngineError> {
        let mut pending = Vec::new();
        for step in steps {
            let (node, path, base) = match step {
                Step::UploadNew { path, .. } => {
                    let node = NodeId::random(&mut self.rng);
                    (node, carry(path, &run.moves), None)
                }
                Step::UploadChange { node, .. } => {
                    let Some(path) = run.locations.get(node).cloned() else {
                        continue;
                    };
                    let base = self
                        .state
                        .base
                        .get(node)
                        .map(|entry| entry.version)
                        .or_else(|| self.remote_entry(*node).map(|entry| entry.node.version));
                    (*node, path, base)
                }
                Step::UploadDelete { node } => {
                    if let Some(record) = self.deletion(*node) {
                        pending.push(record);
                    }
                    continue;
                }
                _ => continue,
            };
            let Ok(parent) = Self::parent_node(run, &path) else {
                continue;
            };
            let Some(name) = path.name().cloned() else {
                continue;
            };
            let (kind, base_kind) = match self.fs.stat(&path).await? {
                Some(FsEntry::Folder { file_id }) => {
                    (NodeKind::Folder, BaseKind::Folder { file_id })
                }
                Some(FsEntry::File(stat)) => match self.upload_content(&path, stat).await? {
                    Some((info, stat)) => {
                        let content = info.content_hash;
                        (NodeKind::File(info), BaseKind::File { stat, content })
                    }
                    None => continue,
                },
                None => continue,
            };
            let version = self.next_version();
            run.locations.insert(node, path.clone());
            pending.push(Pending {
                node,
                payload: NodePayload {
                    format: NODE_FORMAT,
                    parent,
                    name,
                    kind,
                    version,
                    base,
                },
                base: Some(BaseEntry {
                    path,
                    kind: base_kind,
                    version,
                }),
            });
        }
        Ok(pending)
    }

    /// The tombstone record for a node deleted locally.
    fn deletion(&mut self, node: NodeId) -> Option<Pending> {
        let remote = self.remote_entry(node)?.node.clone();
        let version = self.next_version();
        Some(Pending {
            node,
            payload: NodePayload {
                format: NODE_FORMAT,
                parent: remote.parent,
                name: remote.name,
                kind: NodeKind::Deleted,
                version,
                base: Some(remote.version),
            },
            base: None,
        })
    }

    /// Chunks a file, uploads the chunks the server lacks, and describes the file. `None` if
    /// the file changed while it was read (it is uploaded next time).
    async fn upload_content(
        &mut self,
        path: &RelPath,
        stat: Stat,
    ) -> Result<Option<(FileInfo, Stat)>, EngineError> {
        let key = self.config.keys.current();
        let chunker = Chunker::new(&key.chunking(), self.config.chunk_params);
        let chunk_keys = ChunkKeys::new(key);
        let mut hasher = KeyedHasher::new(&key.id());
        let mut chunks = Vec::new();
        let mut batch: Vec<(ChunkId, Vec<u8>)> = Vec::new();
        let mut batch_bytes = 0;
        let mut buffer = Vec::new();
        let mut offset = 0;
        let mut eof = false;
        loop {
            while !eof && buffer.len() < chunker.params().max() as usize {
                let block = match self.fs.read(path, offset, READ_BLOCK).await {
                    Ok(block) => block,
                    Err(FsError::NotFound) => return Ok(None),
                    Err(error) => return Err(error.into()),
                };
                offset += block.len() as u64;
                eof = block.len() < READ_BLOCK;
                buffer.extend_from_slice(&block);
            }
            let Some(cut) = chunker.next_cut(&buffer, eof) else {
                break;
            };
            let chunk: Vec<u8> = buffer.drain(..cut).collect();
            let id = ChunkId(chunk_keys.chunk_id(&chunk));
            hasher.update(&chunk);
            chunks.push(ChunkRef {
                id,
                len: u32::try_from(chunk.len()).unwrap_or(u32::MAX),
            });
            batch_bytes += chunk.len();
            batch.push((id, chunk));
            if batch_bytes >= UPLOAD_BATCH_BYTES {
                self.flush_chunks(&chunk_keys, std::mem::take(&mut batch))
                    .await?;
                batch_bytes = 0;
            }
        }
        self.flush_chunks(&chunk_keys, batch).await?;
        let Some(FsEntry::File(after)) = self.fs.stat(path).await? else {
            return Ok(None);
        };
        if after.size != stat.size || after.mtime_ms != stat.mtime_ms || offset != stat.size {
            return Ok(None);
        }
        Ok(Some((
            FileInfo {
                size: stat.size,
                mtime_ms: stat.mtime_ms,
                executable: stat.executable,
                content_hash: ContentHash(hasher.finalize()),
                chunks,
            },
            after,
        )))
    }

    /// Uploads the chunks of `batch` the server doesn't have.
    async fn flush_chunks(
        &mut self,
        keys: &ChunkKeys,
        batch: Vec<(ChunkId, Vec<u8>)>,
    ) -> Result<(), EngineError> {
        if batch.is_empty() {
            return Ok(());
        }
        let ids: Vec<ChunkId> = batch.iter().map(|(id, _)| *id).collect();
        let missing = self.server.missing(self.config.collection, ids).await?;
        let wanted: BTreeSet<[u8; 32]> = missing.ids.iter().map(|id| *id.0.as_bytes()).collect();
        let mut sent = BTreeSet::new();
        for (id, data) in batch {
            if wanted.contains(id.0.as_bytes()) && sent.insert(*id.0.as_bytes()) {
                let sealed = seal_chunk(
                    keys,
                    &mut self.rng,
                    self.config.collection.as_bytes(),
                    &data,
                )?;
                self.server
                    .put_chunk(self.config.collection, missing.lease, id, sealed.object)
                    .await?;
            }
        }
        Ok(())
    }

    /// Appends the prepared records in bounded commits. Returns `false` if a commit lost the
    /// race: nothing of it is recorded, and the caller plans again.
    async fn commit_uploads(
        &mut self,
        pending: Vec<Pending>,
        report: &mut SyncReport,
    ) -> Result<bool, EngineError> {
        let mut rest = pending.as_slice();
        while !rest.is_empty() {
            let epoch = self.config.keys.current().epoch();
            let meta = self.config.keys.current().meta();
            let head = self.remote.head;
            let seq = head.map_or(1, |head| head.seq + 1);
            let context = RecordContext {
                collection: self.config.collection,
                seq,
                epoch,
            };
            let mut records = Vec::new();
            let mut bytes = 0;
            let mut taken = 0;
            for item in rest {
                let record =
                    NodeRecord::seal(item.node, &item.payload, &meta, &mut self.rng, &context)?;
                if !records.is_empty()
                    && (records.len() >= MAX_RECORDS
                        || bytes + record.sealed.len() > MAX_COMMIT_BYTES)
                {
                    break;
                }
                bytes += record.sealed.len();
                records.push(record);
                taken += 1;
            }
            let (batch, remaining) = rest.split_at(taken);
            let commit = Commit::create(
                &self.config.signing_key,
                &CommitDraft {
                    collection: self.config.collection,
                    seq,
                    prev: head.map(|head| head.hash),
                    epoch,
                    time_ms: self.clock.now_ms(),
                },
                &records,
            );
            let new_head = Head {
                seq,
                hash: commit.hash(),
            };
            match self
                .server
                .append(self.config.collection, head, commit)
                .await?
            {
                AppendResult::Appended(appended) if appended == new_head => {}
                AppendResult::Appended(_) | AppendResult::Conflict(_) => return Ok(false),
            }
            let mut txn = IndexTxn {
                head: Some(new_head),
                counter: Some(self.state.counter),
                ..IndexTxn::default()
            };
            for item in batch {
                let entry = RemoteEntry::from_payload(&item.payload, epoch);
                self.remote.apply(item.node, entry.clone());
                txn.remote.push((item.node, entry));
                match &item.base {
                    Some(base) => txn.put.push((item.node, base.clone())),
                    None => txn.remove.push(item.node),
                }
            }
            self.remote.head = Some(new_head);
            self.commit_index(txn).await?;
            report.commits += 1;
            rest = remaining;
        }
        Ok(true)
    }
}

/// A temporary name for moving an entry out of the way (cycle breaking). Always a valid
/// name: a fixed prefix and the node ID in hex.
fn temporary_name(kind: &str, node: NodeId) -> Name {
    let hex: String = node.as_bytes().iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    });
    Name::new(&format!(".oxidrive-{kind}-{hex}"))
        .unwrap_or_else(|_| unreachable!("prefix and hex digits form a valid name"))
}

/// `path` after the moves (in order), for paths below a moved entry.
fn carry(path: &RelPath, moves: &[(RelPath, RelPath)]) -> RelPath {
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
