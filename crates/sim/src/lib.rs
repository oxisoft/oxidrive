//! The deterministic simulator (docs `simulator.md`): 2–4 devices share one collection
//! through long random timelines of user edits, syncs in random order, syncs interrupted by
//! another device's sync or by the user, injected failures, crashes, clock jumps and offline
//! stretches. A run is reproducible from its seed alone.
//!
//! A run is a series of epochs. Each epoch is a number of random actions, then every device
//! syncs until nothing is left to do, and the invariants are checked:
//!
//! 1. **Convergence:** every device holds the same tree, and a brand-new device syncing from
//!    scratch gets it too, which also verifies the whole commit chain.
//! 2. **No data loss:** every content a user wrote survives, unless a user removed it or a
//!    clean sync had taken it to the server before (after which deleting it is legitimate).
//! 3. **No foreign content:** every file holds something a user wrote.
//! 4. **Nothing stuck:** nothing is deferred once devices are quiet, and no temporary or
//!    staging names are left behind.
//!
//! After every sync, the device's view of the remote tree must also never hold two live
//! entries at the same place: honest devices don't commit such a tree.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oxisoft_drive_core::ServerApi;
use oxisoft_drive_core::{FileSystem, FsError, FsRules, RelPath, RemoteKind, SyncReport};
use oxisoft_drive_proto::{Name, NodeId};
use oxisoft_drive_testkit::{
    Device, MemFs, MemServer, ServerFailure, ServiceServer, Tree, World, contents,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

/// How long a run is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Epochs, each ending with all devices syncing until quiet and the invariant checks.
    pub epochs: usize,
    /// Random actions per epoch.
    pub ticks: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            epochs: 4,
            ticks: 60,
        }
    }
}

/// What a run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Devices in the world (drawn from the seed).
    pub devices: usize,
    /// Whether the file systems ignore case (drawn from the seed).
    pub case_insensitive: bool,
    /// User edits.
    pub edits: usize,
    /// Syncs that ran without injected failures.
    pub syncs: usize,
    /// Syncs interrupted by another device's sync or a user edit.
    pub interleavings: usize,
    /// Syncs with an injected failure.
    pub faults: usize,
    /// Crash-restarts.
    pub crashes: usize,
    /// Commits appended.
    pub commits: usize,
    /// Commit races lost and retried.
    pub retries: usize,
    /// Conflicts resolved by keeping both versions.
    pub conflicts: usize,
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} devices{}, {} edits, {} syncs, {} interleaved, {} faults, {} crashes, \
             {} commits, {} retries, {} conflicts",
            self.devices,
            if self.case_insensitive {
                " (case-insensitive)"
            } else {
                ""
            },
            self.edits,
            self.syncs,
            self.interleavings,
            self.faults,
            self.crashes,
            self.commits,
            self.retries,
            self.conflicts
        )
    }
}

/// A failed run: what broke, when, and everything that happened before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The seed that reproduces it.
    pub seed: u64,
    /// The run's length.
    pub config: Config,
    /// The action it failed at (0 before the first).
    pub tick: usize,
    /// What went wrong.
    pub message: String,
    /// Every action so far, one line each.
    pub trace: Vec<String>,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "simulation seed {} failed at tick {}: {}",
            self.seed, self.tick, self.message
        )?;
        writeln!(
            f,
            "replay: cargo xtask sim --seed {} --epochs {} --ticks {}",
            self.seed, self.config.epochs, self.config.ticks
        )?;
        for line in &self.trace {
            writeln!(f, "  {line}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Failure {}

/// Which server the devices sync with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend<'a> {
    /// The in-memory test server (fastest; the default).
    Memory,
    /// The real server's rules on SQLite.
    Sqlite,
    /// The real server's rules on PostgreSQL: a new database on the server at this URL.
    Postgres(&'a str),
}

/// Runs one simulation on the in-memory server.
///
/// # Errors
///
/// The first broken invariant or unexpected error, with the trace leading up to it. A panic
/// inside the engine is reported the same way, without a trace.
pub fn run(seed: u64, config: Config) -> Result<Summary, Failure> {
    run_on(seed, config, Backend::Memory)
}

/// Runs one simulation on the given server.
///
/// # Errors
///
/// As [`run`], and if the server can't be set up.
pub fn run_on(seed: u64, config: Config, backend: Backend<'_>) -> Result<Summary, Failure> {
    match backend {
        Backend::Memory => guarded(seed, config, |_| Ok(MemServer::new())),
        Backend::Sqlite => guarded(seed, config, |trusted| {
            ServiceServer::sqlite(trusted).map_err(|error| error.to_string())
        }),
        Backend::Postgres(url) => guarded(seed, config, |trusted| {
            ServiceServer::postgres(url, trusted).map_err(|error| error.to_string())
        }),
    }
}

/// Runs a simulation, turning a panic into a [`Failure`].
fn guarded<S: ServerApi + 'static>(
    seed: u64,
    config: Config,
    server: impl FnOnce(usize) -> Result<S, String>,
) -> Result<Summary, Failure> {
    panic::catch_unwind(AssertUnwindSafe(|| Sim::new(seed, config, server)?.run())).unwrap_or_else(
        |payload| {
            let message = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    payload
                        .downcast_ref::<&str>()
                        .map(|text| (*text).to_owned())
                })
                .unwrap_or_default();
            Err(Failure {
                seed,
                config,
                tick: 0,
                message: format!("panicked: {message}"),
                trace: Vec::new(),
            })
        },
    )
}

type Shared<S> = Arc<Mutex<Device<S>>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A user edit and the contents it added and removed.
#[derive(Debug, Default)]
struct Edit {
    description: String,
    added: BTreeSet<Vec<u8>>,
    removed: BTreeSet<Vec<u8>>,
}

/// What happened inside an interleaving hook.
#[derive(Debug)]
struct Interleaved {
    edit: Option<Edit>,
    sync: Option<Result<SyncReport, String>>,
    counter: u64,
}

struct Sim<S> {
    seed: u64,
    config: Config,
    world: World<S>,
    rng: ChaCha20Rng,
    devices: Vec<Shared<S>>,
    /// The tick until which each device is offline.
    offline_until: Vec<usize>,
    tick: usize,
    /// Numbers every written content, so each is unique.
    counter: u64,
    /// Every content a user ever wrote.
    written: BTreeSet<Vec<u8>>,
    /// Contents that must survive: written, not removed by a user, not yet taken to the
    /// server by a clean sync.
    dirty: BTreeSet<Vec<u8>>,
    trace: Vec<String>,
    summary: Summary,
}

impl<S: ServerApi + 'static> Sim<S> {
    /// A world of 2–4 devices (drawn from the seed) on the server `server` makes for that
    /// many trusted devices.
    fn new(
        seed: u64,
        config: Config,
        server: impl FnOnce(usize) -> Result<S, String>,
    ) -> Result<Self, Failure> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let count = 2 + usize::try_from(rng.next_u64() % 3).unwrap_or(0);
        let rules = FsRules {
            case_insensitive: rng.next_u64() % 2 == 1,
            windows_names: false,
        };
        let server = server(count - 1).map_err(|message| Failure {
            seed,
            config,
            tick: 0,
            message: format!("server setup: {message}"),
            trace: Vec::new(),
        })?;
        let mut sim = Self {
            seed,
            config,
            // Devices 0..count commit; the fresh device checking convergence doesn't.
            world: World::with_server(rules, count - 1, server),
            rng,
            devices: Vec::new(),
            offline_until: vec![0; count],
            tick: 0,
            counter: 0,
            written: BTreeSet::new(),
            dirty: BTreeSet::new(),
            trace: Vec::new(),
            summary: Summary {
                devices: count,
                case_insensitive: rules.case_insensitive,
                ..Summary::default()
            },
        };
        for number in 0..count {
            let device = sim
                .world
                .device(number)
                .map_err(|error| sim.fail(format!("device {number} didn't start: {error}")))?;
            sim.devices.push(Arc::new(Mutex::new(device)));
        }
        Ok(sim)
    }

    fn run(mut self) -> Result<Summary, Failure> {
        for epoch in 0..self.config.epochs {
            for _ in 0..self.config.ticks {
                self.tick += 1;
                self.step()?;
            }
            self.settle(epoch)?;
        }
        Ok(self.summary)
    }

    fn fail(&self, message: impl Into<String>) -> Failure {
        Failure {
            seed: self.seed,
            config: self.config,
            tick: self.tick,
            message: message.into(),
            trace: self.trace.clone(),
        }
    }

    fn log(&mut self, line: impl fmt::Display) {
        self.trace.push(format!("t{} {line}", self.tick));
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.rng.next_u64() % bound
    }

    fn below_usize(&mut self, bound: usize) -> usize {
        usize::try_from(self.below(bound as u64)).unwrap_or(0)
    }

    fn online(&self) -> Vec<usize> {
        (0..self.devices.len())
            .filter(|&d| self.offline_until[d] <= self.tick)
            .collect()
    }

    fn online_device(&mut self) -> Option<usize> {
        let online = self.online();
        if online.is_empty() {
            return None;
        }
        let index = self.below_usize(online.len());
        Some(online[index])
    }

    fn fs(&self, d: usize) -> Arc<MemFs> {
        Arc::clone(&lock(&self.devices[d]).fs)
    }

    fn step(&mut self) -> Result<(), Failure> {
        let elapsed = 1 + self.below(5_000);
        self.world.clock.advance(elapsed);
        match self.below(100) {
            0..35 => {
                self.user_edit();
                Ok(())
            }
            35..60 => self.sync(),
            60..72 => self.interleaved_sync(),
            72..82 => self.faulty_sync(),
            82..88 => {
                let d = self.below_usize(self.devices.len());
                self.crash(d)
            }
            88..94 => {
                self.clock_jump();
                Ok(())
            }
            _ => {
                self.go_offline();
                Ok(())
            }
        }
    }

    fn record_edit(&mut self, d: usize, edit: &Edit) {
        self.summary.edits += 1;
        self.log(format_args!("d{d} user: {}", edit.description));
        self.written.extend(edit.added.iter().cloned());
        self.dirty.extend(edit.added.iter().cloned());
        for content in &edit.removed {
            self.dirty.remove(content);
        }
    }

    fn user_edit(&mut self) {
        let d = self.below_usize(self.devices.len());
        let fs = self.fs(d);
        let edit = edit(&fs, &mut self.rng, &mut self.counter);
        self.record_edit(d, &edit);
    }

    /// Checks a sync that ran without injected failures. After a clean one (nothing
    /// deferred, no user edit during it), everything on the device is on the server.
    fn checked(
        &mut self,
        d: usize,
        what: &str,
        result: Result<SyncReport, String>,
        clean: bool,
    ) -> Result<SyncReport, Failure> {
        let report = match result {
            Ok(report) => report,
            Err(error) => {
                self.log(format_args!("d{d} {what}: error {error}"));
                return Err(self.fail(format!("d{d} {what} failed: {error}")));
            }
        };
        self.log(format_args!("d{d} {what}: {}", brief(&report)));
        self.summary.syncs += 1;
        self.count(&report);
        if let Some(pause) = &report.paused {
            return Err(self.fail(format!("d{d} {what} paused: {pause:?}")));
        }
        self.check_remote(d)?;
        if clean && report.deferred == 0 {
            for content in contents(&self.fs(d).tree()) {
                self.dirty.remove(&content);
            }
        }
        Ok(report)
    }

    /// No two live remote entries share a place (by folded name where case is ignored).
    fn check_remote(&self, d: usize) -> Result<(), Failure> {
        let device = lock(&self.devices[d]);
        let mut places: BTreeMap<(Option<NodeId>, String), NodeId> = BTreeMap::new();
        for (node, entry) in &device.engine.state().remote {
            if matches!(entry.node.kind, RemoteKind::Deleted) {
                continue;
            }
            let name = RelPath::root().join(entry.node.name.clone());
            let key = if self.summary.case_insensitive {
                name.fold_case()
            } else {
                name.to_string()
            };
            if let Some(other) = places.insert((entry.node.parent, key), *node) {
                return Err(self.fail(format!(
                    "d{d} sees {other:?} and {node:?} both named {name} in {:?}",
                    entry.node.parent
                )));
            }
        }
        Ok(())
    }

    /// What every device's index says about the paths where two trees differ.
    fn explain(&self, left: &Tree, right: &Tree) -> String {
        let paths: BTreeSet<&RelPath> = left
            .keys()
            .chain(right.keys())
            .filter(|path| left.get(*path) != right.get(*path))
            .take(4)
            .collect();
        let mut out = String::new();
        for (d, device) in self.devices.iter().enumerate() {
            let device = lock(device);
            let state = device.engine.state();
            for (node, entry) in &state.base {
                if !paths.contains(&entry.path) {
                    continue;
                }
                let remote = state.remote.get(node).map(|remote| &remote.node);
                let _ = write!(
                    out,
                    "\n  d{d} index: {} is {node:?} {:?} {:?}; remote: {:?}",
                    entry.path, entry.kind, entry.version, remote
                );
            }
        }
        out
    }

    fn count(&mut self, report: &SyncReport) {
        self.summary.commits += report.commits;
        self.summary.retries += report.retries;
        self.summary.conflicts += report.conflicts.len();
    }

    fn sync(&mut self) -> Result<(), Failure> {
        let Some(d) = self.online_device() else {
            return Ok(());
        };
        let result = lock(&self.devices[d]).sync().map_err(|e| e.to_string());
        self.checked(d, "sync", result, true).map(drop)
    }

    /// A sync during which, at a random server operation, another device syncs, the user of
    /// the syncing device edits, or both.
    fn interleaved_sync(&mut self) -> Result<(), Failure> {
        let Some(a) = self.online_device() else {
            return Ok(());
        };
        let others: Vec<usize> = self.online().into_iter().filter(|&b| b != a).collect();
        let other = if others.is_empty() || self.below(4) == 0 {
            None
        } else {
            let index = self.below_usize(others.len());
            Some(others[index])
        };
        let user_edits = other.is_none() || self.below(3) == 0;
        let at = self.below_usize(12);

        let fs = self.fs(a);
        let other_device = other.map(|b| Arc::clone(&self.devices[b]));
        let mut rng = ChaCha20Rng::seed_from_u64(self.rng.next_u64());
        let mut counter = self.counter;
        let slot: Arc<Mutex<Option<Interleaved>>> = Arc::default();
        let out = Arc::clone(&slot);
        self.world.server.interleave_after(
            at,
            Box::new(move || {
                let edit = user_edits.then(|| edit(&fs, &mut rng, &mut counter));
                let sync =
                    other_device.map(|device| lock(&device).sync().map_err(|e| e.to_string()));
                *lock(&out) = Some(Interleaved {
                    edit,
                    sync,
                    counter,
                });
            }),
        );
        let result = lock(&self.devices[a]).sync().map_err(|e| e.to_string());
        self.world.server.cancel_failures();

        let fired = lock(&slot).take();
        let mut clean = true;
        if let Some(inside) = fired {
            self.summary.interleavings += 1;
            self.counter = inside.counter;
            self.log(format_args!(
                "d{a} sync interrupted before server operation {at}"
            ));
            if let Some(edit) = &inside.edit {
                clean = false;
                self.record_edit(a, edit);
            }
            if let (Some(b), Some(result)) = (other, inside.sync) {
                self.checked(b, "sync inside", result, true)?;
            }
        }
        self.checked(a, "interrupted sync", result, clean).map(drop)
    }

    /// A sync with a failure injected at a random file system, server or index operation,
    /// then often a crash-restart.
    fn faulty_sync(&mut self) -> Result<(), Failure> {
        let Some(d) = self.online_device() else {
            return Ok(());
        };
        let (fs, index) = {
            let device = lock(&self.devices[d]);
            (Arc::clone(&device.fs), Arc::clone(&device.index))
        };
        let failure = match self.below(3) {
            0 => {
                let at = self.below_usize(40);
                fs.fail_after(at, FsError::Io("injected failure".into()));
                format!("file system operation {at}")
            }
            1 => {
                let at = self.below_usize(15);
                let kind = match self.below(3) {
                    0 => ServerFailure::Unavailable,
                    1 => ServerFailure::LostResponse,
                    _ => ServerFailure::Conflict,
                };
                self.world.server.fail_after(at, kind);
                format!("server operation {at} ({kind:?})")
            }
            _ => {
                let at = self.below_usize(6);
                index.fail_apply_after(at);
                format!("index transaction {at}")
            }
        };
        let result = lock(&self.devices[d]).sync();
        fs.cancel_failures();
        self.world.server.cancel_failures();
        index.cancel_failures();
        self.summary.faults += 1;
        match result {
            Ok(report) => {
                self.log(format_args!(
                    "d{d} sync, failing at {failure}: {}",
                    brief(&report)
                ));
                self.count(&report);
                if let Some(pause) = &report.paused {
                    return Err(self.fail(format!("d{d} faulty sync paused: {pause:?}")));
                }
            }
            Err(error) => self.log(format_args!("d{d} sync, failing at {failure}: {error}")),
        }
        self.check_remote(d)?;
        if self.below(2) == 0 {
            self.crash(d)?;
        }
        Ok(())
    }

    fn crash(&mut self, d: usize) -> Result<(), Failure> {
        self.summary.crashes += 1;
        self.log(format_args!("d{d} crashes and restarts"));
        let device = Arc::clone(&self.devices[d]);
        let reopened = self.world.reopen(&mut lock(&device));
        reopened.map_err(|error| self.fail(format!("d{d} didn't restart: {error}")))
    }

    fn clock_jump(&mut self) {
        const HOUR: u64 = 3_600_000;
        let now = oxisoft_drive_core::Clock::now_ms(&*self.world.clock);
        if self.below(2) == 0 {
            let jump = self.below(30 * 24 * HOUR);
            self.world.clock.set(now + jump);
            self.log(format_args!("clock jumps {jump} ms forward"));
        } else {
            let jump = self.below(48 * HOUR);
            self.world.clock.set(now.saturating_sub(jump));
            self.log(format_args!("clock jumps {jump} ms back"));
        }
    }

    fn go_offline(&mut self) {
        let d = self.below_usize(self.devices.len());
        let ticks = 5 + self.below_usize(40);
        self.offline_until[d] = self.tick + ticks;
        self.log(format_args!("d{d} goes offline for {ticks} ticks"));
    }

    /// Every device syncs until none has anything left to do; then the invariants.
    fn settle(&mut self, epoch: usize) -> Result<(), Failure> {
        self.offline_until.fill(0);
        let expected = self.dirty.clone();
        let mut quiet = false;
        for _ in 0..16 {
            let mut work = 0;
            for d in 0..self.devices.len() {
                let result = lock(&self.devices[d]).sync().map_err(|e| e.to_string());
                let report = self.checked(d, "settling sync", result, true)?;
                work += report.planned + report.deferred;
            }
            if work == 0 {
                quiet = true;
                break;
            }
        }
        if !quiet {
            return Err(self.fail("devices did not settle"));
        }
        let first = lock(&self.devices[0]).tree();
        for d in 1..self.devices.len() {
            let tree = lock(&self.devices[d]).tree();
            if tree != first {
                return Err(self.fail(format!(
                    "device {d} differs from device 0: {}{}",
                    difference(&first, &tree),
                    self.explain(&first, &tree)
                )));
            }
        }
        let mut fresh = self
            .world
            .device(self.devices.len())
            .map_err(|error| self.fail(format!("a new device didn't start: {error}")))?;
        fresh
            .sync()
            .map_err(|error| self.fail(format!("a new device failed to sync: {error}")))?;
        let tree = fresh.tree();
        if tree != first {
            return Err(self.fail(format!(
                "a new device differs from device 0: {}",
                difference(&first, &tree)
            )));
        }
        if let Some(leftover) = first.keys().find(|path| {
            path.to_string()
                .split('/')
                .any(|name| name.starts_with(".oxidrive"))
        }) {
            return Err(self.fail(format!("left behind: {leftover}")));
        }
        let present = contents(&first);
        let lost: Vec<u64> = expected.difference(&present).map(|c| number(c)).collect();
        if !lost.is_empty() {
            return Err(self.fail(format!("lost contents {lost:?}")));
        }
        let foreign: Vec<u64> = present
            .difference(&self.written)
            .map(|c| number(c))
            .collect();
        if !foreign.is_empty() {
            return Err(self.fail(format!("contents nobody wrote {foreign:?}")));
        }
        self.dirty.clear();
        self.log(format_args!(
            "epoch {epoch} settled: {} entries",
            first.len()
        ));
        Ok(())
    }
}

fn brief(report: &SyncReport) -> String {
    format!(
        "planned {}, commits {}, retries {}, conflicts {}, deferred {}",
        report.planned,
        report.commits,
        report.retries,
        report.conflicts.len(),
        report.deferred
    )
}

/// A content's number (its first eight bytes).
fn number(content: &[u8]) -> u64 {
    content
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

/// The paths where two trees differ, with content numbers (`-` for a folder, `none` for
/// missing).
fn difference(left: &Tree, right: &Tree) -> String {
    let paths: BTreeSet<&RelPath> = left.keys().chain(right.keys()).collect();
    let show = |entry: Option<&Option<Vec<u8>>>| match entry {
        None => "none".to_owned(),
        Some(None) => "-".to_owned(),
        Some(Some(content)) => format!("#{}", number(content)),
    };
    paths
        .into_iter()
        .filter(|path| left.get(*path) != right.get(*path))
        .take(10)
        .map(|path| {
            format!(
                "{path}: {} vs {}",
                show(left.get(path)),
                show(right.get(path))
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Names that collide, differ only in case, and nest.
const NAMES: [&str; 6] = ["a", "b", "c.txt", "d.txt", "e", "A"];

fn pick<T: Clone>(rng: &mut ChaCha20Rng, items: &[T]) -> Option<T> {
    if items.is_empty() {
        return None;
    }
    let index = usize::try_from(rng.next_u64() % items.len() as u64).unwrap_or(0);
    items.get(index).cloned()
}

fn random_name(rng: &mut ChaCha20Rng) -> Option<Name> {
    Name::new(pick(rng, &NAMES)?).ok()
}

/// A unique content: its number, then random bytes (often several chunks).
fn content(rng: &mut ChaCha20Rng, counter: &mut u64) -> Vec<u8> {
    *counter += 1;
    let mut bytes = counter.to_le_bytes().to_vec();
    let extra = usize::try_from(rng.next_u32() % 3000).unwrap_or(0);
    let mut noise = vec![0; extra];
    rng.fill_bytes(&mut noise);
    bytes.extend(noise);
    bytes
}

/// One random user edit: a new file, a changed file, a new folder, a deletion or a move.
fn edit(fs: &MemFs, rng: &mut ChaCha20Rng, counter: &mut u64) -> Edit {
    let tree = fs.tree();
    let before = contents(&tree);
    let folders: Vec<RelPath> = std::iter::once(RelPath::root())
        .chain(
            tree.iter()
                .filter(|(_, c)| c.is_none())
                .map(|(p, _)| p.clone()),
        )
        .collect();
    let files: Vec<RelPath> = tree
        .iter()
        .filter(|(_, c)| c.is_some())
        .map(|(p, _)| p.clone())
        .collect();
    let all: Vec<RelPath> = tree.keys().cloned().collect();
    let exists = |candidate: &RelPath| {
        tree.keys().any(|p| {
            p == candidate
                || (fs.rules().case_insensitive && p.fold_case() == candidate.fold_case())
        })
    };
    let new_path = |rng: &mut ChaCha20Rng| {
        let folder = pick(rng, &folders)?;
        let path = folder.join(random_name(rng)?);
        (!exists(&path)).then_some(path)
    };
    let description = match rng.next_u32() % 10 {
        0..=2 => new_path(rng).map(|path| {
            let bytes = content(rng, counter);
            fs.write(&path, &bytes);
            format!("write new {path} #{}", number(&bytes))
        }),
        3..=4 => pick(rng, &files).map(|path| {
            let bytes = content(rng, counter);
            fs.write(&path, &bytes);
            format!("change {path} to #{}", number(&bytes))
        }),
        5 => new_path(rng).map(|path| {
            fs.mkdir(&path);
            format!("mkdir {path}")
        }),
        6 => pick(rng, &all).map(|path| {
            fs.remove(&path);
            format!("remove {path}")
        }),
        _ => pick(rng, &all).and_then(|path| {
            let target = new_path(rng)?;
            (!target.starts_with(&path)).then(|| {
                fs.move_entry(&path, &target);
                format!("move {path} to {target}")
            })
        }),
    };
    let after = contents(&fs.tree());
    Edit {
        description: description.unwrap_or_else(|| "nothing".to_owned()),
        added: after.difference(&before).cloned().collect(),
        removed: before.difference(&after).cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_reproduces_its_run() {
        let config = Config {
            epochs: 2,
            ticks: 30,
        };
        let first = run(5, config).unwrap();
        assert_eq!(run(5, config).unwrap(), first);
        assert!(first.syncs > 0 && first.edits > 0);
    }

    #[test]
    fn failures_and_summaries_read_well() {
        let failure = Failure {
            seed: 3,
            config: Config::default(),
            tick: 7,
            message: "lost contents [4]".into(),
            trace: vec!["t1 d0 user: mkdir a".into()],
        };
        let text = failure.to_string();
        assert!(text.contains("seed 3 failed at tick 7: lost contents [4]"));
        assert!(text.contains("cargo xtask sim --seed 3 --epochs 4 --ticks 60"));
        assert!(text.contains("  t1 d0 user: mkdir a"));
        let summary = Summary {
            devices: 3,
            case_insensitive: true,
            ..Summary::default()
        };
        assert!(
            summary
                .to_string()
                .starts_with("3 devices (case-insensitive), 0 edits")
        );
    }

    #[test]
    fn differences_name_paths_and_contents() {
        let path = |text: &str| RelPath::parse(text).unwrap();
        let mut content = 9u64.to_le_bytes().to_vec();
        content.push(1);
        let left: Tree = [(path("x"), Some(content)), (path("f"), None)].into();
        let right: Tree = [(path("f"), None)].into();
        assert_eq!(difference(&left, &right), "x: #9 vs none");
        assert_eq!(number(b"short"), 0);
    }
}
