//! The model test of the reconciler (core `tests/model.rs`), run on the real engine: several
//! devices with in-memory file systems and one in-memory server, random edits, sync until
//! quiet. Checked after every cycle:
//!
//! 1. **Convergence:** every device has the same tree, and a brand-new device syncing from
//!    scratch gets it too (the server holds everything).
//! 2. **No data loss:** every content a device wrote and still had when it synced survives
//!    somewhere.
//!
//! Runs with case-sensitive and case-insensitive file systems.

#![cfg(test)]

use std::collections::BTreeSet;

use oxisoft_drive_core::{FileSystem, FsRules, RelPath, ServerApi};
use oxisoft_drive_proto::Name;
use oxisoft_drive_testkit::{MemFs, ServiceServer, Tree, World, contents};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

const NAMES: [&str; 6] = ["a", "b", "c.txt", "d.txt", "e", "A"];

fn pick<T: Clone>(rng: &mut ChaCha20Rng, items: &[T]) -> Option<T> {
    if items.is_empty() {
        return None;
    }
    let index = usize::try_from(rng.next_u64() % items.len() as u64).unwrap();
    Some(items[index].clone())
}

fn random_name(rng: &mut ChaCha20Rng) -> Name {
    Name::new(pick(rng, &NAMES).unwrap()).unwrap()
}

/// A unique content: a counter followed by some random bytes (sometimes several chunks).
fn content(rng: &mut ChaCha20Rng, counter: &mut u64) -> Vec<u8> {
    *counter += 1;
    let mut bytes = counter.to_le_bytes().to_vec();
    let extra = usize::try_from(rng.next_u32() % 3000).unwrap();
    let mut noise = vec![0; extra];
    rng.fill_bytes(&mut noise);
    bytes.extend(noise);
    bytes
}

fn edit(fs: &MemFs, rng: &mut ChaCha20Rng, counter: &mut u64) {
    let tree = fs.tree();
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
    match rng.next_u32() % 10 {
        0..=2 => {
            let Some(folder) = pick(rng, &folders) else {
                return;
            };
            let path = folder.join(random_name(rng));
            if !exists(&path) {
                fs.write(&path, &content(rng, counter));
            }
        }
        3..=4 => {
            if let Some(path) = pick(rng, &files) {
                fs.write(&path, &content(rng, counter));
            }
        }
        5 => {
            let Some(folder) = pick(rng, &folders) else {
                return;
            };
            let path = folder.join(random_name(rng));
            if !exists(&path) {
                fs.mkdir(&path);
            }
        }
        6 => {
            if let Some(path) = pick(rng, &all) {
                fs.remove(&path);
            }
        }
        _ => {
            let (Some(path), Some(folder)) = (pick(rng, &all), pick(rng, &folders)) else {
                return;
            };
            let target = folder.join(random_name(rng));
            if !folder.starts_with(&path) && !exists(&target) {
                fs.move_entry(&path, &target);
            }
        }
    }
}

fn run(seed: u64, rules: FsRules, devices: usize, cycles: usize, edits: usize) {
    run_world(&World::new(rules, devices), seed, devices, cycles, edits);
}

fn run_world<S: ServerApi>(
    world: &World<S>,
    seed: u64,
    devices: usize,
    cycles: usize,
    edits: usize,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut all: Vec<_> = (0..devices).map(|d| world.device(d).unwrap()).collect();
    let mut counter = 0;
    let mut converged = Tree::new();
    for cycle in 0..cycles {
        for _ in 0..edits {
            for device in &all {
                edit(&device.fs, &mut rng, &mut counter);
            }
        }
        let before = contents(&converged);
        let mut survivors = BTreeSet::new();
        for device in &all {
            survivors.extend(contents(&device.fs.tree()).difference(&before).cloned());
        }
        let mut quiet = false;
        for _ in 0..12 {
            let mut work = 0;
            for device in &mut all {
                let report = device.sync().unwrap_or_else(|error| {
                    panic!("seed {seed} cycle {cycle}: sync failed: {error}")
                });
                assert_eq!(report.paused, None, "seed {seed}");
                assert_eq!(report.deferred, 0, "seed {seed}: steps deferred");
                work += report.planned;
            }
            if work == 0 {
                quiet = true;
                break;
            }
        }
        assert!(quiet, "seed {seed} cycle {cycle}: devices did not settle");
        let first = all[0].fs.tree();
        for (d, device) in all.iter().enumerate() {
            assert_eq!(
                device.fs.tree(),
                first,
                "seed {seed} cycle {cycle}: device {d} differs"
            );
        }
        let mut fresh = world.device(devices).unwrap();
        fresh.sync().unwrap();
        assert_eq!(
            fresh.fs.tree(),
            first,
            "seed {seed} cycle {cycle}: a new device differs"
        );
        let present = contents(&first);
        let lost: Vec<_> = survivors
            .iter()
            .filter(|c| !present.contains(*c))
            .map(|c| u64::from_le_bytes(c[..8].try_into().unwrap()))
            .collect();
        assert!(
            lost.is_empty(),
            "seed {seed} cycle {cycle}: lost contents {lost:?}"
        );
        converged = first;
    }
}

const CASE_SENSITIVE: FsRules = FsRules {
    case_insensitive: false,
    windows_names: false,
};
const CASE_INSENSITIVE: FsRules = FsRules {
    case_insensitive: true,
    windows_names: false,
};

#[test]
fn fixed_seeds_case_sensitive() {
    for seed in 0..60 {
        run(seed, CASE_SENSITIVE, 2, 3, 6);
    }
}

#[test]
fn fixed_seeds_case_insensitive() {
    for seed in 0..60 {
        run(seed, CASE_INSENSITIVE, 2, 3, 6);
    }
}

#[test]
fn three_devices() {
    for seed in 0..20 {
        run(seed, CASE_SENSITIVE, 3, 3, 5);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn random_seeds(seed in any::<u64>(), insensitive in any::<bool>()) {
        let rules = if insensitive { CASE_INSENSITIVE } else { CASE_SENSITIVE };
        run(seed, rules, 2, 3, 8);
    }
}

/// The same scenarios on the real server with SQLite (server storage H3).
#[test]
fn on_the_real_server_with_sqlite() {
    for seed in 0..10 {
        let server = ServiceServer::sqlite(2).unwrap();
        run_world(
            &World::with_server(CASE_SENSITIVE, 2, server),
            seed,
            2,
            3,
            6,
        );
    }
}

/// The same scenarios on the real server with PostgreSQL (server storage H3). Needs
/// `OXIDRIVE_TEST_POSTGRES_URL`; fails without it rather than skipping (server crate G3).
#[test]
fn on_the_real_server_with_postgres() {
    let url = std::env::var("OXIDRIVE_TEST_POSTGRES_URL")
        .expect("OXIDRIVE_TEST_POSTGRES_URL must point at a PostgreSQL server for this test");
    for seed in 0..10 {
        let server = ServiceServer::postgres(&url, 2).unwrap();
        run_world(
            &World::with_server(CASE_SENSITIVE, 2, server),
            seed,
            2,
            3,
            6,
        );
    }
}
