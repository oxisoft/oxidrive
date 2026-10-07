//! Fixed seeds on every push (decision M3: about 30 seconds of work in all), split so the
//! test runner spreads them over cores, plus seeds that once failed. Longer searches run with
//! `cargo xtask sim --runs K`.

#![cfg(test)]

use oxisoft_drive_sim::{Backend, Config, run, run_on};

const CONFIG: Config = Config {
    epochs: 4,
    ticks: 60,
};

const SHORT: Config = Config {
    epochs: 1,
    ticks: 40,
};

/// Seeds that once failed, with what they found (all fixed in the engine unless noted).
const REGRESSIONS: [(u64, Config, &str); 15] = [
    (
        3,
        CONFIG,
        "move recorded the remote content before its download",
    ),
    (
        8,
        CONFIG,
        "a download recorded a pending local rename as synced",
    ),
    (74, CONFIG, "a version number reused after a lost answer"),
    (
        117,
        SHORT,
        "memory ahead of the index after a failed transaction",
    ),
    (
        125,
        SHORT,
        "a folder moved away during a download failed the sync",
    ),
    (
        196,
        SHORT,
        "memory ahead of the index after a failed transaction",
    ),
    (
        254,
        SHORT,
        "memory ahead of the index after a failed transaction",
    ),
    (896, CONFIG, "a commit with two entries at one place"),
    (
        1243,
        CONFIG,
        "an index place differing from the remote at the same version",
    ),
    (
        2577,
        CONFIG,
        "test file system: case of parent folders (testkit)",
    ),
    (2666, CONFIG, "an adopted file edited after the scan"),
    (5859, CONFIG, "a temporary name uploaded after a crash"),
    (
        9877,
        CONFIG,
        "an edit with the synced size and time looked unchanged",
    ),
    (
        18698,
        CONFIG,
        "a folder replaced by a file while it was removed (trait contract)",
    ),
    (
        24352,
        CONFIG,
        "a conflict copy named after a temporary name, looping",
    ),
];

fn seeds(range: std::ops::Range<u64>) {
    for seed in range {
        if let Err(failure) = run(seed, CONFIG) {
            panic!("{failure}");
        }
    }
}

#[test]
fn seeds_0_to_10() {
    seeds(0..10);
}

#[test]
fn seeds_10_to_20() {
    seeds(10..20);
}

#[test]
fn seeds_20_to_30() {
    seeds(20..30);
}

#[test]
fn seeds_30_to_40() {
    seeds(30..40);
}

#[test]
fn seeds_40_to_50() {
    seeds(40..50);
}

#[test]
fn seeds_50_to_60() {
    seeds(50..60);
}

#[test]
fn seeds_60_to_70() {
    seeds(60..70);
}

#[test]
fn seeds_70_to_80() {
    seeds(70..80);
}

#[test]
fn regressions() {
    for (seed, config, found) in REGRESSIONS {
        if let Err(failure) = run(seed, config) {
            panic!("regression ({found}): {failure}");
        }
    }
}

/// Seeds on the real server with SQLite (server storage H3).
#[test]
fn seeds_on_sqlite() {
    for seed in 0..10 {
        if let Err(failure) = run_on(seed, CONFIG, Backend::Sqlite) {
            panic!("{failure}");
        }
    }
}

/// Seeds on the real server over HTTP, through the client (client foundation B5).
#[test]
fn seeds_over_http() {
    for seed in 0..10 {
        if let Err(failure) = run_on(seed, CONFIG, Backend::Http) {
            panic!("{failure}");
        }
    }
}

/// Seeds on the real server with PostgreSQL (server storage H3). Needs
/// `OXIDRIVE_TEST_POSTGRES_URL`; fails without it rather than skipping (server crate G3).
#[test]
fn seeds_on_postgres() {
    let url = std::env::var("OXIDRIVE_TEST_POSTGRES_URL")
        .expect("OXIDRIVE_TEST_POSTGRES_URL must point at a PostgreSQL server for this test");
    for seed in 0..10 {
        if let Err(failure) = run_on(seed, CONFIG, Backend::Postgres(&url)) {
            panic!("{failure}");
        }
    }
}
