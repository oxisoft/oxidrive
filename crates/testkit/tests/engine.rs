//! The real engine, end to end, on in-memory file systems and a shared in-memory server.

#![cfg(test)]

use oxisoft_drive_core::{FsRules, RelPath};
use oxisoft_drive_testkit::World;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

fn path(text: &str) -> RelPath {
    RelPath::parse(text).unwrap()
}

#[test]
fn files_and_folders_reach_another_device() {
    let world = World::new(FsRules::default(), 1);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    let mut big = vec![0; 20_000];
    ChaCha20Rng::from_seed([5; 32]).fill_bytes(&mut big);
    a.fs.write(&path("notes.txt"), b"hello");
    a.fs.write(&path("docs/big.bin"), &big);
    a.fs.mkdir(&path("empty"));
    let report = a.sync().unwrap();
    assert_eq!(report.commits, 1, "{report:?}");
    b.sync().unwrap();
    assert_eq!(b.tree(), a.tree());
    assert_eq!(b.fs.content(&path("docs/big.bin")).unwrap(), big);
    // Nothing left to do on either side.
    assert_eq!(a.sync().unwrap().planned, 0);
    assert_eq!(b.sync().unwrap().planned, 0);
    // 20 000 random bytes in chunks of 64–1024 bytes, plus the small file.
    assert!(world.server.chunk_count(world.collection) > 20);
    // Repetitive content deduplicates: 20 copies of one pattern add few chunks.
    let before = world.server.chunk_count(world.collection);
    a.fs.write(&path("repeat.bin"), &big[..500].repeat(20));
    a.sync().unwrap();
    assert!(world.server.chunk_count(world.collection) - before < 10);
}

#[test]
fn a_missing_marker_pauses_and_an_untrusted_device_is_refused() {
    let world = World::new(FsRules::default(), 1);
    let mut a = world.device(0).unwrap();
    a.fs.write(&path("x"), b"1");
    a.fs.remove(&path(".oxidrive"));
    let report = a.sync().unwrap();
    assert_eq!(
        report.paused,
        Some(oxisoft_drive_core::Pause::MarkerMissing)
    );
    assert_eq!(report.commits, 0);

    // Device 2 isn't trusted (the world trusts 0 and 1): its commits are rejected on read.
    let mut stranger = world.device(2).unwrap();
    stranger.fs.write(&path("y"), b"2");
    stranger.sync().unwrap();
    let mut b = world.device(1).unwrap();
    assert!(b.sync().is_err());
}

#[test]
fn deletions_and_moves_propagate() {
    let world = World::new(FsRules::default(), 1);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("gone.txt"), b"bye");
    a.fs.write(&path("folder/inner.txt"), b"in");
    a.fs.write(&path("moving.txt"), b"moves");
    a.sync().unwrap();
    b.sync().unwrap();
    assert_eq!(b.tree(), a.tree());

    b.fs.remove(&path("gone.txt"));
    b.fs.remove(&path("folder"));
    b.fs.move_entry(&path("moving.txt"), &path("moved.txt"));
    let report = b.sync().unwrap();
    assert_eq!(report.commits, 1, "{report:?}");
    let report = a.sync().unwrap();
    assert!(report.planned >= 3, "{report:?}");
    assert_eq!(a.tree(), b.tree());
    assert!(a.fs.content(&path("gone.txt")).is_none());
    assert_eq!(a.fs.content(&path("moved.txt")).unwrap(), b"moves");
}
