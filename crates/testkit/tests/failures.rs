//! Failures and crashes at every point of a sync (engineering standards §1, requirement N2).
//!
//! One scenario is run again and again; each time the n-th operation of the file system, the
//! server or the index fails. The device then "crashes" (its engine is dropped and reopened
//! from its index) and both devices sync until quiet. Every run must converge, give a new
//! device the same tree, and lose nothing either device wrote.

#![cfg(test)]

use std::collections::BTreeSet;

use oxisoft_drive_core::{FsError, FsRules, RelPath};
use oxisoft_drive_testkit::{Device, ServerFailure, World, contents};

fn path(text: &str) -> RelPath {
    RelPath::parse(text).unwrap()
}

/// Two devices share a synced tree, then both edit it (including a conflict).
fn scenario() -> (World, Device, Device, BTreeSet<Vec<u8>>) {
    let world = World::new(FsRules::default(), 2);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("shared/doc.txt"), &[b'v'; 3000]);
    a.fs.write(&path("shared/keep.txt"), b"keep");
    a.fs.write(&path("old.txt"), b"old");
    a.sync().unwrap();
    b.sync().unwrap();

    a.fs.write(&path("shared/doc.txt"), &[b'a'; 2500]);
    a.fs.write(&path("new/a.bin"), &[b'n'; 5000]);
    a.fs.move_entry(&path("old.txt"), &path("shared/renamed.txt"));
    b.fs.write(&path("shared/doc.txt"), &[b'b'; 1500]);
    b.fs.remove(&path("shared/keep.txt"));
    b.fs.write(&path("b.txt"), b"from b");
    let mut own = contents(&a.tree());
    own.extend(contents(&b.tree()));
    // keep.txt was deleted by b and not changed by a: it may go.
    own.remove(b"keep".as_slice());
    (world, a, b, own)
}

/// After the injected failure: crash, then sync both until quiet; check everything.
fn recover_and_check(
    world: &World,
    a: &mut Device,
    b: &mut Device,
    own: &BTreeSet<Vec<u8>>,
    label: &str,
) {
    a.fs.cancel_failures();
    a.index.cancel_failures();
    world.server.cancel_failures();
    world.reopen(a).unwrap();
    let mut quiet = false;
    for _ in 0..10 {
        let planned = a.sync().unwrap().planned + b.sync().unwrap().planned;
        if planned == 0 {
            quiet = true;
            break;
        }
    }
    assert!(quiet, "{label}: devices did not settle");
    assert_eq!(a.tree(), b.tree(), "{label}: devices differ");
    let mut fresh = world.device(2).unwrap();
    fresh.sync().unwrap();
    assert_eq!(fresh.tree(), a.tree(), "{label}: a new device differs");
    let present = contents(&a.tree());
    let lost: Vec<_> = own
        .iter()
        .filter(|c| !present.contains(*c))
        .map(Vec::len)
        .collect();
    assert!(lost.is_empty(), "{label}: lost contents of sizes {lost:?}");
}

/// How many operations device a's sync takes without failures.
fn operations() -> (usize, usize) {
    let (world, mut a, _, _) = scenario();
    let fs_before = a.fs.operations();
    let server_before = world.server.operations();
    a.sync().unwrap();
    (
        a.fs.operations() - fs_before,
        world.server.operations() - server_before,
    )
}

#[test]
fn a_failure_at_every_file_system_operation() {
    let (fs_operations, _) = operations();
    assert!(fs_operations > 10, "only {fs_operations} operations");
    for n in 0..fs_operations {
        let (world, mut a, mut b, own) = scenario();
        a.fs.fail_after(n, FsError::Io("injected".into()));
        let _ = a.sync();
        recover_and_check(&world, &mut a, &mut b, &own, &format!("fs operation {n}"));
    }
}

#[test]
fn a_failure_at_every_server_operation() {
    let (_, server_operations) = operations();
    assert!(server_operations > 3);
    for failure in [ServerFailure::Unavailable, ServerFailure::LostResponse] {
        for n in 0..server_operations {
            let (world, mut a, mut b, own) = scenario();
            world.server.fail_after(n, failure);
            let _ = a.sync();
            recover_and_check(
                &world,
                &mut a,
                &mut b,
                &own,
                &format!("{failure:?} at server operation {n}"),
            );
        }
    }
}

#[test]
fn a_failure_at_every_index_transaction() {
    for n in 0..16 {
        let (world, mut a, mut b, own) = scenario();
        a.index.fail_apply_after(n);
        let _ = a.sync();
        recover_and_check(
            &world,
            &mut a,
            &mut b,
            &own,
            &format!("index transaction {n}"),
        );
    }
}

/// A node moved and edited on one device; the other moves it, then fails to download the
/// edit and crashes. The index must not claim the edit arrived (found by the simulator).
#[test]
fn a_crash_between_a_remote_move_and_its_download() {
    let world = World::new(FsRules::default(), 2);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("f"), b"first");
    a.sync().unwrap();
    b.sync().unwrap();
    a.fs.move_entry(&path("f"), &path("g"));
    a.fs.write(&path("g"), b"second");
    a.sync().unwrap();

    world.server.fail_next(
        oxisoft_drive_testkit::ServerOp::GetChunk,
        ServerFailure::Unavailable,
    );
    assert!(b.sync().is_err());
    world.reopen(&mut b).unwrap();
    b.sync().unwrap();
    assert_eq!(b.fs.content(&path("g")).unwrap(), b"second");
}

/// A node moved on one device and edited on the other, whose upload fails after it moved the
/// node locally. The local edit must still be uploaded after the crash.
#[test]
fn a_crash_between_a_remote_move_and_uploading_a_local_edit() {
    let world = World::new(FsRules::default(), 2);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("f"), b"first");
    a.sync().unwrap();
    b.sync().unwrap();
    a.fs.move_entry(&path("f"), &path("g"));
    a.sync().unwrap();
    b.fs.write(&path("f"), b"edited on b");

    world.server.fail_next(
        oxisoft_drive_testkit::ServerOp::PutChunk,
        ServerFailure::Unavailable,
    );
    assert!(b.sync().is_err());
    assert_eq!(b.fs.content(&path("g")).unwrap(), b"edited on b");
    world.reopen(&mut b).unwrap();
    b.sync().unwrap();
    a.sync().unwrap();
    assert_eq!(a.fs.content(&path("g")).unwrap(), b"edited on b");
}

/// An index transaction fails while new commits are taken in, and the engine goes on without
/// a restart. What the failed transaction held must not be forgotten, then or after a later
/// restart (found by the simulator: files were never downloaded).
#[test]
fn a_failed_index_transaction_without_a_restart() {
    let world = World::new(FsRules::default(), 2);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("first"), b"1");
    a.sync().unwrap();
    b.index.fail_next_applies(1);
    assert!(b.sync().is_err());
    a.fs.write(&path("second"), b"2");
    a.sync().unwrap();
    b.sync().unwrap();
    world.reopen(&mut b).unwrap();
    b.sync().unwrap();
    a.sync().unwrap();
    assert_eq!(b.tree(), a.tree());
    assert_eq!(a.tree().len(), 2);
}

/// A commit lands but its answer is lost, and the device restarts: its next change must not
/// reuse the version number of the one that landed, or other devices take the new change
/// for the one they already have (found by the simulator).
#[test]
fn versions_are_never_reused_after_a_lost_answer() {
    let world = World::new(FsRules::default(), 2);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("f"), b"first");
    a.sync().unwrap();
    b.sync().unwrap();
    a.fs.write(&path("f"), b"second");
    world.server.fail_next(
        oxisoft_drive_testkit::ServerOp::Append,
        ServerFailure::LostResponse,
    );
    assert!(a.sync().is_err());
    world.reopen(&mut a).unwrap();
    a.sync().unwrap();
    b.sync().unwrap();
    a.fs.write(&path("f"), b"third");
    a.sync().unwrap();
    b.sync().unwrap();
    assert_eq!(b.fs.content(&path("f")).unwrap(), b"third");
}

/// An edit that keeps a file's size, with its modification time set back to the synced one
/// (a coarse clock, or a tool setting times), is still an edit: a remote delete must not
/// remove it (found by the simulator: the edit looked unchanged and was deleted).
#[test]
fn an_edit_with_the_same_size_and_time_is_seen() {
    let world = World::new(FsRules::default(), 2);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("f"), b"first");
    a.sync().unwrap();
    b.sync().unwrap();
    let synced = b.engine.state().base.values().next().unwrap().clone();
    let oxisoft_drive_core::BaseKind::File { stat, .. } = synced.kind else {
        panic!("not a file");
    };
    b.fs.write(&path("f"), b"edit!");
    b.fs.set_mtime(&path("f"), stat.mtime_ms);
    a.fs.remove(&path("f"));
    a.sync().unwrap();
    b.sync().unwrap();
    a.sync().unwrap();
    assert_eq!(a.fs.content(&path("f")).unwrap(), b"edit!");
}
