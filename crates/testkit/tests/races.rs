//! Races and awkward orders on the real engine: the user editing at every point of a sync,
//! moves that block each other, and lost commit races.

#![cfg(test)]

use oxisoft_drive_core::{EngineError, FsRules, RelPath};
use oxisoft_drive_testkit::{Device, ServerFailure, ServerOp, UserAction, World, contents};

fn path(text: &str) -> RelPath {
    RelPath::parse(text).unwrap()
}

fn settle(world: &World, devices: &mut [&mut Device]) {
    for _ in 0..10 {
        let mut planned = 0;
        for device in devices.iter_mut() {
            planned += device.sync().unwrap().planned;
        }
        if planned == 0 {
            let first = devices[0].tree();
            for device in devices.iter() {
                assert_eq!(device.tree(), first, "devices differ");
            }
            let mut fresh = world.device(9).unwrap();
            fresh.sync().unwrap();
            assert_eq!(fresh.tree(), first, "a new device differs");
            return;
        }
    }
    panic!("devices did not settle");
}

/// Two devices share a tree; device a has local changes to upload, and device b changed a
/// file a also has, so a downloads while it uploads.
fn scenario() -> (World, Device, Device) {
    let world = World::new(FsRules::default(), 9);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("doc.txt"), &[b'1'; 2000]);
    a.fs.write(&path("other.txt"), &[b'o'; 1500]);
    a.fs.write(&path("gone.txt"), &[b'g'; 900]);
    a.fs.write(&path("dir/inner.txt"), &[b'i'; 800]);
    a.sync().unwrap();
    b.sync().unwrap();
    b.fs.write(&path("other.txt"), &[b'b'; 1700]);
    b.fs.remove(&path("gone.txt"));
    b.fs.move_entry(&path("dir"), &path("moved"));
    b.sync().unwrap();
    a.fs.write(&path("doc.txt"), &[b'2'; 2100]);
    a.fs.write(&path("new.txt"), &[b'n'; 1200]);
    (world, a, b)
}

#[test]
fn a_user_action_at_every_operation() {
    let operations = {
        let (_world, mut a, _b) = scenario();
        let before = a.fs.operations();
        a.sync().unwrap();
        a.fs.operations() - before
    };
    for n in 0..operations {
        // Edits must survive wherever they land; deletes and moves must not break the sync.
        let edits = [
            "doc.txt",
            "other.txt",
            "new.txt",
            "gone.txt",
            "dir/inner.txt",
        ];
        for target in edits {
            let (world, mut a, mut b) = scenario();
            let latest = format!("user edit at {n} of {target}").into_bytes();
            a.fs.act_after(n, UserAction::Write(path(target), latest.clone()));
            a.sync().unwrap();
            a.fs.cancel_failures();
            settle(&world, &mut [&mut a, &mut b]);
            assert!(
                contents(&a.tree()).contains(&latest),
                "edit of {target} at operation {n} was lost: {:?}",
                a.tree().keys().collect::<Vec<_>>()
            );
        }
        for action in [
            UserAction::Remove(path("doc.txt")),
            UserAction::Remove(path("dir")),
            UserAction::Move(path("new.txt"), path("renamed.txt")),
            UserAction::Move(path("dir"), path("elsewhere")),
        ] {
            let (world, mut a, mut b) = scenario();
            a.fs.act_after(n, action.clone());
            a.sync().unwrap();
            a.fs.cancel_failures();
            settle(&world, &mut [&mut a, &mut b]);
        }
    }
}

#[test]
fn a_server_serving_wrong_chunks_is_caught() {
    let world = World::new(FsRules::default(), 9);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("x"), &[b'x'; 3000]);
    a.fs.write(&path("y"), &[b'y'; 3000]);
    a.sync().unwrap();
    world.server.swap_chunks(world.collection);
    assert!(matches!(b.sync(), Err(EngineError::Chunk(_))));
    assert!(b.tree().is_empty(), "nothing written from bad data");
    assert!(
        b.engine.state().base.is_empty(),
        "nothing recorded from bad data"
    );
}

#[test]
fn swapped_names() {
    let world = World::new(FsRules::default(), 9);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("x"), b"content of x");
    a.fs.write(&path("y"), b"content of y");
    a.sync().unwrap();
    b.sync().unwrap();
    b.fs.move_entry(&path("x"), &path("t"));
    b.fs.move_entry(&path("y"), &path("x"));
    b.fs.move_entry(&path("t"), &path("y"));
    b.sync().unwrap();
    a.sync().unwrap();
    assert_eq!(a.fs.content(&path("x")).unwrap(), b"content of y");
    assert_eq!(a.fs.content(&path("y")).unwrap(), b"content of x");
    settle(&world, &mut [&mut a, &mut b]);
}

#[test]
fn a_folder_taking_the_place_of_the_file_moving_into_it() {
    let world = World::new(FsRules::default(), 9);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("e/e"), b"the file");
    a.sync().unwrap();
    b.sync().unwrap();
    b.fs.mkdir(&path("e/b"));
    b.fs.move_entry(&path("e/e"), &path("e/b/a"));
    b.fs.move_entry(&path("e/b"), &path("e/e"));
    b.sync().unwrap();
    a.sync().unwrap();
    assert_eq!(a.fs.content(&path("e/e/a")).unwrap(), b"the file");
    settle(&world, &mut [&mut a, &mut b]);
}

#[test]
fn a_file_taking_the_name_of_its_deleted_folder() {
    let world = World::new(FsRules::default(), 9);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("e/f"), b"inner file");
    a.sync().unwrap();
    b.sync().unwrap();
    b.fs.move_entry(&path("e/f"), &path("x"));
    b.fs.remove(&path("e"));
    b.fs.move_entry(&path("x"), &path("e"));
    b.sync().unwrap();
    a.sync().unwrap();
    assert_eq!(a.fs.content(&path("e")).unwrap(), b"inner file");
    settle(&world, &mut [&mut a, &mut b]);
}

#[test]
fn lost_commit_races_are_retried() {
    let world = World::new(FsRules::default(), 9);
    let mut a = world.device(0).unwrap();
    a.fs.write(&path("x"), b"x");
    for _ in 0..3 {
        world
            .server
            .fail_next(ServerOp::Append, ServerFailure::Conflict);
    }
    let report = a.sync().unwrap();
    assert_eq!((report.retries, report.commits), (3, 1));

    a.fs.write(&path("y"), b"y");
    for _ in 0..8 {
        world
            .server
            .fail_next(ServerOp::Append, ServerFailure::Conflict);
    }
    assert_eq!(
        a.sync(),
        Err(EngineError::TooManyRetries).map(|()| unreachable!())
    );
    assert_eq!(a.sync().unwrap().commits, 1);
}
