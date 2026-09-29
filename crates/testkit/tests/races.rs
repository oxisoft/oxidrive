//! Races and awkward orders on the real engine: the user editing at every point of a sync,
//! moves that block each other, and lost commit races.

#![cfg(test)]

use oxisoft_drive_core::{EngineError, FsRules, RelPath, RemoteKind};
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

#[test]
fn another_device_committing_in_the_middle_of_a_sync() {
    use std::sync::{Arc, Mutex};

    let world = World::new(FsRules::default(), 9);
    let mut a = world.device(0).unwrap();
    let b = Arc::new(Mutex::new(world.device(1).unwrap()));
    a.fs.write(&path("x"), b"from a");
    b.lock().unwrap().fs.write(&path("y"), b"from b");
    let inside = Arc::clone(&b);
    // Right after a has fetched the head, b commits: a's commit then loses the race.
    world.server.interleave_after(
        1,
        Box::new(move || {
            assert_eq!(inside.lock().unwrap().sync().unwrap().commits, 1);
        }),
    );
    let report = a.sync().unwrap();
    assert_eq!((report.retries, report.commits), (1, 1));
    assert_eq!(a.fs.content(&path("y")).unwrap(), b"from b");

    // A hook that never fired is cancelled with the failures.
    world
        .server
        .interleave_after(1000, Box::new(|| panic!("cancelled")));
    world.server.cancel_failures();
    let mut b = Arc::try_unwrap(b).unwrap().into_inner().unwrap();
    settle(&world, &mut [&mut a, &mut b]);
    assert_eq!(b.fs.content(&path("x")).unwrap(), b"from a");
}

/// A folder deleted and made again (so with a new file ID) is found by its path. After its
/// parent's move is uploaded, it must still be found there, and what was made inside it must
/// stay inside it (found by the simulator: the old folder came back as a conflict copy).
#[test]
fn a_recreated_folder_inside_a_moved_folder() {
    let world = World::new(FsRules::default(), 9);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.mkdir(&path("p/c"));
    a.sync().unwrap();
    a.fs.remove(&path("p/c"));
    a.fs.mkdir(&path("p/c/d"));
    a.fs.move_entry(&path("p"), &path("q"));
    a.sync().unwrap();
    a.sync().unwrap();
    settle(&world, &mut [&mut a, &mut b]);
    let paths: Vec<String> = a.tree().keys().map(ToString::to_string).collect();
    assert_eq!(paths, ["q", "q/c", "q/c/d"]);
}

/// The user moves a folder away at every point of a sync that downloads into it (found by
/// the simulator: the sync failed instead of leaving it to the next one).
#[test]
fn a_folder_moved_away_while_downloading_into_it() {
    for n in 0..40 {
        let world = World::new(FsRules::default(), 9);
        let mut a = world.device(0).unwrap();
        let mut b = world.device(1).unwrap();
        a.fs.mkdir(&path("dir/sub"));
        a.sync().unwrap();
        b.sync().unwrap();
        a.fs.write(&path("dir/one"), &[1; 700]);
        a.fs.mkdir(&path("dir/sub/new"));
        a.sync().unwrap();
        b.fs.act_after(n, UserAction::Move(path("dir"), path("moved")));
        b.sync().unwrap();
        b.fs.cancel_failures();
        settle(&world, &mut [&mut a, &mut b]);
        // Late values of `n` come after the sync's last operation: then nothing moved.
        let one =
            a.fs.content(&path("moved/one"))
                .or_else(|| a.fs.content(&path("dir/one")));
        assert_eq!(one, Some(vec![1; 700]), "n {n}");
    }
}

/// A file renamed on one device and edited on another: the renaming device downloads the
/// edit, then loses the commit race for the rename. The rename must survive the retry (found
/// by the simulator: the download had recorded the rename as synced).
#[test]
fn a_local_rename_survives_a_lost_race_after_downloading_an_edit() {
    let world = World::new(FsRules::default(), 9);
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    a.fs.write(&path("f"), b"first");
    a.sync().unwrap();
    b.sync().unwrap();
    b.fs.move_entry(&path("f"), &path("g"));
    a.fs.write(&path("f"), b"second");
    a.sync().unwrap();
    world
        .server
        .fail_next(ServerOp::Append, ServerFailure::Conflict);
    b.sync().unwrap();
    settle(&world, &mut [&mut a, &mut b]);
    let paths: Vec<String> = a.tree().keys().map(ToString::to_string).collect();
    assert_eq!(paths, ["g"]);
    assert_eq!(a.fs.content(&path("g")).unwrap(), b"second");
}

/// A file renamed and a new folder made at its old name; while the sync runs, the user
/// renames the file again. However the uploads interleave with that, the commit must not put
/// two entries at one place (found by the simulator).
#[test]
fn a_rename_racing_a_new_entry_at_the_old_name() {
    for n in 0..40 {
        let world = World::new(FsRules::default(), 9);
        let mut a = world.device(0).unwrap();
        let mut b = world.device(1).unwrap();
        a.fs.write(&path("x"), b"file");
        a.sync().unwrap();
        b.sync().unwrap();
        a.fs.move_entry(&path("x"), &path("y"));
        a.fs.mkdir(&path("x"));
        a.fs.act_after(n, UserAction::Move(path("y"), path("w")));
        a.sync().unwrap();
        a.fs.cancel_failures();
        let mut places = std::collections::BTreeSet::new();
        for entry in a.engine.state().remote.values() {
            if entry.node.kind != RemoteKind::Deleted {
                assert!(
                    places.insert((entry.node.parent, entry.node.name.clone())),
                    "n {n}: two entries named {}",
                    entry.node.name
                );
            }
        }
        settle(&world, &mut [&mut a, &mut b]);
        assert_eq!(contents(&a.tree()).len(), 1, "n {n}");
    }
}

/// Both devices reach the same content, so the second one adopts the other's version
/// without uploading or downloading; the user editing the file at any point of that sync
/// keeps the edit (found by the simulator: the index took the edited file for the remote
/// content).
#[test]
fn an_edit_during_an_adopted_remote_change() {
    for n in 0..30 {
        let world = World::new(FsRules::default(), 9);
        let mut a = world.device(0).unwrap();
        let mut b = world.device(1).unwrap();
        a.fs.write(&path("f"), b"first");
        a.sync().unwrap();
        b.sync().unwrap();
        a.fs.write(&path("f"), b"same on both");
        b.fs.write(&path("f"), b"same on both");
        b.sync().unwrap();
        let edit = format!("edit at {n}").into_bytes();
        a.fs.act_after(n, UserAction::Write(path("f"), edit.clone()));
        a.sync().unwrap();
        a.fs.cancel_failures();
        settle(&world, &mut [&mut a, &mut b]);
        // Late values of `n` come after the sync's last operation: then nothing was edited.
        let content = a.fs.content(&path("f")).unwrap();
        assert!(content == edit || content == b"same on both", "n {n}");
    }
}

/// A folder deleted remotely is replaced by a file locally while the sync removes it: the sync
/// leaves it to the next one and the file survives (found by the simulator: "not a folder"
/// failed the sync).
#[test]
fn a_folder_replaced_by_a_file_while_it_is_removed() {
    for n in 0..30 {
        let world = World::new(FsRules::default(), 9);
        let mut a = world.device(0).unwrap();
        let mut b = world.device(1).unwrap();
        a.fs.mkdir(&path("d"));
        a.sync().unwrap();
        b.sync().unwrap();
        b.fs.remove(&path("d"));
        b.sync().unwrap();
        let file = format!("file at {n}").into_bytes();
        a.fs.act_after(n, UserAction::Write(path("d"), file.clone()));
        a.sync().unwrap();
        a.fs.cancel_failures();
        settle(&world, &mut [&mut a, &mut b]);
        // Late values of `n` come after the sync's last operation: then nothing was written.
        let kept =
            a.fs.content(&path("d"))
                .is_none_or(|content| content == file);
        assert!(kept, "n {n}");
    }
}
