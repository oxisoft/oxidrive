//! The engine end to end on real disks (client foundation §5): devices with `OsFs`,
//! `SqliteIndex` and `HttpServer` against the real server in process, and the event socket
//! telling one device about another's commit.

#![cfg(test)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use oxisoft_drive_chunking::ChunkParams;
use oxisoft_drive_client::http::{Api, Events, HttpServer, Notice, Session, Trust};
use oxisoft_drive_client::{OsFs, SqliteIndex};
use oxisoft_drive_core::{
    Clock, CollectionKeys, Engine, EngineConfig, MassDeleteBrake, SyncReport,
};
use oxisoft_drive_crypto::keys::CollectionKey;
use oxisoft_drive_proto::DeviceId;
use oxisoft_drive_proto::api::Event;
use oxisoft_drive_testkit::COLLECTION;
use oxisoft_drive_testkit::http_server::{Prepared, device_key, prepare, start, stop};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

/// The wall clock.
#[derive(Debug)]
struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    }
}

type RealEngine = Engine<OsFs, HttpServer, SqliteIndex, SystemClock, ChaCha20Rng>;

/// One device: its folder, its index file, its engine.
struct Device {
    folder: tempfile::TempDir,
    index: tempfile::TempDir,
    number: usize,
    engine: RealEngine,
}

const TRUSTED: usize = 1;

fn session(prepared: &Prepared, number: usize) -> Arc<Session> {
    let api = Api::new(&prepared.origin, Trust::System).unwrap();
    Session::new(api, device_key(number))
}

async fn engine(prepared: &Prepared, number: usize, folder: &Path, index: &Path) -> RealEngine {
    let trusted = (0..=TRUSTED)
        .map(|device| {
            let key = device_key(device).verifying_key();
            (DeviceId::from_key(&key), key)
        })
        .collect();
    let config = EngineConfig {
        collection: COLLECTION,
        signing_key: device_key(number),
        // Every device unwraps the same collection key; a seeded RNG stands in for that.
        keys: CollectionKeys::new(CollectionKey::generate(
            &mut ChaCha20Rng::from_seed([77; 32]),
            0,
        )),
        trusted,
        chunk_params: ChunkParams::new(64, 256, 1024).unwrap(),
        conflict_tag: Box::new(move |_| format!("conflict d{number}")),
        is_ignored: Box::new(|_, _| false),
        brake: MassDeleteBrake::default(),
    };
    Engine::open(
        OsFs::open(folder).unwrap(),
        HttpServer::new(session(prepared, number)),
        SqliteIndex::open(&index.join("index.sqlite"))
            .await
            .unwrap(),
        SystemClock,
        ChaCha20Rng::seed_from_u64(u64::try_from(number).unwrap() + 100),
        config,
    )
    .await
    .unwrap()
}

impl Device {
    async fn new(prepared: &Prepared, number: usize) -> Self {
        let (folder, index) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let engine = engine(prepared, number, folder.path(), index.path()).await;
        engine.init_folder().await.unwrap();
        Self {
            folder,
            index,
            number,
            engine,
        }
    }

    async fn sync(&mut self) -> SyncReport {
        self.engine.sync_once(false).await.unwrap()
    }

    /// Opens the engine again from its index, as after a restart.
    async fn restart(&mut self, prepared: &Prepared) {
        self.engine = engine(prepared, self.number, self.folder.path(), self.index.path()).await;
    }

    fn write(&self, at: &str, bytes: &[u8]) {
        let full = self.folder.path().join(at);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, bytes).unwrap();
    }

    fn path(&self, at: &str) -> std::path::PathBuf {
        self.folder.path().join(at)
    }

    /// Everything in the folder but the engine's own: path → content (`None` for folders).
    fn tree(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        let mut tree = BTreeMap::new();
        walk(self.folder.path(), "", &mut tree);
        tree
    }
}

fn walk(dir: &Path, prefix: &str, tree: &mut BTreeMap<String, Option<Vec<u8>>>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if prefix.is_empty() && name == ".oxidrive" {
            continue;
        }
        let at = format!("{prefix}{name}");
        if entry.file_type().unwrap().is_dir() {
            tree.insert(at.clone(), None);
            walk(&entry.path(), &format!("{at}/"), tree);
        } else {
            tree.insert(at, Some(std::fs::read(entry.path()).unwrap()));
        }
    }
}

async fn next_event(events: &mut Events) -> Notice {
    tokio::time::timeout(Duration::from_secs(10), events.next())
        .await
        .unwrap()
        .unwrap()
}

#[test]
fn two_devices_sync_real_folders_over_http() {
    let prepared = prepare(TRUSTED, None, "");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let server = start(&prepared).await;
        let mut a = Device::new(&prepared, 0).await;
        let mut b = Device::new(&prepared, 1).await;

        let mut big = vec![0; 20_000];
        ChaCha20Rng::from_seed([5; 32]).fill_bytes(&mut big);
        a.write("notes.txt", b"hello");
        a.write("docs/big.bin", &big);
        std::fs::create_dir_all(a.path("empty")).unwrap();
        assert_eq!(a.sync().await.commits, 1);
        b.sync().await;
        assert_eq!(b.tree(), a.tree());
        assert_eq!(b.tree()["docs/big.bin"].as_deref(), Some(big.as_slice()));

        // B hears of A's next commit over the event socket.
        let mut events = Events::start(session(&prepared, 1));
        assert_eq!(next_event(&mut events).await, Notice::Connected);
        a.write("notes.txt", b"hello again");
        a.sync().await;
        let seq = a.engine.state().head.unwrap().seq;
        assert_eq!(
            next_event(&mut events).await,
            Notice::Event(Event::Head {
                collection: COLLECTION,
                seq
            })
        );
        b.sync().await;
        assert_eq!(b.tree(), a.tree());

        // A rename on B arrives as a rename; both edit one file: a conflict copy, nothing lost.
        std::fs::rename(b.path("docs"), b.path("documents")).unwrap();
        b.sync().await;
        a.write("notes.txt", b"from a");
        b.write("notes.txt", b"from b, longer");
        a.sync().await;
        let report = b.sync().await;
        assert_eq!(report.conflicts.len(), 1, "{report:?}");
        a.sync().await;
        assert_eq!(b.tree(), a.tree());
        let tree = a.tree();
        assert!(tree.contains_key("documents/big.bin"));
        assert!(!tree.contains_key("docs"));
        let contents: Vec<&[u8]> = tree.values().filter_map(Option::as_deref).collect();
        assert!(contents.contains(&b"from a".as_slice()));
        assert!(contents.contains(&b"from b, longer".as_slice()));

        // A delete; then B restarts from its index and has nothing to do.
        std::fs::remove_file(a.path("documents/big.bin")).unwrap();
        a.sync().await;
        b.sync().await;
        assert!(!b.tree().contains_key("documents/big.bin"));
        b.restart(&prepared).await;
        assert_eq!(b.sync().await.planned, 0);

        // The event socket reconnects after the server restarts.
        stop(server).await;
        // Head events of the later commits come first.
        loop {
            match next_event(&mut events).await {
                Notice::Disconnected(_) => break,
                Notice::Event(Event::Head { .. }) => {}
                other @ (Notice::Connected | Notice::Event(_)) => panic!("unexpected {other:?}"),
            }
        }
        let server = start(&prepared).await;
        loop {
            match next_event(&mut events).await {
                Notice::Connected => break,
                Notice::Disconnected(_) => {}
                other @ Notice::Event(_) => panic!("unexpected {other:?}"),
            }
        }
        drop(events);
        stop(server).await;
    });
}
