//! Backup and restore end to end (server binary §5–§7, S4): a server in use is backed up, the
//! backup restored into an empty server, and a new device syncs exactly the tree of the
//! snapshot; repeat backups copy only what changed; backups racing garbage collection always
//! restore cleanly; and what a restore can't trust, it refuses. PostgreSQL runs on the Linux
//! job, with `OXIDRIVE_TEST_POSTGRES_URL` and `OXIDRIVE_TEST_PG_TOOLS` (a command prefix that
//! runs PostgreSQL's client tools); without them those tests fail (server crate G3).

#![cfg(test)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use oxisoft_drive_core::{FsRules, RelPath};
use oxisoft_drive_crypto::hash::Digest;
use oxisoft_drive_proto::api::PatchCollection;
use oxisoft_drive_proto::{AccountId, ChunkId, CollectionId};
use oxisoft_drive_server::backup::{self, BackupError, BackupReport, MANIFEST, Restored};
use oxisoft_drive_server::config::{Config, Database};
use oxisoft_drive_server::{
    BlobKey, BlobStore, FsBlobStore, RestoreReport, Service, Settings, SystemClock,
};
use oxisoft_drive_server_postgres::PostgresStore;
use oxisoft_drive_server_sqlite::SqliteStore;
use oxisoft_drive_server_store::{MetaStore, NewAccount, NewChunk, NewCollection};
use oxisoft_drive_testkit::{
    ACCOUNT, COLLECTION, ServiceServer, Tree, World, new_postgres_database,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

fn path(text: &str) -> RelPath {
    RelPath::parse(text).unwrap()
}

/// Which backend a test runs on.
#[derive(Clone)]
enum Backend {
    Sqlite,
    Postgres { base: String, tools: Vec<String> },
}

impl Backend {
    fn postgres() -> Self {
        let base = std::env::var("OXIDRIVE_TEST_POSTGRES_URL")
            .expect("OXIDRIVE_TEST_POSTGRES_URL must point at a PostgreSQL server for this test");
        let tools = std::env::var("OXIDRIVE_TEST_PG_TOOLS")
            .expect("OXIDRIVE_TEST_PG_TOOLS must name a command prefix running pg_dump/pg_restore")
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        Self::Postgres { base, tools }
    }

    /// A new, empty database: its config value.
    fn database(&self) -> String {
        match self {
            Self::Sqlite => "sqlite".to_owned(),
            Self::Postgres { base, .. } => runtime().block_on(new_postgres_database(base)).unwrap(),
        }
    }

    /// The config of a server in `data_dir` on `database`, with this garbage grace period.
    fn config(&self, data_dir: &Path, database: &str, grace: &str) -> Config {
        let tools = match self {
            Self::Sqlite => String::new(),
            Self::Postgres { tools, .. } => {
                let list = |tool: &str| {
                    let mut words: Vec<String> =
                        tools.iter().map(|word| format!("{word:?}")).collect();
                    words.push(format!("{tool:?}"));
                    format!("[{}]", words.join(", "))
                };
                format!(
                    "[backup]\npg_dump = {}\npg_restore = {}\n",
                    list("pg_dump"),
                    list("pg_restore")
                )
            }
        };
        let text = format!(
            "[server]\nlisten = [\"127.0.0.1:0\"]\norigin = \"https://drive.example.com\"\n\
             [storage]\ndata_dir = '{}'\ndatabase = \"{database}\"\n\
             [maintenance]\ngarbage_grace = \"{grace}\"\n{tools}",
            data_dir.display()
        );
        Config::parse(&text, Path::new("server.toml"), None).unwrap()
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

/// Runs `backup` as the CLI does: in its own process (here, runtime), with its own store.
fn run_backup(config: &Config, dir: &Path) -> Result<BackupReport, BackupError> {
    runtime().block_on(async {
        let sqlite = match config.database {
            Database::Sqlite => Some(SqliteStore::open(&config.sqlite_path()).await.unwrap()),
            Database::Postgres(_) => None,
        };
        backup::backup(config, sqlite.as_ref(), dir).await
    })
}

fn run_restore(config: &Config, dir: &Path) -> Result<Restored, BackupError> {
    runtime().block_on(backup::restore(config, dir))
}

/// Copies a directory tree.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Engine devices on the real service, either backend.
trait Server: oxisoft_drive_core::ServerApi + Sized + 'static {
    fn open(
        backend: &Backend,
        database: &str,
        data_dir: &Path,
        trusted: Option<usize>,
        settings: Settings,
    ) -> Self;
    fn gc(&self);
    fn end_leases(&self);
    fn repair(&self) -> RestoreReport;
    fn retention_zero(&self);
}

macro_rules! server_impl {
    ($store:ty, $open:expr) => {
        impl Server for ServiceServer<$store> {
            fn open(
                _backend: &Backend,
                database: &str,
                data_dir: &Path,
                trusted: Option<usize>,
                settings: Settings,
            ) -> Self {
                let open: fn(&str, &Path, Option<usize>, Settings) -> Self = $open;
                open(database, data_dir, trusted, settings)
            }

            fn gc(&self) {
                self.run(async {
                    self.service().prune().await.unwrap();
                    self.service().collect_garbage().await.unwrap();
                });
            }

            fn end_leases(&self) {
                // As if every upload lease had run out.
                self.run(self.service().meta().drop_expired_leases(u64::MAX))
                    .unwrap();
            }

            fn repair(&self) -> RestoreReport {
                self.run(self.service().repair_after_restore()).unwrap()
            }

            fn retention_zero(&self) {
                self.run(self.service().patch_collection(
                    ACCOUNT,
                    COLLECTION,
                    &PatchCollection {
                        retention_days: Some(0),
                        config: None,
                    },
                ))
                .unwrap();
            }
        }
    };
}

server_impl!(SqliteStore, |_, dir, trusted, settings| {
    ServiceServer::sqlite_at(dir, trusted, settings).unwrap()
});
server_impl!(PostgresStore, |url, dir, trusted, settings| {
    ServiceServer::postgres_at(url, dir, trusted, settings).unwrap()
});

/// A server in use, backed up twice (the second time into a copy of the first backup, so
/// only what changed is copied); each backup restores into an empty server, where a device
/// that never synced gets exactly the tree of that snapshot.
fn round_trip<S: Server>(backend: &Backend) {
    let root = tempfile::tempdir().unwrap();
    let source_dir = root.path().join("source");
    let source_db = backend.database();
    // The service deletes garbage at once, so the second backup has objects to drop; the
    // backup's own check uses the config's (generous) grace period.
    let settings = Settings {
        garbage_grace_ms: 0,
        ..Settings::default()
    };
    let config = backend.config(&source_dir, &source_db, "1d");
    let world = World::with_server(
        FsRules::default(),
        2,
        S::open(backend, &source_db, &source_dir, Some(2), settings),
    );
    let mut a = world.device(0).unwrap();
    let mut b = world.device(1).unwrap();
    let mut big = vec![0; 20_000];
    ChaCha20Rng::from_seed([3; 32]).fill_bytes(&mut big);
    a.fs.write(&path("notes.txt"), b"first");
    a.fs.write(&path("docs/big.bin"), &big);
    a.fs.write(&path("docs/small.txt"), b"small");
    a.fs.mkdir(&path("empty"));
    a.sync().unwrap();
    b.sync().unwrap();
    b.fs.write(&path("notes.txt"), b"second");
    b.fs.remove(&path("docs/small.txt"));
    b.sync().unwrap();
    a.sync().unwrap();
    let first: Tree = a.tree();
    assert_eq!(b.tree(), first);

    let one = root.path().join("one");
    let report = run_backup(&config, &one).unwrap();
    assert!(report.manifest.objects > 20, "{report:?}");
    assert_eq!(report.copied, report.manifest.objects);
    assert_eq!((report.kept, report.removed), (0, 0));

    // More work: the big file goes (and with retention 0, its chunks), a new one comes.
    world.server.inner().retention_zero();
    a.fs.remove(&path("docs/big.bin"));
    a.fs.write(&path("later.txt"), b"after the first backup");
    a.sync().unwrap();
    world.server.inner().end_leases();
    world.server.inner().gc();
    let second: Tree = a.tree();
    let two = root.path().join("two");
    copy_dir(&one, &two);
    let report = run_backup(&config, &two).unwrap();
    assert!(
        report.copied > 0 && report.copied < report.manifest.objects,
        "{report:?}"
    );
    assert!(report.kept > 0 && report.removed > 0, "{report:?}");

    for (backup, expected) in [(&one, &first), (&two, &second)] {
        let target_dir = root.path().join(format!(
            "target-{}",
            backup.file_name().unwrap().to_string_lossy()
        ));
        let target_db = backend.database();
        let target = backend.config(&target_dir, &target_db, "1d");
        let restored = run_restore(&target, backup).unwrap();
        let manifest = backup::read_manifest(backup).unwrap().unwrap();
        assert_eq!(restored.objects, manifest.objects);
        let server = S::open(backend, &target_db, &target_dir, None, Settings::default());
        let repaired = server.repair();
        assert!(repaired.is_clean(), "{repaired:?}");
        assert_eq!((repaired.forgotten, repaired.orphans_removed), (0, 0));
        let fresh_world = World::with_server(FsRules::default(), 2, server);
        let mut fresh = fresh_world.device(2).unwrap();
        fresh.sync().unwrap();
        assert_eq!(&fresh.tree(), expected);
        // The restored server takes new work.
        fresh.fs.write(&path("after restore.txt"), b"new");
        assert_eq!(fresh.sync().unwrap().commits, 1);
    }
}

#[test]
fn backup_and_restore_round_trip_on_sqlite() {
    round_trip::<ServiceServer<SqliteStore>>(&Backend::Sqlite);
}

#[test]
fn backup_and_restore_round_trip_on_postgres() {
    round_trip::<ServiceServer<PostgresStore>>(&Backend::postgres());
}

/// A chunk ID from a number.
fn chunk_id(n: u64) -> ChunkId {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&n.to_le_bytes());
    ChunkId(Digest::from_bytes(bytes))
}

const RACE_ACCOUNT: AccountId = AccountId::from_bytes([4; 16]);
const RACE_COLLECTION: CollectionId = CollectionId::from_bytes([6; 16]);

async fn setup_collection<M: MetaStore>(store: &M) {
    store
        .create_account(&NewAccount {
            id: RACE_ACCOUNT,
            signing_key: vec![0; 32],
            kem_key: Vec::new(),
            quota_bytes: u64::MAX,
            created_ms: 1,
        })
        .await
        .unwrap();
    store
        .create_collection(&NewCollection {
            id: RACE_COLLECTION,
            account: RACE_ACCOUNT,
            config: Vec::new(),
            retention_days: 30,
            created_ms: 1,
            key: None,
        })
        .await
        .unwrap();
}

/// Stores chunks nothing references (garbage at once) while garbage collection with a short
/// grace period runs, and backs up `rounds` times meanwhile. A backup either completes and
/// restores into an empty server cleanly, or takes longer than the grace period and is
/// refused; never one that completes broken. Most rounds must complete (a slow machine may
/// refuse some), and across them the restores had objects uploaded after the snapshot to
/// remove.
async fn race<M: MetaStore + 'static>(
    store: M,
    backend: &Backend,
    root: &Path,
    source: &Config,
    rounds: usize,
    open_target: impl AsyncFn(&str) -> M,
) {
    setup_collection(&store).await;
    let objects = FsBlobStore::new(&source.objects_dir()).unwrap();
    let service = Arc::new(Service::new(
        store,
        objects.clone(),
        SystemClock,
        ChaCha20Rng::seed_from_u64(0),
        source.settings,
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let next = Arc::new(AtomicU64::new(0));
    let writer = tokio::spawn({
        let (service, stop, next) = (Arc::clone(&service), Arc::clone(&stop), Arc::clone(&next));
        async move {
            let mut rng = ChaCha20Rng::seed_from_u64(1);
            while !stop.load(Ordering::Relaxed) {
                let chunk = chunk_id(next.fetch_add(1, Ordering::Relaxed));
                let size = 10 + usize::try_from(rng.next_u32() % 2000).unwrap();
                let key = BlobKey::new(RACE_ACCOUNT, RACE_COLLECTION, chunk);
                objects.put(&key, &vec![7; size]).await.unwrap();
                service
                    .meta()
                    .add_chunk(&NewChunk {
                        collection: RACE_COLLECTION,
                        chunk,
                        size: size as u64,
                        stored_ms: 1,
                    })
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    });
    let collector = tokio::spawn({
        let (service, stop) = (Arc::clone(&service), Arc::clone(&stop));
        async move {
            while !stop.load(Ordering::Relaxed) {
                service.collect_garbage().await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    });
    // Let garbage build up and outlive the grace period, so collection deletes during backups.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let (mut orphans, mut forgotten, mut refused) = (0, 0, 0);
    let dir = root.join("backup");
    for round in 0..rounds {
        let sqlite = match source.database {
            Database::Sqlite => Some(SqliteStore::open(&source.sqlite_path()).await.unwrap()),
            Database::Postgres(_) => None,
        };
        match backup::backup(source, sqlite.as_ref(), &dir).await {
            Ok(_) => {}
            Err(BackupError::TooSlow { .. }) => {
                refused += 1;
                continue;
            }
            Err(error) => panic!("round {round}: {error}"),
        }
        let target_dir = root.join(format!("target{round}"));
        let target_db = match backend {
            Backend::Sqlite => "sqlite".to_owned(),
            Backend::Postgres { base, .. } => new_postgres_database(base).await.unwrap(),
        };
        let target = backend.config(&target_dir, &target_db, "3s");
        backup::restore(&target, &dir).await.unwrap();
        let store = match target.database {
            Database::Sqlite => open_target(&target.sqlite_path().to_string_lossy()).await,
            Database::Postgres(ref url) => open_target(url).await,
        };
        let restored = Service::new(
            store,
            FsBlobStore::new(&target.objects_dir()).unwrap(),
            SystemClock,
            ChaCha20Rng::seed_from_u64(2),
            target.settings,
        );
        let report = restored.repair_after_restore().await.unwrap();
        assert!(report.is_clean(), "round {round}: {report:?}");
        assert!(restored.fsck().await.unwrap().is_clean(), "round {round}");
        orphans += report.orphans_removed;
        forgotten += report.forgotten;
    }
    stop.store(true, Ordering::Relaxed);
    writer.await.unwrap();
    collector.await.unwrap();
    assert!(next.load(Ordering::Relaxed) > 100);
    assert!(
        refused * 2 <= rounds,
        "{refused} of {rounds} backups took longer than the grace period"
    );
    assert!(
        orphans > 0,
        "no backup ever raced an upload (forgotten: {forgotten})"
    );
}

fn race_config(backend: &Backend, root: &Path, database: &str) -> Config {
    backend.config(&root.join("source"), database, "3s")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backups_race_garbage_collection_on_sqlite() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::Sqlite;
    let config = race_config(&backend, root.path(), "sqlite");
    std::fs::create_dir_all(&config.data_dir).unwrap();
    let store = SqliteStore::open(&config.sqlite_path()).await.unwrap();
    race(
        store,
        &backend,
        root.path(),
        &config,
        30,
        async |path: &str| SqliteStore::open(Path::new(path)).await.unwrap(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backups_race_garbage_collection_on_postgres() {
    let root = tempfile::tempdir().unwrap();
    let backend = Backend::postgres();
    let Backend::Postgres { base, .. } = &backend else {
        unreachable!()
    };
    let database = new_postgres_database(base).await.unwrap();
    let config = race_config(&backend, root.path(), &database);
    let store = PostgresStore::open(&database).await.unwrap();
    race(
        store,
        &backend,
        root.path(),
        &config,
        10,
        async |url: &str| PostgresStore::open(url).await.unwrap(),
    )
    .await;
}

/// A server with some objects, backed up with `grace`.
fn small_server(root: &Path, grace: &str) -> Config {
    let config = Backend::Sqlite.config(&root.join("source"), "sqlite", grace);
    std::fs::create_dir_all(&config.data_dir).unwrap();
    runtime().block_on(async {
        let store = SqliteStore::open(&config.sqlite_path()).await.unwrap();
        setup_collection(&store).await;
        let objects = FsBlobStore::new(&config.objects_dir()).unwrap();
        for n in 0..50 {
            let chunk = chunk_id(n);
            objects
                .put(
                    &BlobKey::new(RACE_ACCOUNT, RACE_COLLECTION, chunk),
                    &[1; 100],
                )
                .await
                .unwrap();
            store
                .add_chunk(&NewChunk {
                    collection: RACE_COLLECTION,
                    chunk,
                    size: 100,
                    stored_ms: 1,
                })
                .await
                .unwrap();
        }
    });
    config
}

#[test]
fn a_backup_outlasting_the_grace_period_fails_and_cant_be_restored() {
    let root = tempfile::tempdir().unwrap();
    let config = small_server(root.path(), "1ns");
    let dir = root.path().join("backup");
    match run_backup(&config, &dir) {
        Err(error @ BackupError::TooSlow { .. }) => {
            assert!(error.to_string().contains("garbage_grace"), "{error}");
        }
        other => panic!("expected TooSlow, got {other:?}"),
    }
    assert!(!dir.join(MANIFEST).exists());
    let target = Backend::Sqlite.config(&root.path().join("target"), "sqlite", "1d");
    let refused = run_restore(&target, &dir).unwrap_err();
    assert!(refused.to_string().contains("never completed"), "{refused}");
}

#[test]
fn a_restore_refuses_what_it_cant_trust() {
    let root = tempfile::tempdir().unwrap();
    let config = small_server(root.path(), "1d");
    let dir = root.path().join("backup");
    run_backup(&config, &dir).unwrap();
    let manifest = std::fs::read_to_string(dir.join(MANIFEST)).unwrap();
    let target = |name: &str| Backend::Sqlite.config(&root.path().join(name), "sqlite", "1d");
    let edited = |from: &str, to: &str, name: &str| -> String {
        std::fs::write(dir.join(MANIFEST), manifest.replace(from, to)).unwrap();
        let error = run_restore(&target(name), &dir).unwrap_err().to_string();
        std::fs::write(dir.join(MANIFEST), &manifest).unwrap();
        error
    };
    assert!(edited("format = 1", "format = 9", "a").contains("format 9"));
    assert!(
        edited("schema_version = 3", "schema_version = 99", "b").contains("newer than this one")
    );
    assert!(
        edited("backend = \"sqlite\"", "backend = \"postgres\"", "c").contains("postgres server")
    );
    assert!(edited("bytes = ", "extra = 1\nbytes = ", "d").contains("manifest.toml"));
    // A target with objects already.
    let busy = target("e");
    std::fs::create_dir_all(busy.objects_dir().join("x")).unwrap();
    assert!(
        run_restore(&busy, &dir)
            .unwrap_err()
            .to_string()
            .contains("isn't empty")
    );
    // And a good one works.
    let good = target("f");
    let restored = run_restore(&good, &dir).unwrap();
    assert_eq!(restored.objects, 50);
    let _: PathBuf = good.data_dir;
}
