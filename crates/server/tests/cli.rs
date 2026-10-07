//! The admin command line in process (server binary §4, §7): each command's output and exit
//! code, on SQLite and on PostgreSQL (the Linux job; server crate G3).

#![cfg(test)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oxisoft_drive_crypto::hash::{self, Digest};
use oxisoft_drive_crypto::keys::{AccountKey, AccountSigningKey, DeviceIdentity};
use oxisoft_drive_proto::{
    AccountId, CertificateHash, ChunkId, CollectionId, DEVICE_FORMAT, DeviceCertificate,
    DeviceEntry, DeviceList, Signed,
};
use oxisoft_drive_server::{BlobKey, BlobStore, FsBlobStore};
use oxisoft_drive_server_postgres::PostgresStore;
use oxisoft_drive_server_sqlite::SqliteStore;
use oxisoft_drive_server_store::{
    MetaStore, NewAccount, NewChunk, NewCollection, StoredCertificate, StoredDeviceList,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// What a command did.
struct Ran {
    code: ExitCode,
    out: String,
    err: String,
}

/// A server directory with its config file.
struct Server {
    dir: tempfile::TempDir,
    config: PathBuf,
    database: String,
}

impl Server {
    fn sqlite() -> Self {
        Self::new("sqlite", "")
    }

    fn new(database: &str, extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("server.toml");
        std::fs::write(
            &config,
            format!(
                "[server]\nlisten = [\"127.0.0.1:0\"]\norigin = \"https://drive.example.com\"\n\
                 [storage]\ndata_dir = '{}'\ndatabase = \"{database}\"\n{extra}",
                dir.path().join("data").display()
            ),
        )
        .unwrap();
        Self {
            dir,
            config,
            database: database.to_owned(),
        }
    }

    fn data(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn run(&self, args: &[&str]) -> Ran {
        self.answer("", args)
    }

    /// Runs a command with `input` as what the user types.
    fn answer(&self, input: &str, args: &[&str]) -> Ran {
        let config = self.config.to_string_lossy().into_owned();
        let mut all = vec!["oxidrive-server", "--config", config.as_str()];
        all.extend_from_slice(args);
        run(&all, input)
    }
}

/// Runs a command line on a thread of its own: the CLI starts its own runtime, which it
/// can't inside a test's.
fn run(args: &[&str], input: &str) -> Ran {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let (mut out, mut err) = (Vec::new(), Vec::new());
                let code =
                    oxisoft_drive_server::cli::run(args, &mut input.as_bytes(), &mut out, &mut err);
                Ran {
                    code,
                    out: String::from_utf8(out).unwrap(),
                    err: String::from_utf8(err).unwrap(),
                }
            })
            .join()
            .unwrap()
    })
}

fn ok(ran: &Ran) {
    assert_eq!(
        ran.code,
        ExitCode::SUCCESS,
        "out: {}\nerr: {}",
        ran.out,
        ran.err
    );
}

fn failed(ran: &Ran) {
    assert_eq!(
        ran.code,
        ExitCode::FAILURE,
        "out: {}\nerr: {}",
        ran.out,
        ran.err
    );
}

/// A signed device list trusting one new device, and that device's certificate.
fn signed_list(
    account: AccountId,
    seed: u64,
) -> (AccountSigningKey, StoredDeviceList, StoredCertificate) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let signing = AccountSigningKey::generate(&mut rng);
    let meta = AccountKey::generate(&mut rng, 0).meta();
    let identity = DeviceIdentity::generate(&mut rng);
    let certificate = DeviceCertificate::new(
        account,
        (identity.verifying_key(), identity.kem_public_key()),
        "laptop",
        &meta,
        &mut rng,
        0,
    )
    .unwrap();
    let certificate = Signed::sign(signing.signing_key(), &certificate);
    let device = certificate.decode_unverified().unwrap().device;
    let list = DeviceList {
        format: DEVICE_FORMAT,
        account,
        version: 1,
        devices: vec![DeviceEntry {
            device,
            certificate: CertificateHash(certificate.hash()),
        }],
        revoked: Vec::new(),
    };
    let list = Signed::sign(signing.signing_key(), &list);
    (
        signing,
        StoredDeviceList {
            version: 1,
            signed: minicbor::to_vec(&list).unwrap(),
        },
        StoredCertificate {
            device,
            signed: minicbor::to_vec(&certificate).unwrap(),
        },
    )
}

fn new_account(id: AccountId, signing: &AccountSigningKey) -> NewAccount {
    NewAccount {
        id,
        signing_key: signing.verifying_key().to_bytes().to_vec(),
        kem_key: Vec::new(),
        quota_bytes: u64::MAX,
        created_ms: 1_790_000_000_000,
    }
}

const ALICE: AccountId = AccountId::from_bytes([0xab; 16]);
const BOB: AccountId = AccountId::from_bytes([0xac; 16]);

/// Invites, accounts and every user command, against `store` (the server's database).
async fn users<S: MetaStore>(server: &Server, store: &S) {
    let invite = server.run(&["invite", "create", "--label", "alice", "--expires", "2d"]);
    ok(&invite);
    let code = invite
        .out
        .lines()
        .find_map(|line| line.strip_prefix("invite code: "))
        .unwrap()
        .to_owned();
    assert!(invite.out.contains("label:       alice"), "{}", invite.out);
    assert!(invite.out.contains("(in 2days)"), "{}", invite.out);
    // The device creates its account with the code.
    let (signing, list, certificate) = signed_list(ALICE, 1);
    store
        .create_account_by_invite(
            *hash::hash(code.as_bytes()).as_bytes(),
            1_790_000_000_000,
            &new_account(ALICE, &signing),
            &list,
            &certificate,
            &[],
        )
        .await
        .unwrap();
    let (other, _, _) = signed_list(BOB, 2);
    store
        .create_account(&new_account(BOB, &other))
        .await
        .unwrap();
    // An invite without a label says nothing about one.
    let unlabelled = server.run(&["invite", "create"]);
    ok(&unlabelled);
    assert!(!unlabelled.out.contains("label:"));

    let listed = server.run(&["user", "list"]);
    ok(&listed);
    let lines: Vec<&str> = listed.out.lines().collect();
    assert!(lines[0].starts_with("ID "), "{}", listed.out);
    assert!(lines[1].starts_with(&"ab".repeat(16)), "{}", listed.out);
    assert!(lines[1].contains("alice  active  1"), "{}", listed.out);
    assert!(lines[1].contains("0 B / unlimited"), "{}", listed.out);
    assert!(lines[2].starts_with(&"ac".repeat(16)), "{}", listed.out);
    let json = server.run(&["user", "list", "--json"]);
    ok(&json);
    let rows: serde_json::Value = serde_json::from_str(&json.out).unwrap();
    assert_eq!(rows[0]["label"], "alice");
    assert_eq!(rows[0]["devices"], 1);
    assert_eq!(rows[0]["quota_bytes"], serde_json::Value::Null);
    assert_eq!(rows[1]["devices"], 0);

    // Prefixes: unique, ambiguous, unknown, not hex.
    ok(&server.run(&["user", "quota", "AB", "1 GB"]));
    let quota = server.run(&["user", "list", "--json"]);
    let rows: serde_json::Value = serde_json::from_str(&quota.out).unwrap();
    assert_eq!(rows[0]["quota_bytes"], 1_000_000_000);
    for (prefix, needle) in [
        ("a", "more than one"),
        ("ff", "no account"),
        ("zz", "isn't an account ID"),
        ("", "isn't an account ID"),
    ] {
        let refused = server.run(&["user", "disable", prefix]);
        failed(&refused);
        assert!(refused.err.contains(needle), "{prefix}: {}", refused.err);
    }
    let bad = server.run(&["user", "quota", "ab", "plenty"]);
    failed(&bad);
    assert!(bad.err.contains("500 GB"), "{}", bad.err);
    ok(&server.run(&["user", "quota", "ab", "unlimited"]));

    // Deleting: only a disabled account, and only when confirmed.
    let active = server.run(&["user", "delete", "ab", "--yes"]);
    failed(&active);
    assert!(
        active.err.contains("only a disabled account"),
        "{}",
        active.err
    );
    let disabled = server.run(&["user", "disable", "ab"]);
    ok(&disabled);
    assert!(disabled.out.contains("signed out"));
    let declined = server.answer("n\n", &["user", "delete", "ab"]);
    failed(&declined);
    assert!(
        declined
            .out
            .contains("(alice)? Its data will be freed. [y/N] not deleted"),
        "{}",
        declined.out
    );
    ok(&server.run(&["user", "enable", "ab"]));
    ok(&server.run(&["user", "disable", "ab"]));
    let deleted = server.answer("yes\n", &["user", "delete", "ab"]);
    ok(&deleted);
    assert!(
        deleted
            .out
            .contains("deleted; garbage collection frees its data")
    );
    let gone = server.run(&["user", "enable", "ab"]);
    failed(&gone);
    assert!(gone.err.contains("deleted"), "{}", gone.err);
    assert!(server.run(&["user", "list"]).out.contains("deleted"));
    ok(&server.run(&["user", "disable", "ac"]));
    ok(&server.run(&["user", "delete", "ac", "--yes"]));
}

/// gc and fsck, with an orphan object and a missing one.
async fn maintenance<S: MetaStore>(server: &Server, store: &S) {
    let gc = server.run(&["gc"]);
    ok(&gc);
    assert!(
        gc.out.contains("deleted chunks:      0 (0 B)"),
        "{}",
        gc.out
    );
    assert!(gc.out.contains("(deleted after 1day)"), "{}", gc.out);
    let json: serde_json::Value = serde_json::from_str(&server.run(&["gc", "--json"]).out).unwrap();
    assert_eq!(json["deleted_chunks"], 0);
    let clean = server.run(&["fsck"]);
    ok(&clean);
    assert_eq!(clean.out, "clean\n");

    let (signing, _, _) = signed_list(ALICE, 3);
    store
        .create_account(&new_account(ALICE, &signing))
        .await
        .unwrap();
    let collection = CollectionId::from_bytes([7; 16]);
    store
        .create_collection(&NewCollection {
            id: collection,
            account: ALICE,
            config: Vec::new(),
            retention_days: 30,
            created_ms: 1,
            key: None,
        })
        .await
        .unwrap();
    let objects = FsBlobStore::new(&server.data().join("objects")).unwrap();
    let orphan = BlobKey::new(ALICE, collection, ChunkId(Digest::from_bytes([1; 32])));
    objects.put(&orphan, b"left by a crash").await.unwrap();
    let found = server.run(&["fsck"]);
    failed(&found);
    assert!(
        found
            .out
            .starts_with(&format!("orphan object: {}/", "ab".repeat(16))),
        "{}",
        found.out
    );
    assert!(found.out.contains("only orphans"), "{}", found.out);
    let json: serde_json::Value =
        serde_json::from_str(&server.run(&["fsck", "--json"]).out).unwrap();
    assert_eq!(json["clean"], false);
    assert_eq!(json["orphan_objects"].as_array().unwrap().len(), 1);

    // Not while a server runs.
    store.beat("serve", now_ms()).await.unwrap();
    let refused = server.run(&["fsck", "--remove-orphans"]);
    failed(&refused);
    assert!(
        refused.err.contains("the server is running"),
        "{}",
        refused.err
    );
    store.stop_beat("serve").await.unwrap();
    let removed = server.run(&["fsck", "--remove-orphans"]);
    ok(&removed);
    assert_eq!(removed.out, "orphan objects removed: 1\nclean\n");
    assert_eq!(
        objects.size(&orphan).await,
        Err(oxisoft_drive_server::BlobError::NotFound)
    );

    // A row without its object.
    let lost = ChunkId(Digest::from_bytes([2; 32]));
    store
        .add_chunk(&NewChunk {
            collection,
            chunk: lost,
            size: 9,
            stored_ms: 1,
        })
        .await
        .unwrap();
    let missing = server.run(&["fsck"]);
    failed(&missing);
    assert!(
        missing.out.starts_with("missing object: "),
        "{}",
        missing.out
    );
    assert!(!missing.out.contains("only orphans"));
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

#[test]
fn usage_and_config_errors_exit_with_2() {
    let help = run(&["oxidrive-server", "--help"], "");
    assert_eq!(help.code, ExitCode::SUCCESS);
    assert!(help.out.contains("Usage: oxidrive-server"), "{}", help.out);
    let unknown = run(&["oxidrive-server", "frobnicate"], "");
    assert_eq!(unknown.code, ExitCode::from(2));
    assert!(unknown.err.contains("frobnicate"), "{}", unknown.err);
    let dir = tempfile::tempdir().unwrap();
    let missing = dir
        .path()
        .join("nowhere.toml")
        .to_string_lossy()
        .into_owned();
    let absent = run(&["oxidrive-server", "-c", &missing, "gc"], "");
    assert_eq!(absent.code, ExitCode::from(2));
    assert!(absent.err.starts_with("error: ") && absent.err.contains("nowhere.toml"));
    let broken = dir.path().join("broken.toml");
    std::fs::write(&broken, "[server]\nlisten = []\n").unwrap();
    let broken = broken.to_string_lossy().into_owned();
    let wrong = run(&["oxidrive-server", "-c", &broken, "gc"], "");
    assert_eq!(wrong.code, ExitCode::from(2));
    assert!(wrong.err.contains("broken.toml:1:"), "{}", wrong.err);
}

#[test]
fn config_check_opens_the_database() {
    let server = Server::sqlite();
    let checked = server.run(&["config", "check"]);
    ok(&checked);
    assert!(
        checked.out.contains("tls:            off (plain HTTP)"),
        "{}",
        checked.out
    );
    assert!(
        checked.out.contains("database:       sqlite at "),
        "{}",
        checked.out
    );
    assert!(
        checked.out.ends_with("config and database: ok\n"),
        "{}",
        checked.out
    );
    assert!(server.data().join("meta.sqlite").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_on_sqlite() {
    let server = Server::sqlite();
    ok(&server.run(&["config", "check"]));
    let store = SqliteStore::open(&server.data().join("meta.sqlite"))
        .await
        .unwrap();
    users(&server, &store).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_on_sqlite() {
    let server = Server::sqlite();
    ok(&server.run(&["config", "check"]));
    let store = SqliteStore::open(&server.data().join("meta.sqlite"))
        .await
        .unwrap();
    maintenance(&server, &store).await;
}

/// A server on a new, empty PostgreSQL database (fails without
/// `OXIDRIVE_TEST_POSTGRES_URL`).
async fn postgres_server(extra: &str) -> Server {
    let base = std::env::var("OXIDRIVE_TEST_POSTGRES_URL")
        .expect("OXIDRIVE_TEST_POSTGRES_URL must point at a PostgreSQL server for these tests");
    let url = oxisoft_drive_testkit_free::new_database(&base).await;
    Server::new(&url, extra)
}

/// A server on a new PostgreSQL database, and its store.
async fn postgres_server_with_store(extra: &str) -> (Server, PostgresStore) {
    let server = postgres_server(extra).await;
    let store = PostgresStore::open(&server.database).await.unwrap();
    (server, store)
}

/// What the tests run `pg_dump` and `pg_restore` with: `OXIDRIVE_TEST_PG_TOOLS`, a command
/// prefix (such as a container run) that the tool name is appended to.
fn pg_tools() -> String {
    let prefix = std::env::var("OXIDRIVE_TEST_PG_TOOLS").expect(
        "OXIDRIVE_TEST_PG_TOOLS must name a command prefix running PostgreSQL's client tools",
    );
    let words: Vec<String> = prefix
        .split_whitespace()
        .map(|word| format!("{word:?}"))
        .collect();
    let list = |tool: &str| {
        let mut all = words.clone();
        all.push(format!("{tool:?}"));
        format!("[{}]", all.join(", "))
    };
    format!(
        "[backup]\npg_dump = {}\npg_restore = {}\n",
        list("pg_dump"),
        list("pg_restore")
    )
}

/// Creating test databases, as the conformance suite does.
mod oxisoft_drive_testkit_free {
    use std::sync::atomic::{AtomicU64, Ordering};

    use sqlx::Connection;

    pub(super) async fn new_database(base: &str) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!(
            "cli{}_{}_{}",
            std::process::id(),
            stamp,
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let mut admin = sqlx::PgConnection::connect(base).await.unwrap();
        // The name is made of letters, digits and underscores only.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await
            .unwrap();
        let (prefix, _) = base.rsplit_once('/').unwrap();
        format!("{prefix}/{name}")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_on_postgres() {
    let (server, store) = postgres_server_with_store("").await;
    users(&server, &store).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_on_postgres() {
    let (server, store) = postgres_server_with_store("").await;
    maintenance(&server, &store).await;
}

/// Backup into a directory, restore into an empty server, and the refusals on the way.
fn backup_and_restore(source: &Server, target: &Server, foreign: &str) {
    ok(&source.run(&["invite", "create"]));
    let dir = source.dir.path().join("backup");
    let made = source.run(&["backup", dir.to_str().unwrap()]);
    ok(&made);
    assert!(made.out.starts_with("backup complete: "), "{}", made.out);
    assert!(made.out.contains("objects: 0 (0 B)"), "{}", made.out);
    let again = source.run(&["backup", dir.to_str().unwrap()]);
    ok(&again);

    let restored = target.run(&["restore", dir.to_str().unwrap()]);
    ok(&restored);
    assert!(
        restored.out.starts_with("restored the backup of "),
        "{}",
        restored.out
    );
    assert!(restored.out.ends_with("fsck: clean\n"), "{}", restored.out);
    let twice = target.run(&["restore", dir.to_str().unwrap()]);
    failed(&twice);
    assert!(twice.err.contains("restore into an empty"), "{}", twice.err);

    // Not a backup.
    let empty = source.dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let nothing = target.run(&["restore", empty.to_str().unwrap()]);
    failed(&nothing);
    assert!(
        nothing.err.contains("has no manifest.toml"),
        "{}",
        nothing.err
    );
    // A directory with other things in it.
    let busy = source.dir.path().join("busy");
    std::fs::create_dir_all(&busy).unwrap();
    std::fs::write(busy.join("notes.txt"), "mine").unwrap();
    let refused = source.run(&["backup", busy.to_str().unwrap()]);
    failed(&refused);
    assert!(refused.err.contains("notes.txt"), "{}", refused.err);
    // Another backend's backup.
    let other = Path::new(foreign);
    let mismatch = source.run(&["backup", other.to_str().unwrap()]);
    failed(&mismatch);
    assert!(
        mismatch.err.contains("backup, and this server uses"),
        "{}",
        mismatch.err
    );
}

/// A directory holding a (fake) backup of the other backend.
fn foreign_backup(dir: &Path, backend: &str) -> String {
    let path = dir.join("foreign");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(
        path.join("manifest.toml"),
        format!(
            "format = 1\nserver_version = \"0.0.0\"\nschema_version = 1\nbackend = \"{backend}\"\n\
             snapshot_ms = 0\nfinished_ms = 0\nobjects = 0\nbytes = 0\n"
        ),
    )
    .unwrap();
    path.to_string_lossy().into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_and_restore_on_sqlite() {
    let (source, target) = (Server::sqlite(), Server::sqlite());
    let foreign = foreign_backup(source.dir.path(), "postgres");
    backup_and_restore(&source, &target, &foreign);
    assert_eq!(source.database, "sqlite");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_and_restore_on_postgres() {
    let tools = pg_tools();
    let source = postgres_server(&tools).await;
    let target = postgres_server(&tools).await;
    let foreign = foreign_backup(source.dir.path(), "sqlite");
    backup_and_restore(&source, &target, &foreign);
}
