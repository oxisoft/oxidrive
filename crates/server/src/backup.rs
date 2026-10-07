//! Backup and restore (server binary §5, §6, S4).
//!
//! A backup is a directory: a database snapshot (`meta.sqlite` or `meta.pgdump`), the
//! objects in `objects/`, and `manifest.toml`, written last. The snapshot comes first and the
//! objects after it; garbage collection's grace period keeps every object the snapshot needs
//! for that long, so a backup that finishes within it is complete. Objects uploaded after the
//! snapshot come along too; a restore deletes them, and forgets the chunks that were garbage
//! already and whose objects were deleted meanwhile.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use oxisoft_drive_server_postgres::PostgresStore;
use oxisoft_drive_server_sqlite::SqliteStore;
use oxisoft_drive_server_store::StoreError;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt as _;

use crate::blob::{BlobError, BlobKey, BlobStore, FsBlobStore};
use crate::config::{Config, Database};
use crate::service::ServiceError;

/// The manifest's file name.
pub const MANIFEST: &str = "manifest.toml";
const SQLITE_FILE: &str = "meta.sqlite";
const PGDUMP_FILE: &str = "meta.pgdump";
const OBJECTS_DIR: &str = "objects";
/// The manifest format this code writes and reads.
const FORMAT: u32 = 1;
/// Objects handled per listing.
const PAGE: usize = 1000;

/// What a backup holds, written when it is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// This format's version.
    pub format: u32,
    /// The server version that wrote it.
    pub server_version: String,
    /// The database schema (newest migration) of the snapshot.
    pub schema_version: i64,
    /// `sqlite` or `postgres`.
    pub backend: String,
    /// When the database snapshot was taken, milliseconds since the Unix epoch.
    pub snapshot_ms: u64,
    /// When the backup finished.
    pub finished_ms: u64,
    /// Objects in the backup.
    pub objects: u64,
    /// Their bytes.
    pub bytes: u64,
}

/// What a backup did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    /// The manifest written.
    pub manifest: Manifest,
    /// Objects copied this time.
    pub copied: u64,
    /// Objects already in the directory from an earlier backup.
    pub kept: u64,
    /// Objects removed because the server no longer has them.
    pub removed: u64,
}

/// Why a backup or restore failed.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// Refused before anything changed.
    #[error("{0}")]
    Refused(String),
    /// A file operation failed.
    #[error("{what}: {source}")]
    Io {
        /// What was being done.
        what: String,
        /// What went wrong.
        source: std::io::Error,
    },
    /// `pg_dump` or `pg_restore` failed.
    #[error("{program} failed ({status}): {stderr}")]
    Command {
        /// The program.
        program: String,
        /// Its exit status.
        status: String,
        /// What it printed.
        stderr: String,
    },
    /// The backup ran longer than garbage collection's grace period.
    #[error(
        "the backup took {took_s} s, longer than the garbage grace period of {grace_s} s, so \
         it may lack objects; it was not completed (raise maintenance.garbage_grace)"
    )]
    TooSlow {
        /// How long it took.
        took_s: u64,
        /// The grace period.
        grace_s: u64,
    },
    /// The metadata store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The object store failed.
    #[error(transparent)]
    Blob(#[from] BlobError),
    /// The service failed.
    #[error(transparent)]
    Service(#[from] ServiceError),
}

fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> BackupError {
    let what = what.into();
    move |source| BackupError::Io { what, source }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

const fn backend_name(database: &Database) -> &'static str {
    match database {
        Database::Sqlite => "sqlite",
        Database::Postgres(_) => "postgres",
    }
}

fn schema_version(database: &Database) -> i64 {
    match database {
        Database::Sqlite => SqliteStore::schema_version(),
        Database::Postgres(_) => PostgresStore::schema_version(),
    }
}

/// Reads a backup's manifest; `None` if it has none (empty, or never completed).
///
/// # Errors
///
/// [`BackupError`] if it exists but can't be read.
pub fn read_manifest(dir: &Path) -> Result<Option<Manifest>, BackupError> {
    let path = dir.join(MANIFEST);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(format!("reading {}", path.display()))(error)),
    };
    toml::from_str(&text)
        .map(Some)
        .map_err(|error| BackupError::Refused(format!("{}: {}", path.display(), error.message())))
}

/// Writes `bytes` to `path` all or nothing: a temporary file beside it, flushed, renamed.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    use std::io::Write as _;
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".tmp")
        .tempfile_in(dir)
        .map_err(io(format!("writing {}", path.display())))?;
    file.write_all(bytes)
        .and_then(|()| file.as_file().sync_all())
        .map_err(io(format!("writing {}", path.display())))?;
    file.persist(path)
        .map_err(|error| io(format!("writing {}", path.display()))(error.error))?;
    sync_dir(dir)
}

/// Makes a rename durable. Windows can't open directories and journals renames itself.
fn sync_dir(dir: &Path) -> Result<(), BackupError> {
    #[cfg(unix)]
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(io(format!("syncing {}", dir.display())))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Refuses a directory that holds anything but an earlier backup of the same backend.
fn check_target(dir: &Path, database: &Database) -> Result<(), BackupError> {
    std::fs::create_dir_all(dir).map_err(io(format!("creating {}", dir.display())))?;
    let entries = std::fs::read_dir(dir).map_err(io(format!("reading {}", dir.display())))?;
    for entry in entries {
        let name = entry
            .map_err(io(format!("reading {}", dir.display())))?
            .file_name();
        let name = name.to_string_lossy();
        let ours = [MANIFEST, SQLITE_FILE, PGDUMP_FILE, OBJECTS_DIR].contains(&name.as_ref())
            || name.starts_with(".tmp");
        if !ours {
            return Err(BackupError::Refused(format!(
                "{} holds {name}, which isn't part of a backup: use an empty directory or an \
                 earlier backup",
                dir.display()
            )));
        }
    }
    if let Some(manifest) = read_manifest(dir)? {
        let backend = backend_name(database);
        if manifest.backend != backend {
            return Err(BackupError::Refused(format!(
                "{} holds a {} backup, and this server uses {backend}",
                dir.display(),
                manifest.backend
            )));
        }
    }
    Ok(())
}

/// What [`copy_objects`] did.
#[derive(Debug, Default)]
struct Mirrored {
    objects: u64,
    bytes: u64,
    copied: u64,
    kept: u64,
    removed: u64,
}

/// Makes `to` hold exactly the objects `from` has: objects already there with the right size
/// stay (objects never change), the rest are copied, and those `from` no longer has go.
async fn copy_objects(from: &FsBlobStore, to: &FsBlobStore) -> Result<Mirrored, BackupError> {
    let mut copied = Mirrored::default();
    let mut after = None;
    loop {
        let page = from.list(after, PAGE).await?;
        let Some(last) = page.last() else {
            break;
        };
        after = Some(*last);
        for key in page {
            let size = match from.size(&key).await {
                Ok(size) => size,
                // Collected meanwhile.
                Err(BlobError::NotFound) => continue,
                Err(error) => return Err(error.into()),
            };
            match to.size(&key).await {
                Ok(existing) if existing == size => copied.kept += 1,
                found => {
                    if found.is_ok() {
                        to.delete(&key).await?;
                    }
                    let object = match from.get(&key).await {
                        Ok(object) => object,
                        Err(BlobError::NotFound) => continue,
                        Err(error) => return Err(error.into()),
                    };
                    to.put(&key, &object).await?;
                    copied.copied += 1;
                }
            }
            copied.objects += 1;
            copied.bytes += size;
        }
    }
    let mut after: Option<BlobKey> = None;
    loop {
        let page = to.list(after, PAGE).await?;
        let Some(last) = page.last() else {
            break;
        };
        after = Some(*last);
        for key in page {
            if matches!(from.size(&key).await, Err(BlobError::NotFound)) {
                to.delete(&key).await?;
                copied.removed += 1;
            }
        }
    }
    Ok(copied)
}

/// Backs the server up into `dir` (server binary §5): an empty directory, or an earlier
/// backup, which is brought up to date. `sqlite` is the open store for a SQLite server.
///
/// # Errors
///
/// [`BackupError`]; the directory then has no manifest, so it can't be restored.
pub async fn backup(
    config: &Config,
    sqlite: Option<&SqliteStore>,
    dir: &Path,
) -> Result<BackupReport, BackupError> {
    check_target(dir, &config.database)?;
    // Whatever happens next, the directory isn't a complete backup until the end.
    match std::fs::remove_file(dir.join(MANIFEST)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(io("removing the old manifest")(error));
        }
        _ => sync_dir(dir)?,
    }
    let started = Instant::now();
    let snapshot_ms = now_ms();
    match (&config.database, sqlite) {
        (Database::Sqlite, Some(store)) => snapshot_sqlite(store, dir).await?,
        (Database::Postgres(url), _) => {
            dump_postgres(&config.pg_dump, url, &dir.join(PGDUMP_FILE)).await?;
        }
        (Database::Sqlite, None) => {
            return Err(BackupError::Refused("no SQLite store to back up".into()));
        }
    }
    let live = FsBlobStore::new(&config.objects_dir())?;
    let target = FsBlobStore::new(&dir.join(OBJECTS_DIR))?;
    let copied = copy_objects(&live, &target).await?;
    let took = started.elapsed();
    let grace_ms = config.settings.garbage_grace_ms;
    if u64::try_from(took.as_millis()).unwrap_or(u64::MAX) >= grace_ms {
        return Err(BackupError::TooSlow {
            took_s: took.as_secs(),
            grace_s: grace_ms / 1000,
        });
    }
    let manifest = Manifest {
        format: FORMAT,
        server_version: env!("CARGO_PKG_VERSION").to_owned(),
        schema_version: schema_version(&config.database),
        backend: backend_name(&config.database).to_owned(),
        snapshot_ms,
        finished_ms: now_ms(),
        objects: copied.objects,
        bytes: copied.bytes,
    };
    let text = toml::to_string(&manifest)
        .map_err(|error| BackupError::Refused(format!("writing the manifest: {error}")))?;
    write_atomically(&dir.join(MANIFEST), text.as_bytes())?;
    Ok(BackupReport {
        manifest,
        copied: copied.copied,
        kept: copied.kept,
        removed: copied.removed,
    })
}

async fn snapshot_sqlite(store: &SqliteStore, dir: &Path) -> Result<(), BackupError> {
    let temporary = dir.join(".tmp-meta.sqlite");
    match std::fs::remove_file(&temporary) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(io("removing an old temporary snapshot")(error));
        }
        _ => {}
    }
    store.snapshot_into(&temporary).await?;
    std::fs::File::open(&temporary)
        .and_then(|file| file.sync_all())
        .map_err(io("syncing the snapshot"))?;
    std::fs::rename(&temporary, dir.join(SQLITE_FILE)).map_err(io("renaming the snapshot"))?;
    sync_dir(dir)
}

/// A PostgreSQL URL without its password, and the password: the password goes to the tools
/// through `PGPASSWORD`, so other users can't read it from the process list.
fn split_password(url: &str) -> (String, Option<String>) {
    let Some((scheme, rest)) = url.split_once("://") else {
        return (url.to_owned(), None);
    };
    let (authority_end, _) = rest
        .char_indices()
        .find(|(_, c)| matches!(c, '/' | '?'))
        .unwrap_or((rest.len(), ' '));
    let (authority, tail) = rest.split_at(authority_end);
    let Some((userinfo, host)) = authority.rsplit_once('@') else {
        return (url.to_owned(), None);
    };
    let Some((user, password)) = userinfo.split_once(':') else {
        return (url.to_owned(), None);
    };
    (
        format!("{scheme}://{user}@{host}{tail}"),
        Some(percent_decode(password)),
    )
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Runs `command` (program and leading arguments) with `args`, the database URL's password
/// in `PGPASSWORD`, `stdin` and `stdout` as given; fails with its error output.
async fn run_tool(
    command: &[String],
    args: &[&str],
    password: Option<&str>,
    stdin: Stdio,
    stdout: Stdio,
) -> Result<(), BackupError> {
    let (program, leading) = command
        .split_first()
        .ok_or_else(|| BackupError::Refused("empty command".into()))?;
    let mut process = tokio::process::Command::new(program);
    process
        .args(leading)
        .args(args)
        .stdin(stdin)
        .stdout(stdout)
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(password) = password {
        process.env("PGPASSWORD", password);
    }
    let mut child = process.spawn().map_err(io(format!("starting {program}")))?;
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)
            .await
            .map_err(io(format!("reading {program}'s output")))?;
    }
    let status = child
        .wait()
        .await
        .map_err(io(format!("waiting for {program}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(BackupError::Command {
            program: program.clone(),
            status: status.to_string(),
            stderr: stderr.trim().to_owned(),
        })
    }
}

async fn dump_postgres(command: &[String], url: &str, path: &Path) -> Result<(), BackupError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let file = tempfile::Builder::new()
        .prefix(".tmp")
        .tempfile_in(dir)
        .map_err(io("creating the dump file"))?;
    let (url, password) = split_password(url);
    let out = file
        .as_file()
        .try_clone()
        .map_err(io("opening the dump file"))?;
    run_tool(
        command,
        &["--format=custom", "--dbname", &url],
        password.as_deref(),
        Stdio::null(),
        Stdio::from(out),
    )
    .await?;
    file.as_file().sync_all().map_err(io("syncing the dump"))?;
    file.persist(path)
        .map_err(|error| io("renaming the dump")(error.error))?;
    sync_dir(dir)
}

/// What a restore found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// The backup's manifest.
    pub manifest: Manifest,
    /// Objects copied.
    pub objects: u64,
}

/// Loads the backup in `dir` into the empty database and object directory `config` names
/// (server binary §6, step 1–4). The caller then opens the store and repairs
/// ([`crate::service::Service::repair_after_restore`]).
///
/// # Errors
///
/// [`BackupError::Refused`] for an incomplete or foreign backup, or a target that isn't
/// empty; others if loading fails.
pub async fn restore(config: &Config, dir: &Path) -> Result<Restored, BackupError> {
    let manifest = read_manifest(dir)?.ok_or_else(|| {
        BackupError::Refused(format!(
            "{} has no {MANIFEST}: not a backup, or one that never completed",
            dir.display()
        ))
    })?;
    if manifest.format != FORMAT {
        return Err(BackupError::Refused(format!(
            "backup format {} is unknown to this server",
            manifest.format
        )));
    }
    let backend = backend_name(&config.database);
    if manifest.backend != backend {
        return Err(BackupError::Refused(format!(
            "the backup is of a {} server, and the config uses {backend}",
            manifest.backend
        )));
    }
    if manifest.schema_version > schema_version(&config.database) {
        return Err(BackupError::Refused(format!(
            "the backup was made by server {}, newer than this one ({}); restore it with that \
             version or newer",
            manifest.server_version,
            env!("CARGO_PKG_VERSION")
        )));
    }
    let objects_dir = config.objects_dir();
    if !is_empty_dir(&objects_dir)? {
        return Err(BackupError::Refused(format!(
            "{} isn't empty: restore into an empty server",
            objects_dir.display()
        )));
    }
    match &config.database {
        Database::Sqlite => {
            let target = config.sqlite_path();
            if std::fs::metadata(&target).is_ok_and(|meta| meta.len() > 0) {
                return Err(BackupError::Refused(format!(
                    "{} exists: restore into an empty server",
                    target.display()
                )));
            }
            std::fs::create_dir_all(&config.data_dir)
                .map_err(io(format!("creating {}", config.data_dir.display())))?;
            let bytes = std::fs::read(dir.join(SQLITE_FILE)).map_err(io("reading the snapshot"))?;
            write_atomically(&target, &bytes)?;
        }
        Database::Postgres(url) => {
            if PostgresStore::has_tables(url).await? {
                return Err(BackupError::Refused(
                    "the PostgreSQL database has tables: restore into an empty database".into(),
                ));
            }
            let dump =
                std::fs::File::open(dir.join(PGDUMP_FILE)).map_err(io("opening the dump"))?;
            let (url, password) = split_password(url);
            run_tool(
                &config.pg_restore,
                &[
                    "--no-owner",
                    "--no-privileges",
                    "--exit-on-error",
                    "--dbname",
                    &url,
                ],
                password.as_deref(),
                Stdio::from(dump),
                Stdio::null(),
            )
            .await?;
        }
    }
    let source = FsBlobStore::new(&dir.join(OBJECTS_DIR))?;
    let target = FsBlobStore::new(&objects_dir)?;
    let copied = copy_objects(&source, &target).await?;
    Ok(Restored {
        manifest,
        objects: copied.objects,
    })
}

fn is_empty_dir(dir: &PathBuf) -> Result<bool, BackupError> {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => Ok(entries.next().is_none()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(io(format!("reading {}", dir.display()))(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::{percent_decode, split_password};

    #[test]
    fn passwords_leave_the_url() {
        assert_eq!(
            split_password("postgres://drive:s%40cret@db:5432/drive?sslmode=require"),
            (
                "postgres://drive@db:5432/drive?sslmode=require".to_owned(),
                Some("s@cret".to_owned())
            )
        );
        assert_eq!(
            split_password("postgres://drive@db/drive"),
            ("postgres://drive@db/drive".to_owned(), None)
        );
        assert_eq!(
            split_password("postgres://db/drive"),
            ("postgres://db/drive".to_owned(), None)
        );
        assert_eq!(split_password("db"), ("db".to_owned(), None));
        assert_eq!(percent_decode("a%2Fb%zz%4"), "a/b%zz%4");
    }
}
