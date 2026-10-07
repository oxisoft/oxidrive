//! The `oxidrive-server` command line (server binary §4). Every command opens the database
//! itself; there is no admin socket and no admin login (R3).
//!
//! [`run`] does the work with the input and outputs given, so tests run commands in process.
//! Exit codes: 0 done, 1 failed (or fsck found problems), 2 a usage or config error.

use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use oxisoft_drive_proto::AccountId;
use oxisoft_drive_server_postgres::PostgresStore;
use oxisoft_drive_server_sqlite::SqliteStore;
use oxisoft_drive_server_store::{AccountStatus, MetaStore, StoreError};
use rand_core::UnwrapErr;

use crate::api::{ServiceOf, With};
use crate::backup::{self, BackupError};
use crate::blob::{BlobError, BlobKey, FsBlobStore};
use crate::config::{self, Config, ConfigError, Database};
use crate::serve::{self, HEARTBEAT, HEARTBEAT_STALE, SHUTDOWN_GRACE, ServeError};
use crate::service::{AccountSummary, Service, ServiceError, SystemClock};

/// The random number generator a live server uses: the operating system's.
pub type Rng = UnwrapErr<getrandom::SysRng>;
/// The types of a live server over metadata store `M`.
pub type Live<M> = With<M, FsBlobStore, SystemClock, Rng>;

/// oxidrive server: stores only encrypted data, orders commits and serves the sync API.
#[derive(Debug, Parser)]
#[command(name = "oxidrive-server", version)]
pub struct Cli {
    /// The config file.
    #[arg(long, short, global = true, default_value = config::DEFAULT_PATH)]
    pub config: PathBuf,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Runs the server until SIGTERM or SIGINT; SIGHUP reloads the TLS certificate.
    Serve,
    /// Account invites.
    #[command(subcommand)]
    Invite(InviteCommand),
    /// Account administration.
    #[command(subcommand)]
    User(UserCommand),
    /// Prunes old records and collects garbage once.
    Gc {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Checks the database against the stored objects.
    Fsck {
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
        /// Delete objects the database doesn't list (only with the server stopped).
        #[arg(long)]
        remove_orphans: bool,
    },
    /// Backs the server up into a directory: empty, or an earlier backup to bring up to date.
    Backup {
        /// The backup directory.
        dir: PathBuf,
    },
    /// Restores a backup into an empty server (stopped).
    Restore {
        /// The backup directory.
        dir: PathBuf,
    },
    /// The config file.
    #[command(subcommand)]
    Config(ConfigCommand),
}

/// `invite …`
#[derive(Debug, Subcommand)]
pub enum InviteCommand {
    /// Prints a new one-time invite code.
    Create {
        /// How long the code is valid, like `7d` or `12h`.
        #[arg(long, default_value = "7d", value_parser = humantime::parse_duration)]
        expires: Duration,
        /// A note for the account it creates, shown in `user list`.
        #[arg(long, default_value = "")]
        label: String,
    },
}

/// `user …`
#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// Lists the accounts.
    List {
        /// Print the list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Disables an account and signs its devices out.
    Disable {
        /// The account ID, or a unique start of it.
        id: String,
    },
    /// Enables a disabled account.
    Enable {
        /// The account ID, or a unique start of it.
        id: String,
    },
    /// Sets an account's quota.
    Quota {
        /// The account ID, or a unique start of it.
        id: String,
        /// A size like `500 GB`, or `unlimited`.
        size: String,
    },
    /// Deletes a disabled account; its data is freed.
    Delete {
        /// The account ID, or a unique start of it.
        id: String,
        /// Don't ask.
        #[arg(long)]
        yes: bool,
    },
}

/// `config …`
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Loads and checks the config file, opens the database, and prints the settings.
    Check,
}

/// Why a command failed.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// The config file is wrong.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Wrong input, like an unknown account.
    #[error("{0}")]
    Usage(String),
    /// The metadata store failed.
    #[error("database: {0}")]
    Store(#[from] StoreError),
    /// The object store failed.
    #[error("objects: {0}")]
    Blob(#[from] BlobError),
    /// The service refused or failed.
    #[error(transparent)]
    Service(#[from] ServiceError),
    /// `serve` couldn't start.
    #[error(transparent)]
    Serve(#[from] ServeError),
    /// A backup or restore failed.
    #[error(transparent)]
    Backup(#[from] BackupError),
    /// Writing the output failed.
    #[error("output: {0}")]
    Output(#[from] std::io::Error),
}

/// What a command that ran to the end found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// All good.
    Done,
    /// It ran, but found problems (fsck, restore) or was declined.
    Problems,
}

/// The program: runs the command line of this process.
#[must_use]
pub fn main() -> ExitCode {
    run(
        std::env::args_os(),
        &mut std::io::stdin().lock(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}

/// Runs a command line: `args` with the program name first, answers read from `input`,
/// results written to `out` and errors to `err`.
pub fn run(
    args: impl IntoIterator<Item = impl Into<OsString> + Clone>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            let text = error.render().to_string();
            let target: &mut dyn Write = if error.use_stderr() { err } else { out };
            let _ = write!(target, "{text}");
            return ExitCode::from(code);
        }
    };
    let config = match Config::load(&cli.config) {
        Ok(config) => config,
        Err(error) => {
            let _ = writeln!(err, "error: {error}");
            return ExitCode::from(2);
        }
    };
    let mut filter = tracing_subscriber::EnvFilter::new(&config.log_level);
    if !config.log_level.contains("sqlx") {
        // PostgreSQL's notices ("relation already exists") at every start are noise.
        if let Ok(quiet) = "sqlx::postgres::notice=warn".parse() {
            filter = filter.add_directive(quiet);
        }
    }
    // Tests run several commands in one process; the first one sets the subscriber.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(err, "error: starting the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(execute(cli.command, &config, input, out)) {
        Ok(Outcome::Done) => ExitCode::SUCCESS,
        Ok(Outcome::Problems) => ExitCode::FAILURE,
        Err(error) => {
            let _ = writeln!(err, "error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// A service over `meta` and the configured objects, as a live server runs it.
///
/// # Errors
///
/// [`BlobError`] if the objects' directory can't be created.
pub fn live_service<M: MetaStore + 'static>(
    config: &Config,
    meta: M,
) -> Result<ServiceOf<Live<M>>, BlobError> {
    Ok(Service::new(
        meta,
        FsBlobStore::new(&config.objects_dir())?,
        SystemClock,
        UnwrapErr(getrandom::SysRng),
        config.settings,
    ))
}

/// Opens the configured store and runs `$body` with `$service` (a live service over it) and
/// `$sqlite` (the SQLite store, if that is the backend). The body is compiled once per backend.
macro_rules! with_service {
    ($config:expr, |$service:ident, $sqlite:ident| $body:expr) => {
        match &$config.database {
            Database::Sqlite => {
                std::fs::create_dir_all(&$config.data_dir)?;
                let store = SqliteStore::open(&$config.sqlite_path()).await?;
                let $sqlite: Option<&SqliteStore> = Some(&store);
                let $service = live_service($config, store.clone())?;
                $body
            }
            Database::Postgres(url) => {
                let store = PostgresStore::open(url).await?;
                let $sqlite: Option<&SqliteStore> = None;
                let $service = live_service($config, store)?;
                $body
            }
        }
    };
}

async fn execute(
    command: Command,
    config: &Config,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Outcome, CliError> {
    match command {
        Command::Serve => with_service!(config, |service, _sqlite| serve_until_stopped(
            config, service
        )
        .await),
        Command::Invite(InviteCommand::Create { expires, label }) => {
            with_service!(config, |service, _sqlite| invite(
                &service, expires, &label, out
            )
            .await)
        }
        Command::User(command) => {
            with_service!(config, |service, _sqlite| user(
                &service, command, input, out
            )
            .await)
        }
        Command::Gc { json } => {
            with_service!(config, |service, _sqlite| gc(&service, json, out).await)
        }
        Command::Fsck {
            json,
            remove_orphans,
        } => with_service!(config, |service, _sqlite| fsck(
            &service,
            json,
            remove_orphans,
            out
        )
        .await),
        Command::Backup { dir } => {
            with_service!(config, |_service, sqlite| backup_into(
                config, sqlite, &dir, out
            )
            .await)
        }
        Command::Restore { dir } => restore_from(config, &dir, out).await,
        Command::Config(ConfigCommand::Check) => {
            with_service!(config, |_service, _sqlite| check_config(config, out))
        }
    }
}

// ── serve ───────────────────────────────────────────────────────────────────────────

async fn serve_until_stopped<M: MetaStore + 'static>(
    config: &Config,
    service: ServiceOf<Live<M>>,
) -> Result<Outcome, CliError> {
    let running = serve::start::<Live<M>>(config, service).await?;
    wait_for_stop(&running).await;
    running.shutdown(SHUTDOWN_GRACE).await;
    Ok(Outcome::Done)
}

/// Waits for SIGTERM or SIGINT, reloading the certificate on SIGHUP meanwhile.
#[cfg(unix)]
async fn wait_for_stop<D: crate::api::Deps>(running: &serve::Running<D>) {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut terminate), Ok(mut interrupt), Ok(mut hangup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::hangup()),
    ) else {
        tracing::error!("can't listen for signals; stopping");
        return;
    };
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = hangup.recv() => match running.reload_tls() {
                Ok(true) => tracing::info!("certificate reloaded"),
                Ok(false) => tracing::info!("SIGHUP: no TLS configured, nothing to reload"),
                Err(error) => tracing::error!(%error, "certificate doesn't load; keeping the old one"),
            },
        }
    }
    tracing::info!("stopping");
}

/// Waits for Ctrl-C (Windows has no Unix signals).
#[cfg(not(unix))]
async fn wait_for_stop<D: crate::api::Deps>(_running: &serve::Running<D>) {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("stopping");
}

// ── invites and users ───────────────────────────────────────────────────────────────

async fn invite<M: MetaStore + 'static>(
    service: &ServiceOf<Live<M>>,
    expires: Duration,
    label: &str,
    out: &mut dyn Write,
) -> Result<Outcome, CliError> {
    let valid_ms = u64::try_from(expires.as_millis()).unwrap_or(u64::MAX);
    let code = service.create_invite(valid_ms, label).await?;
    let until = SystemTime::now() + expires;
    writeln!(out, "invite code: {code}")?;
    writeln!(
        out,
        "expires:     {} (in {})",
        humantime::format_rfc3339_seconds(until),
        humantime::format_duration(expires)
    )?;
    if !label.is_empty() {
        writeln!(out, "label:       {label}")?;
    }
    Ok(Outcome::Done)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Quotas from here up are unlimited: `unlimited` is `u64::MAX`, which the databases'
/// signed 64-bit integers keep as `i64::MAX`.
const UNLIMITED: u64 = i64::MAX.unsigned_abs();

fn size(bytes: u64) -> String {
    if bytes >= UNLIMITED {
        "unlimited".to_owned()
    } else {
        bytesize::ByteSize(bytes).to_string()
    }
}

fn date(ms: u64) -> String {
    let at = UNIX_EPOCH + Duration::from_millis(ms);
    humantime::format_rfc3339_seconds(at).to_string()
}

const fn status_name(status: AccountStatus) -> &'static str {
    match status {
        AccountStatus::Active => "active",
        AccountStatus::Disabled => "disabled",
        AccountStatus::Deleted => "deleted",
    }
}

/// The one account whose hex ID starts with `prefix`.
fn find_account(accounts: &[AccountSummary], prefix: &str) -> Result<AccountId, CliError> {
    let prefix = prefix.to_ascii_lowercase();
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::Usage(format!(
            "{prefix:?} isn't an account ID (hex digits)"
        )));
    }
    let mut matching = accounts
        .iter()
        .filter(|summary| hex(summary.account.id.as_bytes()).starts_with(&prefix));
    match (matching.next(), matching.next()) {
        (Some(one), None) => Ok(one.account.id),
        (None, _) => Err(CliError::Usage(format!("no account starts with {prefix}"))),
        (Some(_), Some(_)) => Err(CliError::Usage(format!(
            "more than one account starts with {prefix}; give more of the ID"
        ))),
    }
}

async fn user<M: MetaStore + 'static>(
    service: &ServiceOf<Live<M>>,
    command: UserCommand,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Outcome, CliError> {
    let accounts = service.accounts().await?;
    match command {
        UserCommand::List { json } => {
            list_users(&accounts, json, out)?;
        }
        UserCommand::Disable { id } => {
            let id = find_account(&accounts, &id)?;
            service
                .set_account_status(id, AccountStatus::Disabled)
                .await?;
            writeln!(
                out,
                "account {} disabled; its devices are signed out",
                hex(id.as_bytes())
            )?;
        }
        UserCommand::Enable { id } => {
            let id = find_account(&accounts, &id)?;
            service
                .set_account_status(id, AccountStatus::Active)
                .await?;
            writeln!(out, "account {} enabled", hex(id.as_bytes()))?;
        }
        UserCommand::Quota { id, size: text } => {
            let id = find_account(&accounts, &id)?;
            let quota = config::quota(&text).map_err(CliError::Usage)?;
            service.set_quota(id, quota).await?;
            writeln!(out, "account {} quota: {}", hex(id.as_bytes()), size(quota))?;
        }
        UserCommand::Delete { id, yes } => {
            let id = find_account(&accounts, &id)?;
            if !yes {
                let label = accounts
                    .iter()
                    .find(|summary| summary.account.id == id)
                    .map_or("", |summary| summary.account.label.as_str());
                write!(
                    out,
                    "Delete account {} ({label})? Its data will be freed. [y/N] ",
                    hex(id.as_bytes())
                )?;
                out.flush()?;
                let mut answer = String::new();
                input.read_line(&mut answer)?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    writeln!(out, "not deleted")?;
                    return Ok(Outcome::Problems);
                }
            }
            service.delete_account(id).await?;
            writeln!(
                out,
                "account {} deleted; garbage collection frees its data",
                hex(id.as_bytes())
            )?;
        }
    }
    Ok(Outcome::Done)
}

fn list_users(
    accounts: &[AccountSummary],
    json: bool,
    out: &mut dyn Write,
) -> Result<(), CliError> {
    if json {
        let rows: Vec<serde_json::Value> = accounts
            .iter()
            .map(|summary| {
                let account = &summary.account;
                serde_json::json!({
                    "id": hex(account.id.as_bytes()),
                    "label": account.label,
                    "status": status_name(account.status),
                    "devices": summary.devices,
                    "used_bytes": account.used_bytes,
                    "quota_bytes": (account.quota_bytes < UNLIMITED).then_some(account.quota_bytes),
                    "created_ms": account.created_ms,
                })
            })
            .collect();
        writeln!(out, "{}", serde_json::Value::Array(rows))?;
        return Ok(());
    }
    let mut rows = vec![[
        "ID".to_owned(),
        "LABEL".to_owned(),
        "STATUS".to_owned(),
        "DEVICES".to_owned(),
        "USED / QUOTA".to_owned(),
        "CREATED".to_owned(),
    ]];
    for summary in accounts {
        let account = &summary.account;
        rows.push([
            hex(account.id.as_bytes()),
            account.label.clone(),
            status_name(account.status).to_owned(),
            summary.devices.to_string(),
            format!(
                "{} / {}",
                size(account.used_bytes),
                size(account.quota_bytes)
            ),
            date(account.created_ms),
        ]);
    }
    let widths: Vec<usize> = (0..6)
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    for row in &rows {
        let line: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        writeln!(out, "{}", line.join("  ").trim_end())?;
    }
    Ok(())
}

// ── maintenance ─────────────────────────────────────────────────────────────────────

async fn gc<M: MetaStore + 'static>(
    service: &ServiceOf<Live<M>>,
    json: bool,
    out: &mut dyn Write,
) -> Result<Outcome, CliError> {
    let (pruned, report) = serve::maintain::<Live<M>>(service).await?;
    if json {
        writeln!(
            out,
            "{}",
            serde_json::json!({
                "pruned_records": pruned,
                "emptied_collections": report.collections,
                "expired_sign_ins": report.sign_ins,
                "expired_leases": report.leases,
                "marked_chunks": report.marked,
                "deleted_chunks": report.chunks,
                "freed_bytes": report.bytes,
            })
        )?;
    } else {
        writeln!(out, "pruned records:      {pruned}")?;
        writeln!(out, "emptied collections: {}", report.collections)?;
        writeln!(out, "expired sign-ins:    {}", report.sign_ins)?;
        writeln!(out, "expired leases:      {}", report.leases)?;
        writeln!(
            out,
            "marked as garbage:   {} (deleted after {})",
            report.marked,
            humantime::format_duration(Duration::from_millis(service.settings().garbage_grace_ms))
        )?;
        writeln!(
            out,
            "deleted chunks:      {} ({})",
            report.chunks,
            size(report.bytes)
        )?;
    }
    Ok(Outcome::Done)
}

fn key_text(key: &BlobKey) -> String {
    format!(
        "{}/{}/{}",
        hex(key.account.as_bytes()),
        hex(key.collection.as_bytes()),
        hex(&key.chunk.0)
    )
}

async fn fsck<M: MetaStore + 'static>(
    service: &ServiceOf<Live<M>>,
    json: bool,
    remove_orphans: bool,
    out: &mut dyn Write,
) -> Result<Outcome, CliError> {
    if remove_orphans
        && service
            .is_alive(
                HEARTBEAT,
                u64::try_from(HEARTBEAT_STALE.as_millis()).unwrap_or(u64::MAX),
            )
            .await?
    {
        return Err(CliError::Usage(
            "the server is running (its heartbeat is recent): stop it before removing orphans, \
             since an upload writes its object before its row"
                .into(),
        ));
    }
    let mut report = service.fsck().await?;
    let removed = if remove_orphans {
        let removed = service.remove_orphans(&report).await?;
        report.orphan_objects.clear();
        removed
    } else {
        0
    };
    let keys = |keys: &[BlobKey]| keys.iter().map(key_text).collect::<Vec<_>>();
    if json {
        writeln!(
            out,
            "{}",
            serde_json::json!({
                "clean": report.is_clean(),
                "missing_objects": keys(&report.missing_objects),
                "orphan_objects": keys(&report.orphan_objects),
                "wrong_sizes": keys(&report.wrong_sizes),
                "orphans_removed": removed,
            })
        )?;
    } else {
        for (what, list) in [
            ("missing object", &report.missing_objects),
            ("orphan object", &report.orphan_objects),
            ("wrong size", &report.wrong_sizes),
        ] {
            for key in list {
                writeln!(out, "{what}: {}", key_text(key))?;
            }
        }
        if removed > 0 {
            writeln!(out, "orphan objects removed: {removed}")?;
        }
        if report.is_clean() {
            writeln!(out, "clean")?;
        } else if !report.orphan_objects.is_empty()
            && report.missing_objects.is_empty()
            && report.wrong_sizes.is_empty()
        {
            writeln!(
                out,
                "only orphans: left by interrupted uploads; remove them with --remove-orphans \
                 while the server is stopped"
            )?;
        }
    }
    Ok(if report.is_clean() {
        Outcome::Done
    } else {
        Outcome::Problems
    })
}

// ── backup, restore, config ─────────────────────────────────────────────────────────

async fn backup_into(
    config: &Config,
    sqlite: Option<&SqliteStore>,
    dir: &Path,
    out: &mut dyn Write,
) -> Result<Outcome, CliError> {
    let report = backup::backup(config, sqlite, dir).await?;
    let manifest = &report.manifest;
    writeln!(out, "backup complete: {}", dir.display())?;
    writeln!(
        out,
        "objects: {} ({}): {} copied, {} already there, {} removed",
        manifest.objects,
        size(manifest.bytes),
        report.copied,
        report.kept,
        report.removed
    )?;
    writeln!(
        out,
        "took {}",
        humantime::format_duration(Duration::from_secs(
            manifest.finished_ms.saturating_sub(manifest.snapshot_ms) / 1000
        ))
    )?;
    Ok(Outcome::Done)
}

async fn restore_from(
    config: &Config,
    dir: &Path,
    out: &mut dyn Write,
) -> Result<Outcome, CliError> {
    let restored = backup::restore(config, dir).await?;
    writeln!(
        out,
        "restored the backup of {} ({} objects)",
        date(restored.manifest.snapshot_ms),
        restored.objects
    )?;
    let report = with_service!(config, |service, _sqlite| service
        .repair_after_restore()
        .await?);
    writeln!(
        out,
        "forgot {} chunks that were garbage already; removed {} objects uploaded after the \
         snapshot",
        report.forgotten, report.orphans_removed
    )?;
    for key in &report.missing_objects {
        writeln!(out, "missing object: {}", key_text(key))?;
    }
    for key in &report.wrong_sizes {
        writeln!(out, "wrong size: {}", key_text(key))?;
    }
    if report.is_clean() {
        writeln!(out, "fsck: clean")?;
        Ok(Outcome::Done)
    } else {
        writeln!(out, "fsck: the backup is damaged; see above")?;
        Ok(Outcome::Problems)
    }
}

fn check_config(config: &Config, out: &mut dyn Write) -> Result<Outcome, CliError> {
    let listen: Vec<String> = config.listen.iter().map(ToString::to_string).collect();
    let millis = |ms: u64| humantime::format_duration(Duration::from_millis(ms)).to_string();
    writeln!(out, "listen:         {}", listen.join(", "))?;
    writeln!(out, "origin:         {}", config.origin)?;
    writeln!(
        out,
        "tls:            {}",
        config.tls.as_ref().map_or_else(
            || "off (plain HTTP)".to_owned(),
            |files| files.certificate.display().to_string()
        )
    )?;
    writeln!(
        out,
        "database:       {}",
        match config.database {
            Database::Sqlite => format!("sqlite at {}", config.sqlite_path().display()),
            Database::Postgres(_) => "postgres".to_owned(),
        }
    )?;
    writeln!(out, "objects:        {}", config.objects_dir().display())?;
    writeln!(
        out,
        "default quota:  {}",
        size(config.settings.default_quota)
    )?;
    writeln!(
        out,
        "retention:      {} days",
        config.settings.default_retention_days
    )?;
    writeln!(
        out,
        "maintenance:    every {}, garbage grace {}",
        humantime::format_duration(config.maintenance_interval),
        millis(config.settings.garbage_grace_ms)
    )?;
    writeln!(out, "log level:      {}", config.log_level)?;
    writeln!(out, "config and database: ok")?;
    Ok(Outcome::Done)
}
