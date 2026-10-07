//! The config file (server binary §2): one TOML file, validated completely when it is loaded,
//! so a mistake stops the server at start with the file, the line and the reason.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;
use toml::Spanned;

use crate::api::RateLimits;
use crate::service::Settings;
use crate::tls;

/// Where the config file is looked for without `--config`.
pub const DEFAULT_PATH: &str = "/etc/oxidrive/server.toml";
/// The environment variable that overrides `storage.database` (J6).
pub const DATABASE_URL_VAR: &str = "OXIDRIVE_DATABASE_URL";

/// A loaded, valid configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Addresses to listen on.
    pub listen: Vec<SocketAddr>,
    /// The public URL devices sign into their sign-in answers.
    pub origin: String,
    /// Reverse proxies whose `X-Forwarded-For` is believed.
    pub trusted_proxies: Vec<IpAddr>,
    /// The certificate and key, if the server terminates TLS itself.
    pub tls: Option<tls::Files>,
    /// Where the objects and the SQLite database live.
    pub data_dir: PathBuf,
    /// The metadata database.
    pub database: Database,
    /// Limits and defaults for the service.
    pub settings: Settings,
    /// Rate limits for the API.
    pub rates: RateLimits,
    /// How often maintenance (prune, garbage collection) runs.
    pub maintenance_interval: Duration,
    /// The `tracing` filter.
    pub log_level: String,
    /// The `pg_dump` command (program and leading arguments).
    pub pg_dump: Vec<String>,
    /// The `pg_restore` command (program and leading arguments).
    pub pg_restore: Vec<String>,
}

/// Which metadata database.
#[derive(Clone, PartialEq, Eq)]
pub enum Database {
    /// SQLite at `data_dir/meta.sqlite`.
    Sqlite,
    /// PostgreSQL at this URL.
    Postgres(String),
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite => f.write_str("Sqlite"),
            // The URL may hold a password.
            Self::Postgres(_) => f.write_str("Postgres(..)"),
        }
    }
}

/// Why a config file was refused.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file couldn't be read.
    #[error("{}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: std::io::Error,
    },
    /// The file is wrong at a line.
    #[error("{}:{line}: {message}", path.display())]
    Invalid {
        /// The file.
        path: PathBuf,
        /// The line, from 1.
        line: usize,
        /// What is wrong.
        message: String,
    },
}

impl Config {
    /// The objects' directory.
    #[must_use]
    pub fn objects_dir(&self) -> PathBuf {
        self.data_dir.join("objects")
    }

    /// The SQLite database file.
    #[must_use]
    pub fn sqlite_path(&self) -> PathBuf {
        self.data_dir.join("meta.sqlite")
    }

    /// Reads and validates the file at `path`. `OXIDRIVE_DATABASE_URL`, if set, replaces
    /// `storage.database`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] with the line and reason of the first problem.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let env_database = std::env::var(DATABASE_URL_VAR)
            .ok()
            .filter(|url| !url.is_empty());
        Self::parse(&text, path, env_database)
    }

    /// Validates config `text` read from `path` (for messages; relative TLS paths are
    /// relative to the process). `env_database` replaces `storage.database`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] with the line and reason of the first problem.
    pub fn parse(
        text: &str,
        path: &Path,
        env_database: Option<String>,
    ) -> Result<Self, ConfigError> {
        let at = Locator { text, path };
        let file: File = toml::from_str(text).map_err(|error| ConfigError::Invalid {
            path: path.to_path_buf(),
            line: error.span().map_or(1, |span| line_of(text, span.start)),
            message: error.message().to_owned(),
        })?;
        let server = file.server;
        let listen = server.listen;
        if listen.get_ref().is_empty() {
            return Err(at.error(&listen, "listen: name at least one address".into()));
        }
        let origin = server.origin;
        check_origin(origin.get_ref()).map_err(|message| at.error(&origin, message))?;
        let tls = match file.tls {
            Some(section) => {
                let files = tls::Files {
                    certificate: section.certificate.get_ref().clone(),
                    key: section.key.get_ref().clone(),
                };
                tls::load(&files)
                    .map_err(|error| at.error(&section.certificate, error.to_string()))?;
                Some(files)
            }
            None => None,
        };
        if tls.is_none()
            && !server.allow_plain_http
            && let Some(open) = listen
                .get_ref()
                .iter()
                .find(|addr| !addr.ip().is_loopback())
        {
            return Err(at.error(
                &listen,
                format!(
                    "plain HTTP on {open}, which isn't a loopback address: add a [tls] section, \
                     or set allow_plain_http = true (server binary J5)"
                ),
            ));
        }
        let storage = file.storage;
        let database = match env_database {
            Some(url) => database(&url).map_err(|message| {
                at.error(&storage.database, format!("{DATABASE_URL_VAR}: {message}"))
            })?,
            None => database(storage.database.get_ref())
                .map_err(|message| at.error(&storage.database, message))?,
        };
        let (settings, maintenance_interval) =
            settings(&at, &file.accounts, &file.maintenance, &file.limits)?;
        let rates = rates(&at, file.rates)?;
        let level = file.log.level;
        tracing_subscriber::EnvFilter::try_new(level.get_ref())
            .map_err(|error| at.error(&level, format!("level: {error}")))?;
        let backup = file.backup;
        for command in [&backup.pg_dump, &backup.pg_restore] {
            if command.get_ref().is_empty() {
                return Err(at.error(command, "the command needs a program".into()));
            }
        }
        Ok(Self {
            listen: listen.into_inner(),
            origin: origin.into_inner(),
            trusted_proxies: server.trusted_proxies,
            tls,
            data_dir: storage.data_dir,
            database,
            settings,
            rates,
            maintenance_interval,
            log_level: level.into_inner(),
            pg_dump: backup.pg_dump.into_inner(),
            pg_restore: backup.pg_restore.into_inner(),
        })
    }
}

/// Turns a value's place in the file into an error at its line.
struct Locator<'a> {
    text: &'a str,
    path: &'a Path,
}

impl Locator<'_> {
    fn error<T>(&self, value: &Spanned<T>, message: String) -> ConfigError {
        ConfigError::Invalid {
            path: self.path.to_path_buf(),
            line: line_of(self.text, value.span().start),
            message,
        }
    }
}

/// The service settings and the maintenance interval.
fn settings(
    at: &Locator<'_>,
    accounts: &AccountsSection,
    maintenance: &MaintenanceSection,
    limits: &LimitsSection,
) -> Result<(Settings, Duration), ConfigError> {
    let duration = |text: &Spanned<String>| {
        humantime::parse_duration(text.get_ref())
            .map_err(|error| at.error(text, format!("{:?}: {error}", text.get_ref())))
    };
    let mut settings = Settings {
        default_quota: quota(accounts.default_quota.get_ref())
            .map_err(|message| at.error(&accounts.default_quota, message))?,
        default_retention_days: accounts.default_retention_days,
        ..Settings::default()
    };
    let interval = duration(&maintenance.interval)?;
    if interval.is_zero() {
        return Err(at.error(
            &maintenance.interval,
            "interval: must be more than 0".into(),
        ));
    }
    settings.garbage_grace_ms = millis(duration(&maintenance.garbage_grace)?);
    for (field, target) in [
        (&limits.lease, &mut settings.lease_ms),
        (&limits.session, &mut settings.session_ms),
        (&limits.challenge, &mut settings.challenge_ms),
        (&limits.pairing, &mut settings.pairing_ms),
    ] {
        if let Some(value) = field {
            *target = millis(duration(value)?);
        }
    }
    Ok((settings, interval))
}

/// The rate limits, defaults replaced by what the file gives.
fn rates(at: &Locator<'_>, given: RatesSection) -> Result<RateLimits, ConfigError> {
    let mut rates = RateLimits::default();
    for (value, target) in [
        (given.info_per_minute, &mut rates.info_per_minute),
        (given.auth_per_minute, &mut rates.auth_per_minute),
        (given.pairings_per_minute, &mut rates.pairings_per_minute),
        (given.accounts_per_minute, &mut rates.accounts_per_minute),
        (given.recovery_per_hour, &mut rates.recovery_per_hour),
        (given.device_per_minute, &mut rates.device_per_minute),
    ] {
        if let Some(value) = value {
            if *value.get_ref() == 0 {
                return Err(at.error(&value, "rates: must be more than 0".into()));
            }
            *target = *value.get_ref();
        }
    }
    Ok(rates)
}

/// The line (from 1) of byte `offset` in `text`.
fn line_of(text: &str, offset: usize) -> usize {
    text.as_bytes()
        .iter()
        .take(offset)
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The origin devices sign: a scheme and host (and port), nothing after.
fn check_origin(origin: &str) -> Result<(), String> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| format!("origin {origin:?}: must start with https:// or http://"))?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
        return Err(format!(
            "origin {origin:?}: only a scheme, host and port, like https://drive.example.com"
        ));
    }
    Ok(())
}

fn database(text: &str) -> Result<Database, String> {
    if text == "sqlite" {
        Ok(Database::Sqlite)
    } else if text.starts_with("postgres://") || text.starts_with("postgresql://") {
        Ok(Database::Postgres(text.to_owned()))
    } else {
        Err("database: \"sqlite\" or a postgres:// URL".into())
    }
}

/// `unlimited` or a size like `500 GB`.
pub(crate) fn quota(text: &str) -> Result<u64, String> {
    if text == "unlimited" {
        return Ok(u64::MAX);
    }
    bytesize::ByteSize::from_str(text)
        .map(|size| size.as_u64())
        .map_err(|error| format!("{text:?}: {error} (a size like \"500 GB\", or \"unlimited\")"))
}

// ── the file as written ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    server: ServerSection,
    tls: Option<TlsSection>,
    storage: StorageSection,
    #[serde(default)]
    accounts: AccountsSection,
    #[serde(default)]
    maintenance: MaintenanceSection,
    #[serde(default)]
    log: LogSection,
    #[serde(default)]
    backup: BackupSection,
    #[serde(default)]
    limits: LimitsSection,
    #[serde(default)]
    rates: RatesSection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerSection {
    listen: Spanned<Vec<SocketAddr>>,
    origin: Spanned<String>,
    #[serde(default)]
    trusted_proxies: Vec<IpAddr>,
    #[serde(default)]
    allow_plain_http: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsSection {
    certificate: Spanned<PathBuf>,
    key: Spanned<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageSection {
    data_dir: PathBuf,
    database: Spanned<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountsSection {
    #[serde(default = "unlimited")]
    default_quota: Spanned<String>,
    #[serde(default = "thirty")]
    default_retention_days: u32,
}

impl Default for AccountsSection {
    fn default() -> Self {
        Self {
            default_quota: unlimited(),
            default_retention_days: thirty(),
        }
    }
}

fn unlimited() -> Spanned<String> {
    Spanned::new(0..0, "unlimited".into())
}

const fn thirty() -> u32 {
    30
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintenanceSection {
    #[serde(default = "one_hour")]
    interval: Spanned<String>,
    #[serde(default = "one_day")]
    garbage_grace: Spanned<String>,
}

impl Default for MaintenanceSection {
    fn default() -> Self {
        Self {
            interval: one_hour(),
            garbage_grace: one_day(),
        }
    }
}

fn one_hour() -> Spanned<String> {
    Spanned::new(0..0, "1h".into())
}

fn one_day() -> Spanned<String> {
    Spanned::new(0..0, "1d".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogSection {
    #[serde(default = "info")]
    level: Spanned<String>,
}

impl Default for LogSection {
    fn default() -> Self {
        Self { level: info() }
    }
}

fn info() -> Spanned<String> {
    Spanned::new(0..0, "info".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupSection {
    #[serde(default = "pg_dump")]
    pg_dump: Spanned<Vec<String>>,
    #[serde(default = "pg_restore")]
    pg_restore: Spanned<Vec<String>>,
}

impl Default for BackupSection {
    fn default() -> Self {
        Self {
            pg_dump: pg_dump(),
            pg_restore: pg_restore(),
        }
    }
}

fn pg_dump() -> Spanned<Vec<String>> {
    Spanned::new(0..0, vec!["pg_dump".into()])
}

fn pg_restore() -> Spanned<Vec<String>> {
    Spanned::new(0..0, vec!["pg_restore".into()])
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct LimitsSection {
    lease: Option<Spanned<String>>,
    session: Option<Spanned<String>>,
    challenge: Option<Spanned<String>>,
    pairing: Option<Spanned<String>>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RatesSection {
    info_per_minute: Option<Spanned<u32>>,
    auth_per_minute: Option<Spanned<u32>>,
    pairings_per_minute: Option<Spanned<u32>>,
    accounts_per_minute: Option<Spanned<u32>>,
    recovery_per_hour: Option<Spanned<u32>>,
    device_per_minute: Option<Spanned<u32>>,
}
