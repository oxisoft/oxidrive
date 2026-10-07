//! The config file (server binary §2): every key, the defaults, and every refusal with its
//! line.

#![cfg(test)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use oxisoft_drive_server::config::{Config, ConfigError, Database};
use oxisoft_drive_server::{RateLimits, Settings};

const MINIMAL: &str = r#"
[server]
listen = ["127.0.0.1:8080"]
origin = "https://drive.example.com"

[storage]
data_dir = "/var/lib/oxidrive"
database = "sqlite"
"#;

fn parse(text: &str) -> Result<Config, ConfigError> {
    Config::parse(text, Path::new("server.toml"), None)
}

/// The refusal's line and message.
fn refusal(text: &str) -> (usize, String) {
    match parse(text) {
        Err(ConfigError::Invalid {
            path,
            line,
            message,
        }) => {
            assert_eq!(path, PathBuf::from("server.toml"));
            (line, message)
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A self-signed certificate and its key, written to `dir`.
fn certificate(dir: &Path) -> (PathBuf, PathBuf) {
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, made.cert.pem()).unwrap();
    std::fs::write(&key, made.signing_key.serialize_pem()).unwrap();
    (cert, key)
}

#[test]
fn a_minimal_file_takes_the_defaults() {
    let config = parse(MINIMAL).unwrap();
    assert_eq!(config.listen, ["127.0.0.1:8080".parse().unwrap()]);
    assert_eq!(config.origin, "https://drive.example.com");
    assert!(config.trusted_proxies.is_empty());
    assert_eq!(config.tls, None);
    assert_eq!(config.database, Database::Sqlite);
    assert_eq!(
        config.objects_dir(),
        PathBuf::from("/var/lib/oxidrive/objects")
    );
    assert_eq!(
        config.sqlite_path(),
        PathBuf::from("/var/lib/oxidrive/meta.sqlite")
    );
    assert_eq!(config.settings, Settings::default());
    assert_eq!(config.rates, RateLimits::default());
    assert_eq!(config.maintenance_interval, Duration::from_hours(1));
    assert_eq!(config.log_level, "info");
    assert_eq!(config.pg_dump, ["pg_dump"]);
    assert_eq!(config.pg_restore, ["pg_restore"]);
}

#[test]
fn every_key_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(dir.path());
    let text = format!(
        r#"
[server]
listen = ["0.0.0.0:443", "[::]:443"]
origin = "https://drive.example.com:8443"
trusted_proxies = ["10.0.0.1"]
allow_plain_http = false

[tls]
certificate = '{}'
key = '{}'

[storage]
data_dir = "/srv/drive"
database = "postgres://drive@db/drive"

[accounts]
default_quota = "500 GB"
default_retention_days = 7

[maintenance]
interval = "15m"
garbage_grace = "2d"

[log]
level = "oxisoft_drive_server=debug,warn"

[backup]
pg_dump = ["/usr/pgsql-18/bin/pg_dump"]
pg_restore = ["/usr/pgsql-18/bin/pg_restore", "--verbose"]

[limits]
lease = "12h"
session = "30m"
challenge = "30s"
pairing = "5m"

[rates]
info_per_minute = 1
auth_per_minute = 2
pairings_per_minute = 3
accounts_per_minute = 4
recovery_per_hour = 5
device_per_minute = 6
"#,
        cert.display(),
        key.display()
    );
    let config = parse(&text).unwrap();
    assert_eq!(config.listen.len(), 2);
    assert_eq!(
        config.trusted_proxies,
        ["10.0.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(config.tls.as_ref().unwrap().certificate, cert);
    assert_eq!(config.tls.as_ref().unwrap().key, key);
    assert_eq!(
        config.database,
        Database::Postgres("postgres://drive@db/drive".to_owned())
    );
    assert_eq!(format!("{:?}", config.database), "Postgres(..)");
    let settings = config.settings;
    assert_eq!(settings.default_quota, 500_000_000_000);
    assert_eq!(settings.default_retention_days, 7);
    assert_eq!(settings.garbage_grace_ms, 2 * 86_400_000);
    assert_eq!(settings.lease_ms, 12 * 3_600_000);
    assert_eq!(settings.session_ms, 30 * 60_000);
    assert_eq!(settings.challenge_ms, 30_000);
    assert_eq!(settings.pairing_ms, 5 * 60_000);
    assert_eq!(
        config.rates,
        RateLimits {
            info_per_minute: 1,
            auth_per_minute: 2,
            pairings_per_minute: 3,
            accounts_per_minute: 4,
            recovery_per_hour: 5,
            device_per_minute: 6,
        }
    );
    assert_eq!(config.maintenance_interval, Duration::from_mins(15));
    assert_eq!(config.log_level, "oxisoft_drive_server=debug,warn");
    assert_eq!(
        config.pg_restore,
        ["/usr/pgsql-18/bin/pg_restore", "--verbose"]
    );
}

#[test]
fn the_environment_names_the_database() {
    let config = Config::parse(
        MINIMAL,
        Path::new("server.toml"),
        Some("postgresql://drive:secret@db/drive".to_owned()),
    )
    .unwrap();
    assert_eq!(
        config.database,
        Database::Postgres("postgresql://drive:secret@db/drive".to_owned())
    );
    let refused = Config::parse(
        MINIMAL,
        Path::new("server.toml"),
        Some("mysql://x".to_owned()),
    );
    match refused {
        Err(ConfigError::Invalid { line, message, .. }) => {
            assert_eq!(line, 8);
            assert!(message.starts_with("OXIDRIVE_DATABASE_URL"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn plain_http_off_loopback_needs_the_flag() {
    let open = MINIMAL.replace("127.0.0.1:8080", "0.0.0.0:8080");
    let (line, message) = refusal(&open);
    assert_eq!(line, 3);
    assert!(message.contains("allow_plain_http"), "{message}");
    let allowed = open.replace("origin = ", "allow_plain_http = true\norigin = ");
    assert!(parse(&allowed).is_ok());
}

#[test]
fn mistakes_are_refused_at_their_line() {
    let cases: &[(&str, &str, usize, &str)] = &[
        (
            "origin = \"https://drive.example.com\"",
            "origin = \"drive.example.com\"",
            4,
            "https://",
        ),
        (
            "origin = \"https://drive.example.com\"",
            "origin = \"https://drive.example.com/\"",
            4,
            "only a scheme",
        ),
        (
            "origin = \"https://drive.example.com\"",
            "origin = \"https://\"",
            4,
            "only a scheme",
        ),
        (
            "listen = [\"127.0.0.1:8080\"]",
            "listen = []",
            3,
            "at least one",
        ),
        (
            "listen = [\"127.0.0.1:8080\"]",
            "listen = [\"localhost\"]",
            3,
            "socket address",
        ),
        (
            "database = \"sqlite\"",
            "database = \"mysql\"",
            8,
            "postgres://",
        ),
        (
            "database = \"sqlite\"",
            "database = \"sqlite\"\nextra = 1",
            9,
            "unknown field",
        ),
    ];
    for (from, to, line, needle) in cases {
        let (found, message) = refusal(&MINIMAL.replace(from, to));
        assert_eq!(found, *line, "{to}: {message}");
        assert!(message.contains(needle), "{to}: {message}");
    }
    let added: &[(&str, usize, &str)] = &[
        ("[accounts]\ndefault_quota = \"lots\"", 11, "500 GB"),
        ("[maintenance]\ninterval = \"0s\"", 11, "more than 0"),
        ("[maintenance]\ngarbage_grace = \"soon\"", 11, "soon"),
        ("[limits]\nlease = \"forever\"", 11, "forever"),
        ("[rates]\ninfo_per_minute = 0", 11, "more than 0"),
        ("[log]\nlevel = \"=[\"", 11, "level"),
        ("[backup]\npg_dump = []", 11, "needs a program"),
        ("[nonsense]", 10, "unknown field"),
    ];
    for (section, line, needle) in added {
        let (found, message) = refusal(&format!("{MINIMAL}\n{section}\n"));
        assert_eq!(found, *line, "{section}: {message}");
        assert!(message.contains(needle), "{section}: {message}");
    }
    let (line, message) = refusal("[server]\nlisten = [\"127.0.0.1:1\"]\norigin = \"https://x\"\n");
    assert_eq!(line, 1);
    assert!(message.contains("storage"), "{message}");
}

#[test]
fn tls_files_must_load() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(dir.path());
    let with = |cert: &Path, key: &Path| {
        format!(
            "{MINIMAL}\n[tls]\ncertificate = '{}'\nkey = '{}'\n",
            cert.display(),
            key.display()
        )
    };
    assert!(parse(&with(&cert, &key)).is_ok());
    // TLS allows any address.
    assert!(parse(&with(&cert, &key).replace("127.0.0.1:8080", "0.0.0.0:443")).is_ok());

    let (line, message) = refusal(&with(&dir.path().join("missing.pem"), &key));
    assert_eq!(line, 11);
    assert!(message.contains("missing.pem"), "{message}");
    // A key file used as the certificate holds no certificate.
    let (_, message) = refusal(&with(&key, &key));
    assert!(message.contains("no certificate"), "{message}");
    // Another certificate's key doesn't fit.
    let other = tempfile::tempdir().unwrap();
    let (_, other_key) = certificate(other.path());
    let (_, message) = refusal(&with(&cert, &other_key));
    assert!(!message.is_empty());
    let (_, message) = refusal(&with(&cert, &cert));
    assert!(message.contains("cert.pem"), "{message}");
}

#[test]
fn an_unreadable_file_names_itself() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.toml");
    let error = Config::load(&path).unwrap_err();
    assert!(matches!(error, ConfigError::Read { .. }));
    assert!(error.to_string().contains("absent.toml"));
    std::fs::write(&path, MINIMAL).unwrap();
    assert!(Config::load(&path).is_ok());
    let error = parse("[server").unwrap_err();
    assert!(error.to_string().starts_with("server.toml:1: "), "{error}");
}
