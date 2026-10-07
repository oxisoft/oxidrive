//! The real server, started in process over HTTP for client tests, with the account of a
//! [`World`]: devices `0..=trusted` and its collection.

#![expect(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "test setup: anything failing here is a broken test environment"
)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use oxisoft_drive_server::Settings;
use oxisoft_drive_server::cli::{Live, live_service};
use oxisoft_drive_server::config::Config;
use oxisoft_drive_server::serve::{self, Running};
use oxisoft_drive_server_sqlite::SqliteStore;
use rustls_pki_types::CertificateDer;

use crate::{ServiceServer, World};

/// A running test server.
pub type TestServer = Running<Live<SqliteStore>>;

/// A server's directory, address and config, set up but not yet running.
#[derive(Debug)]
pub struct Prepared {
    /// Holds the data directory.
    pub dir: tempfile::TempDir,
    /// The server's config.
    pub config: Config,
    /// The origin clients use and sign.
    pub origin: String,
}

/// A free port on localhost (bound, then released).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A self-signed certificate for `localhost` and its key, written to `dir`; the certificate
/// as DER.
#[must_use]
pub fn certificate(dir: &Path) -> (PathBuf, PathBuf, CertificateDer<'static>) {
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, made.cert.pem()).unwrap();
    std::fs::write(&key, made.signing_key.serialize_pem()).unwrap();
    (cert, key, made.cert.der().clone())
}

/// Sets the account up for devices `0..=trusted` (as [`World`] numbers them) and writes a
/// config: plain HTTP on localhost, or with `tls` HTTPS for `localhost` with that certificate
/// and key; `extra` adds config sections. Call outside any runtime: the setup runs its own.
#[must_use]
pub fn prepare(trusted: usize, tls: Option<(&Path, &Path)>, extra: &str) -> Prepared {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    drop(ServiceServer::sqlite_at(&data, Some(trusted), Settings::default()).unwrap());
    let port = free_port();
    let (origin, tls_section) = match tls {
        Some((cert, key)) => (
            format!("https://localhost:{port}"),
            format!(
                "[tls]\ncertificate = '{}'\nkey = '{}'\n",
                cert.display(),
                key.display()
            ),
        ),
        None => (format!("http://127.0.0.1:{port}"), String::new()),
    };
    let text = format!(
        "[server]\nlisten = [\"127.0.0.1:{port}\"]\norigin = \"{origin}\"\n\
         [storage]\ndata_dir = '{}'\ndatabase = \"sqlite\"\n{tls_section}{extra}",
        data.display()
    );
    let config = Config::parse(&text, Path::new("server.toml"), None).unwrap();
    Prepared {
        dir,
        config,
        origin,
    }
}

/// Starts serving a prepared server; needs a tokio runtime.
pub async fn start(prepared: &Prepared) -> TestServer {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let store = SqliteStore::open(&prepared.config.sqlite_path())
        .await
        .unwrap();
    let service = live_service(&prepared.config, store).unwrap();
    serve::start::<Live<SqliteStore>>(&prepared.config, service)
        .await
        .unwrap()
}

/// Stops a server.
pub async fn stop(server: TestServer) {
    server.shutdown(Duration::from_secs(5)).await;
}

/// The signing key of device `number` (the same in every world).
#[must_use]
pub fn device_key(number: usize) -> oxisoft_drive_crypto::sign::SigningKey {
    World::<crate::MemServer>::signing_key(number)
}
