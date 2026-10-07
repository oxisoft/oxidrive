//! `serve` in process on real sockets (server binary §3, §7): plain HTTP, TLS and a replaced
//! certificate, the heartbeat, the maintenance loop, a graceful shutdown and a busy address.

#![cfg(test)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oxisoft_drive_crypto::hash::Digest;
use oxisoft_drive_crypto::keys::DeviceIdentity;
use oxisoft_drive_proto::api::{PairingRequest, PairingState, ServerInfo};
use oxisoft_drive_proto::{AccountId, ChunkId, CollectionId};
use oxisoft_drive_server::cli::{Live, live_service};
use oxisoft_drive_server::config::Config;
use oxisoft_drive_server::serve::{self, HEARTBEAT, Running, ServeError};
use oxisoft_drive_server::tls::{self, Resolver};
use oxisoft_drive_server::{BlobKey, BlobStore, FsBlobStore};
use oxisoft_drive_server_sqlite::SqliteStore;
use oxisoft_drive_server_store::{MetaStore, NewAccount, NewChunk, NewCollection};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rustls_pki_types::CertificateDer;

/// A server's directory and config.
struct Setup {
    dir: tempfile::TempDir,
    config: Config,
}

fn setup(extra: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let text = format!(
        "[server]\nlisten = [\"127.0.0.1:0\"]\norigin = \"https://drive.example.com\"\n\
         [storage]\ndata_dir = '{}'\ndatabase = \"sqlite\"\n{extra}",
        dir.path().display()
    );
    let config = Config::parse(&text, Path::new("server.toml"), None).unwrap();
    Setup { dir, config }
}

async fn start(setup: &Setup) -> Running<Live<SqliteStore>> {
    // reqwest's TLS needs a crypto provider, even for plain HTTP.
    install_provider();
    let store = SqliteStore::open(&setup.config.sqlite_path())
        .await
        .unwrap();
    let service = live_service(&setup.config, store).unwrap();
    serve::start::<Live<SqliteStore>>(&setup.config, service)
        .await
        .unwrap()
}

/// Writes a new self-signed certificate for `localhost` and its key; returns its DER.
fn write_certificate(cert: &Path, key: &Path) -> CertificateDer<'static> {
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(cert, made.cert.pem()).unwrap();
    std::fs::write(key, made.signing_key.serialize_pem()).unwrap();
    made.cert.der().clone()
}

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// The certificate a TLS server at `addr` presents, trusting `roots`.
async fn served_certificate(
    addr: SocketAddr,
    roots: &[CertificateDer<'static>],
) -> CertificateDer<'static> {
    install_provider();
    let mut store = rustls::RootCertStore::empty();
    for root in roots {
        store.add(root.clone()).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = connector
        .connect("localhost".try_into().unwrap(), stream)
        .await
        .unwrap();
    let (_, connection) = tls.get_ref();
    assert_eq!(
        connection.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    connection.peer_certificates().unwrap()[0].clone()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

fn cbor<T: minicbor::Encode<()>>(value: &T) -> Vec<u8> {
    minicbor::to_vec(value).unwrap()
}

fn uncbor<T: for<'b> minicbor::Decode<'b, ()>>(bytes: &[u8]) -> T {
    minicbor::decode(bytes).unwrap()
}

async fn wait_until(mut done: impl AsyncFnMut() -> bool) {
    let started = Instant::now();
    while !done().await {
        assert!(started.elapsed() < Duration::from_secs(10), "timed out");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_serves_the_api_and_keeps_a_heartbeat() {
    let setup = setup("");
    let running = start(&setup).await;
    let addr = running.addrs()[0];
    assert_ne!(addr.port(), 0);
    let response = reqwest::get(format!("http://{addr}/v1/info"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let info: ServerInfo = uncbor(&response.bytes().await.unwrap());
    assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    let missing = reqwest::get(format!("http://{addr}/nowhere"))
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);

    let service = running.api().service();
    wait_until(async || service.is_alive(HEARTBEAT, 60_000).await.unwrap()).await;
    assert_eq!(running.reload_tls(), Ok(false));
    let store = SqliteStore::open(&setup.config.sqlite_path())
        .await
        .unwrap();
    running.shutdown(Duration::from_secs(5)).await;
    assert_eq!(store.last_beat(HEARTBEAT).await.unwrap(), None);
    drop(setup.dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_serves_and_swaps_in_a_new_certificate() {
    let certs = tempfile::tempdir().unwrap();
    let (cert, key) = (certs.path().join("cert.pem"), certs.path().join("key.pem"));
    let first = write_certificate(&cert, &key);
    let setup = setup(&format!(
        "[tls]\ncertificate = '{}'\nkey = '{}'\n",
        cert.display(),
        key.display()
    ));
    let running = start(&setup).await;
    let addr = running.addrs()[0];
    let client = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_der(&first).unwrap()])
        .build()
        .unwrap();
    let port = addr.port();
    let response = client
        .get(format!("https://localhost:{port}/v1/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        served_certificate(addr, std::slice::from_ref(&first)).await,
        first
    );

    // A renewal: new files, reloaded as on SIGHUP; new handshakes get the new certificate.
    let second = write_certificate(&cert, &key);
    assert_eq!(running.reload_tls(), Ok(true));
    assert_eq!(
        served_certificate(addr, &[first.clone(), second.clone()]).await,
        second
    );
    // A broken file keeps the old certificate.
    std::fs::write(&key, "not a key").unwrap();
    assert!(running.reload_tls().is_err());
    assert_eq!(
        served_certificate(addr, &[first, second.clone()]).await,
        second
    );
    // Plain HTTP on a TLS port gets nowhere.
    assert!(
        reqwest::get(format!("http://{addr}/v1/info"))
            .await
            .is_err()
    );
    running.shutdown(Duration::from_secs(5)).await;
}

#[test]
fn the_resolver_notices_changed_files() {
    let dir = tempfile::tempdir().unwrap();
    let files = tls::Files {
        certificate: dir.path().join("cert.pem"),
        key: dir.path().join("key.pem"),
    };
    write_certificate(&files.certificate, &files.key);
    let resolver = Resolver::new(files.clone()).unwrap();
    assert_eq!(resolver.reload_if_changed(), Ok(false));
    // File times have coarse resolution on some systems; make the change visible.
    std::thread::sleep(Duration::from_millis(20));
    write_certificate(&files.certificate, &files.key);
    let later = std::time::SystemTime::now() + Duration::from_secs(5);
    for path in [&files.certificate, &files.key] {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(later)
            .unwrap();
    }
    assert_eq!(resolver.reload_if_changed(), Ok(true));
    assert_eq!(resolver.reload_if_changed(), Ok(false));
    std::fs::remove_file(&files.key).unwrap();
    assert_eq!(resolver.reload_if_changed(), Ok(false));
    assert!(resolver.reload().is_err());
    assert!(Resolver::new(files).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintenance_runs_on_its_own() {
    let setup = setup("[maintenance]\ninterval = \"100ms\"\ngarbage_grace = \"0s\"\n");
    let store = SqliteStore::open(&setup.config.sqlite_path())
        .await
        .unwrap();
    let (account, collection) = (
        AccountId::from_bytes([1; 16]),
        CollectionId::from_bytes([2; 16]),
    );
    store
        .create_account(&NewAccount {
            id: account,
            signing_key: vec![0; 32],
            kem_key: Vec::new(),
            quota_bytes: u64::MAX,
            created_ms: 1,
        })
        .await
        .unwrap();
    store
        .create_collection(&NewCollection {
            id: collection,
            account,
            config: Vec::new(),
            retention_days: 30,
            created_ms: 1,
            key: None,
        })
        .await
        .unwrap();
    // A chunk nothing references or leases: garbage.
    let chunk = ChunkId(Digest::from_bytes([3; 32]));
    let objects = FsBlobStore::new(&setup.config.objects_dir()).unwrap();
    let key = BlobKey::new(account, collection, chunk);
    objects.put(&key, b"object").await.unwrap();
    store
        .add_chunk(&NewChunk {
            collection,
            chunk,
            size: 6,
            stored_ms: 1,
        })
        .await
        .unwrap();
    let running = start(&setup).await;
    wait_until(async || store.chunk(collection, chunk).await.unwrap().is_none()).await;
    assert_eq!(
        objects.get(&key).await,
        Err(oxisoft_drive_server::BlobError::NotFound)
    );
    running.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_lets_a_long_poll_finish() {
    let setup = setup("");
    let running = start(&setup).await;
    let addr = running.addrs()[0];
    let identity = DeviceIdentity::generate(&mut ChaCha20Rng::seed_from_u64(1));
    let request = PairingRequest {
        verifying_key: identity.verifying_key(),
        kem_key: identity.kem_public_key(),
    };
    let created = running
        .api()
        .service()
        .create_pairing(&request)
        .await
        .unwrap();
    let id = hex(created.pairing.as_bytes());
    let poll = tokio::spawn(async move {
        reqwest::get(format!("http://{addr}/v1/pairings/{id}?wait=2"))
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    running.shutdown(Duration::from_secs(10)).await;
    assert!(started.elapsed() < Duration::from_secs(5));
    let answered = poll.await.unwrap();
    assert_eq!(answered.status(), 200);
    let state: PairingState = uncbor(&answered.bytes().await.unwrap());
    assert_eq!(state, PairingState::Pending(Box::new(request.clone())));
    // New connections are refused once it stopped.
    assert!(
        reqwest::get(format!("http://{addr}/v1/info"))
            .await
            .is_err()
    );
    let _ = cbor(&request);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grace_time_ends_stuck_requests() {
    let setup = setup("");
    let running = start(&setup).await;
    let addr = running.addrs()[0];
    let identity = DeviceIdentity::generate(&mut ChaCha20Rng::seed_from_u64(2));
    let request = PairingRequest {
        verifying_key: identity.verifying_key(),
        kem_key: identity.kem_public_key(),
    };
    let created = running
        .api()
        .service()
        .create_pairing(&request)
        .await
        .unwrap();
    let id = hex(created.pairing.as_bytes());
    let poll = tokio::spawn(async move {
        reqwest::get(format!("http://{addr}/v1/pairings/{id}?wait=30")).await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    running.shutdown(Duration::from_millis(200)).await;
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(poll.await.unwrap().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_address_stops_the_start() {
    let first = setup("");
    let running = start(&first).await;
    let taken = running.addrs()[0];
    let dir = tempfile::tempdir().unwrap();
    let text = format!(
        "[server]\nlisten = [\"{taken}\"]\norigin = \"https://drive.example.com\"\n\
         [storage]\ndata_dir = '{}'\ndatabase = \"sqlite\"\n",
        dir.path().display()
    );
    let config = Config::parse(&text, Path::new("server.toml"), None).unwrap();
    let store = SqliteStore::open(&config.sqlite_path()).await.unwrap();
    let service = live_service(&config, store).unwrap();
    let refused = serve::start::<Live<SqliteStore>>(&config, service).await;
    match refused {
        Err(error @ ServeError::Bind { .. }) => {
            assert!(error.to_string().contains(&taken.to_string()));
        }
        other => panic!("expected a bind error, got {:?}", other.map(|_| ())),
    }
    running.shutdown(Duration::from_secs(5)).await;
    let _: PathBuf = dir.path().to_path_buf();
}
