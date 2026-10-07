//! The built `oxidrive-server` binary (server binary §7): a config error, and `serve` with
//! real signals — SIGHUP swaps the certificate, SIGTERM lets a long poll finish and exits 0.

#![cfg(test)]
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use oxisoft_drive_crypto::keys::DeviceIdentity;
use oxisoft_drive_proto::api::{PairingCreated, PairingRequest, PairingState};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rustls_pki_types::CertificateDer;

const BINARY: &str = env!("CARGO_BIN_EXE_oxidrive-server");

fn write_config(dir: &Path, extra: &str) -> std::path::PathBuf {
    let path = dir.join("server.toml");
    std::fs::write(
        &path,
        format!(
            "[server]\nlisten = [\"127.0.0.1:0\"]\norigin = \"https://drive.example.com\"\n\
             [storage]\ndata_dir = '{}'\ndatabase = \"sqlite\"\n{extra}",
            dir.join("data").display()
        ),
    )
    .unwrap();
    path
}

fn signal(child: &Child, name: &str) {
    let status = Command::new("kill")
        .args([format!("-{name}"), child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

/// Starts `serve`; returns the process, its address, and its log lines as they come.
fn serve(config: &Path) -> (Child, SocketAddr, mpsc::Receiver<String>) {
    let mut child = Command::new(BINARY)
        .args(["--config", config.to_str().unwrap(), "serve"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (lines, receive) = mpsc::channel();
    let stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = lines.send(line);
        }
    });
    let addr = loop {
        let line = receive.recv_timeout(Duration::from_secs(20)).unwrap();
        if let Some(rest) = line.split("address=").nth(1) {
            break rest.split_whitespace().next().unwrap().parse().unwrap();
        }
    };
    (child, addr, receive)
}

/// Waits for a log line containing `needle`.
fn expect_log(lines: &mpsc::Receiver<String>, needle: &str) {
    let started = Instant::now();
    loop {
        let line = lines
            .recv_timeout(Duration::from_secs(10).saturating_sub(started.elapsed()))
            .unwrap_or_else(|_| panic!("no log line with {needle:?}"));
        if line.contains(needle) {
            return;
        }
    }
}

fn wait(mut child: Child) -> std::process::ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "it didn't stop"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_config_error_exits_with_2_and_the_line() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "[maintenance]\ninterval = \"never\"\n");
    let output = Command::new(BINARY)
        .args(["--config", config.to_str().unwrap(), "serve"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("server.toml:8:"), "{stderr}");
    let version = Command::new(BINARY).arg("--version").output().unwrap();
    assert_eq!(version.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn sigterm_lets_a_long_poll_finish_and_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "");
    let (child, addr, lines) = serve(&config);
    let identity = DeviceIdentity::generate(&mut ChaCha20Rng::seed_from_u64(1));
    let request = PairingRequest {
        verifying_key: identity.verifying_key(),
        kem_key: identity.kem_public_key(),
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    // reqwest's TLS needs a crypto provider, even for plain HTTP.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::new();
    let created: PairingCreated = runtime.block_on(async {
        let response = http
            .post(format!("http://{addr}/v1/pairings"))
            .header("content-type", "application/cbor")
            .body(minicbor::to_vec(&request).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        minicbor::decode(&response.bytes().await.unwrap()).unwrap()
    });
    let id: String = created
        .pairing
        .as_bytes()
        .iter()
        .fold(String::new(), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        });
    let poll = runtime.spawn({
        let http = http.clone();
        async move {
            http.get(format!("http://{addr}/v1/pairings/{id}?wait=2"))
                .send()
                .await
                .unwrap()
        }
    });
    std::thread::sleep(Duration::from_millis(300));
    // One line per request, with the route pattern rather than the path.
    expect_log(&lines, "route=\"/v1/pairings\" status=200");
    signal(&child, "HUP");
    expect_log(&lines, "nothing to reload");
    signal(&child, "TERM");
    let status = wait(child);
    assert_eq!(status.code(), Some(0));
    let answered = runtime.block_on(poll).unwrap();
    assert_eq!(answered.status(), 200);
    let bytes = runtime.block_on(answered.bytes()).unwrap();
    let state: PairingState = minicbor::decode(&bytes).unwrap();
    assert_eq!(state, PairingState::Pending(Box::new(request)));
    expect_log(&lines, "stopped");
}

fn write_certificate(cert: &Path, key: &Path) -> CertificateDer<'static> {
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(cert, made.cert.pem()).unwrap();
    std::fs::write(key, made.signing_key.serialize_pem()).unwrap();
    made.cert.der().clone()
}

async fn served_certificate(
    addr: SocketAddr,
    roots: &[CertificateDer<'static>],
) -> CertificateDer<'static> {
    let mut store = rustls::RootCertStore::empty();
    for root in roots {
        store.add(root.clone()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(store)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = connector
        .connect("localhost".try_into().unwrap(), stream)
        .await
        .unwrap();
    tls.get_ref().1.peer_certificates().unwrap()[0].clone()
}

#[test]
fn sighup_swaps_in_a_renewed_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    let first = write_certificate(&cert, &key);
    let config = write_config(
        dir.path(),
        &format!(
            "[tls]\ncertificate = '{}'\nkey = '{}'\n",
            cert.display(),
            key.display()
        ),
    );
    let (child, addr, lines) = serve(&config);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    assert_eq!(
        runtime.block_on(served_certificate(addr, std::slice::from_ref(&first))),
        first
    );
    let second = write_certificate(&cert, &key);
    signal(&child, "HUP");
    expect_log(&lines, "certificate reloaded");
    assert_eq!(
        runtime.block_on(served_certificate(addr, &[first.clone(), second.clone()])),
        second
    );
    // A broken renewal keeps the certificate in use.
    std::fs::write(&key, "broken").unwrap();
    signal(&child, "HUP");
    expect_log(&lines, "keeping the old one");
    assert_eq!(
        runtime.block_on(served_certificate(addr, &[first, second.clone()])),
        second
    );
    signal(&child, "INT");
    assert_eq!(wait(child).code(), Some(0));
}
