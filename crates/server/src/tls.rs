//! TLS when the server terminates it itself (G4, server binary §3): TLS 1.3 only, on ring,
//! with a certificate that can be replaced while the server runs (a Let's Encrypt renewal).

use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::SystemTime;

use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// The certificate chain and key files, both PEM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Files {
    /// The certificate chain, server certificate first.
    pub certificate: PathBuf,
    /// The private key.
    pub key: PathBuf,
}

/// Why a certificate couldn't be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TlsError {
    /// A file couldn't be read or parsed.
    #[error("{}: {reason}", path.display())]
    File {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The key doesn't fit the certificate, or isn't usable.
    #[error("{0}")]
    Key(String),
}

/// The crypto provider: ring, as sqlx uses.
fn provider() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// Reads the certificate chain and key and checks they belong together.
///
/// # Errors
///
/// [`TlsError`] for an unreadable or empty file, or a key that doesn't fit.
pub fn load(files: &Files) -> Result<CertifiedKey, TlsError> {
    let file_error = |path: &PathBuf, reason: String| TlsError::File {
        path: path.clone(),
        reason,
    };
    let chain = CertificateDer::pem_file_iter(&files.certificate)
        .map_err(|error| file_error(&files.certificate, error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| file_error(&files.certificate, error.to_string()))?;
    if chain.is_empty() {
        return Err(file_error(
            &files.certificate,
            "no certificate in it".into(),
        ));
    }
    let key = PrivateKeyDer::from_pem_file(&files.key)
        .map_err(|error| file_error(&files.key, error.to_string()))?;
    CertifiedKey::from_der(chain, key, &provider())
        .map_err(|error| TlsError::Key(error.to_string()))
}

/// When the certificate and key files last changed.
type Stamp = (SystemTime, SystemTime);

/// When the files last changed, to notice a renewal.
fn modified(files: &Files) -> Option<Stamp> {
    let time = |path: &PathBuf| {
        std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
    };
    Some((time(&files.certificate)?, time(&files.key)?))
}

/// Serves the current certificate; [`Self::reload`] swaps in a new one for new handshakes.
#[derive(Debug)]
pub struct Resolver {
    files: Files,
    current: RwLock<(Arc<CertifiedKey>, Option<Stamp>)>,
}

impl Resolver {
    /// Loads the certificate.
    ///
    /// # Errors
    ///
    /// As [`load`].
    pub fn new(files: Files) -> Result<Self, TlsError> {
        let key = load(&files)?;
        let stamp = modified(&files);
        Ok(Self {
            files,
            current: RwLock::new((Arc::new(key), stamp)),
        })
    }

    /// Loads the files again. On failure the old certificate stays.
    ///
    /// # Errors
    ///
    /// As [`load`].
    pub fn reload(&self) -> Result<(), TlsError> {
        let stamp = modified(&self.files);
        let key = load(&self.files)?;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = (Arc::new(key), stamp);
        Ok(())
    }

    /// Reloads if either file changed since the last load; `Ok(true)` if it did.
    ///
    /// # Errors
    ///
    /// As [`load`].
    pub fn reload_if_changed(&self) -> Result<bool, TlsError> {
        let stamp = modified(&self.files);
        let loaded = self
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .1;
        if stamp.is_none() || stamp == loaded {
            return Ok(false);
        }
        self.reload().map(|()| true)
    }

    /// A rustls server configuration serving through this resolver: TLS 1.3, HTTP/2 and
    /// HTTP/1.1.
    ///
    /// # Errors
    ///
    /// [`TlsError::Key`] if rustls refuses the setup.
    pub fn server_config(self: &Arc<Self>) -> Result<rustls::ServerConfig, TlsError> {
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| TlsError::Key(error.to_string()))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(self) as Arc<dyn ResolvesServerCert>);
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(
            &self
                .current
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .0,
        ))
    }
}
