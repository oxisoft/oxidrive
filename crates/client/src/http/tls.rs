//! Trusting the server (decisions L5, B4): the operating system's trust store, or a pinned
//! public key for a server with a self-signed certificate.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest as _, Sha256};

use super::ApiError;

/// Which server certificates to accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Certificates the operating system trusts.
    System,
    /// Exactly the certificates whose public key (SPKI) has this SHA-256. The host name must
    /// still match; the certificate authority and dates aren't checked.
    PinnedKey([u8; 32]),
}

impl Trust {
    /// A pin written as 64 hex digits, e.g. the output of
    /// `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | sha256sum`.
    ///
    /// # Errors
    ///
    /// A message if it isn't 64 hex digits.
    pub fn pinned_from_hex(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let bytes = text.as_bytes();
        if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(format!("{text:?} isn't a SHA-256 in hex (64 digits)"));
        }
        let mut pin = [0; 32];
        for (byte, pair) in pin.iter_mut().zip(bytes.as_chunks::<2>().0) {
            let pair = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|error| error.to_string())?;
        }
        Ok(Self::PinnedKey(pin))
    }
}

/// The pin of a certificate: the SHA-256 of its public key (SPKI, DER).
///
/// # Errors
///
/// [`ApiError::Tls`] if it isn't a certificate.
pub fn key_pin(certificate: &CertificateDer<'_>) -> Result<[u8; 32], ApiError> {
    let parsed = webpki::EndEntityCert::try_from(certificate)
        .map_err(|error| ApiError::Tls(error.to_string()))?;
    Ok(Sha256::digest(parsed.subject_public_key_info().as_ref()).into())
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The TLS configuration for `trust`, offering HTTP/2 and HTTP/1.1.
///
/// # Errors
///
/// [`ApiError::Tls`] if the trust store can't be set up.
pub fn client_config(trust: Trust) -> Result<rustls::ClientConfig, ApiError> {
    let tls = |error: rustls::Error| ApiError::Tls(error.to_string());
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(tls)?;
    let mut config = match trust {
        Trust::System => {
            use rustls_platform_verifier::BuilderVerifierExt as _;
            builder.with_platform_verifier().map_err(tls)?
        }
        Trust::PinnedKey(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned {
                pin,
                provider: provider(),
            })),
    }
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Accepts exactly the pinned public key, for the right host name.
#[derive(Debug)]
struct Pinned {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let bad = |reason: rustls::CertificateError| rustls::Error::InvalidCertificate(reason);
        let parsed = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| bad(rustls::CertificateError::BadEncoding))?;
        let found: [u8; 32] = Sha256::digest(parsed.subject_public_key_info().as_ref()).into();
        if found != self.pin {
            return Err(bad(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        parsed
            .verify_is_valid_for_subject_name(server_name)
            .map_err(|_| bad(rustls::CertificateError::NotValidForName))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
