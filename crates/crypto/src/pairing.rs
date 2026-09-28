//! The pairing secret (crypto design §5.2, server API §4.1).
//!
//! A new device shows it inside the QR code (or as a typed code on a headless machine); it
//! never passes through the server. The approving device MACs the account's identity with it,
//! so the new device can tell a genuine approval from one the server forged.

use std::fmt;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::hash::Digest;
use crate::secret::Secret32;

/// Length of a pairing secret in bytes.
pub const PAIRING_SECRET_LEN: usize = 32;

/// 32 random bytes shared out of band between a new and an existing device.
pub struct PairingSecret(Secret32);

impl PairingSecret {
    /// A new random secret.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        Self(Secret32::random(rng))
    }

    /// Restores a secret read from a QR code or typed code.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PAIRING_SECRET_LEN]) -> Self {
        Self(Secret32::from_bytes(bytes))
    }

    /// The bytes to put into the QR code.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; PAIRING_SECRET_LEN]> {
        Zeroizing::new(*self.0.expose())
    }

    /// Keyed BLAKE3 of `data` under this secret.
    #[must_use]
    pub fn mac(&self, data: &[u8]) -> Digest {
        Digest::from_bytes(*blake3::keyed_hash(self.0.expose(), data).as_bytes())
    }

    /// Checks a MAC in constant time.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidSignature`] if `mac` wasn't made with this secret over `data`.
    pub fn verify(&self, data: &[u8], mac: &Digest) -> Result<(), CryptoError> {
        if self.mac(data) == *mac {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }
}

impl fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingSecret(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::rng;

    #[test]
    fn macs_verify_only_with_the_same_secret_and_data() {
        let secret = PairingSecret::generate(&mut rng(80));
        let mac = secret.mac(b"account");
        assert_eq!(secret.verify(b"account", &mac), Ok(()));
        assert_eq!(
            secret.verify(b"accounT", &mac),
            Err(CryptoError::InvalidSignature)
        );
        let other = PairingSecret::generate(&mut rng(81));
        assert!(other.verify(b"account", &mac).is_err());
        let restored = PairingSecret::from_bytes(*secret.to_bytes());
        assert!(restored.verify(b"account", &mac).is_ok());
        assert_eq!(format!("{secret:?}"), "PairingSecret(..)");
    }
}
