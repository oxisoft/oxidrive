//! The cryptographic suite: which primitives an object was made with.
//!
//! Every stored object carries its suite ID, so a future suite can be introduced without
//! breaking existing data (requirement N4).

use crate::CryptoError;

/// A combination of primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Suite {
    /// XChaCha20-Poly1305, BLAKE3, Ed25519, and HPKE with X-Wing (X25519 + ML-KEM-768),
    /// HKDF-SHA256 and ChaCha20-Poly1305.
    V1,
}

impl Suite {
    /// The suite used for everything new.
    pub const CURRENT: Self = Self::V1;

    /// The byte stored in objects.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::V1 => 1,
        }
    }

    /// Reads a stored suite byte.
    ///
    /// # Errors
    ///
    /// [`CryptoError::UnsupportedSuite`] for an unknown ID.
    pub const fn from_id(id: u8) -> Result<Self, CryptoError> {
        match id {
            1 => Ok(Self::V1),
            other => Err(CryptoError::UnsupportedSuite(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip() {
        assert_eq!(Suite::CURRENT, Suite::V1);
        assert_eq!(Suite::from_id(Suite::V1.id()), Ok(Suite::V1));
    }

    #[test]
    fn unknown_ids_are_rejected() {
        for id in [0, 2, 255] {
            assert_eq!(Suite::from_id(id), Err(CryptoError::UnsupportedSuite(id)));
        }
    }
}
