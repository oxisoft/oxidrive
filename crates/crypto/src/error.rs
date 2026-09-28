use std::fmt;

/// Everything that can go wrong in this crate.
///
/// Failures to decrypt or unwrap are deliberately a single variant without detail, so error
/// messages can't be used to learn why an authentication check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Decryption or unwrapping failed: wrong key, wrong context, or tampered data.
    #[error("decryption failed")]
    Decrypt,
    /// A signature did not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// Bytes that should hold a key are not a valid key.
    #[error("invalid key")]
    InvalidKey,
    /// Input has the wrong length.
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// The required length.
        expected: usize,
        /// The length received.
        actual: usize,
    },
    /// Input is larger than the primitive can process.
    #[error("input too large")]
    TooLarge,
    /// A suite identifier this version doesn't know.
    #[error("unsupported suite {0}")]
    UnsupportedSuite(u8),
    /// The recovery phrase could not be read.
    #[error("invalid recovery phrase: {0}")]
    InvalidRecoveryPhrase(RecoveryPhraseError),
}

/// Why a recovery phrase was rejected. Never carries the words themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryPhraseError {
    /// Not exactly 24 words.
    WordCount,
    /// A word is not in the word list.
    UnknownWord,
    /// The words are valid but their checksum doesn't match: probably a typo or swapped words.
    Checksum,
}

impl fmt::Display for RecoveryPhraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WordCount => "it must have exactly 24 words",
            Self::UnknownWord => "a word is not in the word list",
            Self::Checksum => "the checksum doesn't match",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_carry_no_secrets() {
        assert_eq!(CryptoError::Decrypt.to_string(), "decryption failed");
        assert_eq!(
            CryptoError::InvalidLength {
                expected: 32,
                actual: 3
            }
            .to_string(),
            "invalid length: expected 32 bytes, got 3"
        );
        assert_eq!(
            CryptoError::InvalidRecoveryPhrase(RecoveryPhraseError::Checksum).to_string(),
            "invalid recovery phrase: the checksum doesn't match"
        );
        assert_eq!(
            CryptoError::InvalidRecoveryPhrase(RecoveryPhraseError::WordCount).to_string(),
            "invalid recovery phrase: it must have exactly 24 words"
        );
        assert_eq!(
            CryptoError::InvalidRecoveryPhrase(RecoveryPhraseError::UnknownWord).to_string(),
            "invalid recovery phrase: a word is not in the word list"
        );
        assert_eq!(
            CryptoError::UnsupportedSuite(7).to_string(),
            "unsupported suite 7"
        );
        assert_eq!(
            CryptoError::InvalidSignature.to_string(),
            "invalid signature"
        );
        assert_eq!(CryptoError::InvalidKey.to_string(), "invalid key");
        assert_eq!(CryptoError::TooLarge.to_string(), "input too large");
    }
}
