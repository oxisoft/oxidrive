use oxisoft_drive_crypto::CryptoError;

/// Everything that can go wrong while chunking or handling chunk objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChunkError {
    /// Decryption, authentication or suite failure.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The object was written by a format version this code doesn't know.
    #[error("unsupported chunk format version {0}")]
    UnsupportedVersion(u8),
    /// The object belongs to another key epoch than the keys supplied.
    #[error("chunk is from key epoch {object}, keys are for epoch {keys}")]
    EpochMismatch {
        /// Epoch recorded in the object.
        object: u32,
        /// Epoch of the keys used.
        keys: u32,
    },
    /// The object decrypted but its contents are not well-formed.
    #[error("malformed chunk object")]
    Malformed,
    /// The decrypted content doesn't hash to the chunk ID it was stored under.
    #[error("chunk content doesn't match its ID")]
    IdMismatch,
    /// A chunk larger than [`MAX_CHUNK_LEN`](crate::MAX_CHUNK_LEN).
    #[error("chunk too large")]
    TooLarge,
    /// Chunking parameters outside the supported ranges.
    #[error("invalid chunking parameters")]
    InvalidParams,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages() {
        assert_eq!(
            ChunkError::Crypto(CryptoError::Decrypt).to_string(),
            "decryption failed"
        );
        assert_eq!(
            ChunkError::UnsupportedVersion(9).to_string(),
            "unsupported chunk format version 9"
        );
        assert_eq!(
            ChunkError::EpochMismatch { object: 2, keys: 3 }.to_string(),
            "chunk is from key epoch 2, keys are for epoch 3"
        );
        assert_eq!(ChunkError::Malformed.to_string(), "malformed chunk object");
        assert_eq!(
            ChunkError::IdMismatch.to_string(),
            "chunk content doesn't match its ID"
        );
        assert_eq!(ChunkError::TooLarge.to_string(), "chunk too large");
        assert_eq!(
            ChunkError::InvalidParams.to_string(),
            "invalid chunking parameters"
        );
    }
}
