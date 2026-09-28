use oxisoft_drive_crypto::CryptoError;

/// Everything that can go wrong with oxidrive's formats.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// A signature, decryption or key problem.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Bytes that are not a valid encoding of the expected type.
    #[error("malformed data: {0}")]
    Decode(String),
    /// An object written in a format version this code doesn't know.
    #[error("unsupported format version {0}")]
    UnsupportedFormat(u8),
    /// A file or folder name that isn't allowed.
    #[error("invalid name: {0}")]
    InvalidName(NameError),
    /// A commit log that doesn't verify.
    #[error("invalid commit chain: {0}")]
    Chain(ChainError),
    /// A device list whose version doesn't increase.
    #[error("device list version went backwards")]
    ListRollback,
    /// An object too large to encode.
    #[error("object too large")]
    TooLarge,
    /// Visible and encrypted parts of a record, certificate or code disagree.
    #[error("inconsistent object: {0}")]
    Inconsistent(&'static str),
}

/// Why a name was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// The empty string.
    #[error("empty")]
    Empty,
    /// Longer than 255 bytes after normalisation.
    #[error("longer than 255 bytes")]
    TooLong,
    /// Contains `/` or NUL.
    #[error("contains `/` or NUL")]
    ForbiddenCharacter,
    /// `.` or `..`.
    #[error("`.` and `..` are reserved")]
    Reserved,
}

/// Why a commit chain was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// A commit's sequence number isn't the previous one plus one.
    #[error("sequence number out of order")]
    Sequence,
    /// A commit doesn't point at the hash of the previous one.
    #[error("broken link to the previous commit")]
    Link,
    /// The records don't match the hash the signer committed to.
    #[error("records don't match the signed hash")]
    RecordsHash,
    /// A commit belongs to another collection.
    #[error("commit belongs to another collection")]
    Collection,
    /// Signed by a device that isn't trusted.
    #[error("signed by an unknown or revoked device")]
    UnknownDevice,
}

impl From<minicbor::decode::Error> for ProtoError {
    fn from(error: minicbor::decode::Error) -> Self {
        Self::Decode(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages() {
        let cases: [(ProtoError, &str); 12] = [
            (CryptoError::Decrypt.into(), "decryption failed"),
            (ProtoError::Decode("x".into()), "malformed data: x"),
            (
                ProtoError::UnsupportedFormat(9),
                "unsupported format version 9",
            ),
            (
                ProtoError::InvalidName(NameError::Empty),
                "invalid name: empty",
            ),
            (
                ProtoError::InvalidName(NameError::TooLong),
                "invalid name: longer than 255 bytes",
            ),
            (
                ProtoError::InvalidName(NameError::ForbiddenCharacter),
                "invalid name: contains `/` or NUL",
            ),
            (
                ProtoError::InvalidName(NameError::Reserved),
                "invalid name: `.` and `..` are reserved",
            ),
            (
                ProtoError::Chain(ChainError::Sequence),
                "invalid commit chain: sequence number out of order",
            ),
            (
                ProtoError::Chain(ChainError::Link),
                "invalid commit chain: broken link to the previous commit",
            ),
            (
                ProtoError::Chain(ChainError::RecordsHash),
                "invalid commit chain: records don't match the signed hash",
            ),
            (
                ProtoError::ListRollback,
                "device list version went backwards",
            ),
            (
                ProtoError::Inconsistent("chunks"),
                "inconsistent object: chunks",
            ),
        ];
        for (error, text) in cases {
            assert_eq!(error.to_string(), text);
        }
        assert_eq!(ProtoError::TooLarge.to_string(), "object too large");
        assert_eq!(
            ChainError::Collection.to_string(),
            "commit belongs to another collection"
        );
        assert_eq!(
            ChainError::UnknownDevice.to_string(),
            "signed by an unknown or revoked device"
        );
        let decode: ProtoError = minicbor::decode::<u8>(&[]).unwrap_err().into();
        assert!(matches!(decode, ProtoError::Decode(_)));
    }
}
