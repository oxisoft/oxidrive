use oxisoft_drive_chunking::ChunkError;
use oxisoft_drive_proto::ProtoError;

use crate::traits::{FsError, IndexError, ServerError};

/// Why a sync attempt failed. The engine's state stays consistent; a later attempt resumes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// The local file system failed.
    #[error(transparent)]
    Fs(#[from] FsError),
    /// The server failed or refused.
    #[error(transparent)]
    Server(#[from] ServerError),
    /// The index failed.
    #[error(transparent)]
    Index(#[from] IndexError),
    /// A commit or record didn't verify or decode.
    #[error(transparent)]
    Proto(#[from] ProtoError),
    /// A chunk object didn't verify or decode.
    #[error(transparent)]
    Chunk(#[from] ChunkError),
    /// A commit uses a key epoch this device doesn't have.
    #[error("missing key for epoch {epoch}")]
    MissingKey {
        /// The epoch.
        epoch: u32,
    },
    /// A downloaded file doesn't match its content hash.
    #[error("downloaded content doesn't match its hash")]
    ContentMismatch,
    /// Other devices kept committing first; try again later.
    #[error("gave up after repeated commit conflicts")]
    TooManyRetries,
}
