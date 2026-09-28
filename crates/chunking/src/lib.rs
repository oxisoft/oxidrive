//! oxidrive chunking: keyed content-defined chunking, padding and encrypted chunk objects.
//!
//! - [`Chunker`] splits data into chunks at content-defined boundaries (`FastCDC` 2020), with a
//!   gear table derived from the collection's chunking key, so boundaries can't be predicted
//!   without the key.
//! - [`padme`] rounds lengths up so exact sizes don't leak.
//! - [`seal_chunk`] and [`open_chunk`] turn a chunk into an encrypted, padded, optionally
//!   compressed object and back, verifying its ID on the way out.
//!
//! The crate performs no I/O: callers feed it bytes. Memory use is bounded by the maximum
//! chunk size.

mod chunker;
mod error;
mod object;
mod padding;

pub use chunker::{ChunkParams, Chunker, Chunks};
pub use error::ChunkError;
pub use object::{
    COMPRESSION_LEVEL, ChunkKeys, FORMAT_VERSION, MAX_CHUNK_LEN, SealedChunk, object_epoch,
    open_chunk, seal_chunk,
};
pub use padding::padme;
