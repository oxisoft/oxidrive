//! oxidrive server: stores only encrypted data, orders commits and serves the sync API.
//!
//! - [`Service`]: the rules (server storage §4) over a metadata store (`MetaStore`, from
//!   `oxisoft-drive-server-store`, with SQLite and PostgreSQL backends) and a [`BlobStore`].
//! - [`FsBlobStore`]: chunk objects as files; [`MemBlobStore`] for tests.
//!
//! The HTTP API and the `oxidrive-server` binary follow in steps 6b and 6c.

mod api;
pub mod backup;
mod blob;
pub mod cli;
pub mod config;
pub mod serve;
mod service;
pub mod tls;

pub use api::{Api, ApiConfig, Deps, RateLimits, ServiceOf, With};

pub use blob::{BlobError, BlobKey, BlobOp, BlobStore, ChunkBytes, FsBlobStore, MemBlobStore};
pub use service::{
    AccountSummary, Caller, Clock, FsckReport, GcReport, RestoreReport, Service, ServiceError,
    Settings, SystemClock,
};
