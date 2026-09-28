//! oxidrive sync engine: sans-I/O state machines, conflict rules and the traits for all
//! outside dependencies.
//!
//! The heart is [`reconcile`]: a pure function comparing what this device last synced (the
//! base), what is on disk now (local) and what the collection holds (remote), and returning a
//! [`Plan`]. Every sync decision, including conflict handling, lives there, so it can be
//! tested exhaustively. An executor (next step) carries plans out.

mod engine;
mod error;
mod model;
mod names;
mod path;
mod plan;
mod reconcile;
mod remote;
mod scan;
mod traits;

pub use engine::{ConflictTag, Engine, EngineConfig, IgnoreRule, SyncReport};
pub use error::EngineError;
pub use model::{
    Base, BaseEntry, BaseKind, LocalEntry, LocalTree, RemoteKind, RemoteNode, RemoteTree, Stat,
    TreeError, remote_paths,
};
pub use names::{conflict_name, windows_allows};
pub use path::RelPath;
pub use plan::{Conflict, Pause, Plan, SkipReason, Skipped, Step};
pub use reconcile::{FsRules, MassDeleteBrake, Options, reconcile};
pub use remote::{CollectionKeys, FileMeta, RemoteEntry, RemoteState};
pub use scan::{ENGINE_DIR, MARKER, Scan, content_hash, is_engine_path, marker_path, scan};
pub use traits::{
    Clock, DirEntry, DirList, FileSystem, FsEntry, FsError, IndexError, IndexState, IndexStore,
    IndexTxn, ServerApi, ServerError, TempId,
};
