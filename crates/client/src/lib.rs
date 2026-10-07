//! oxidrive client runtime: the real implementations of core's traits, and the server's API
//! (client foundation, milestone 1 step 7a).
//!
//! - [`OsFs`]: core's `FileSystem` on a real folder.
//! - [`SqliteIndex`]: core's `IndexStore` in a SQLite file per collection.
//! - [`http`]: the server's API, sign-in, the event socket, and [`http::HttpServer`], core's
//!   `ServerApi` over HTTP.

mod fs;
pub mod http;
mod index;

pub use fs::OsFs;
pub use index::SqliteIndex;
