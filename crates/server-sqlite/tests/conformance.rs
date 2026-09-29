//! The metadata store conformance suite on SQLite, each case on a fresh database file.

#![cfg(test)]

use oxisoft_drive_server_sqlite::SqliteStore;

/// A fresh store in its own temporary directory, removed when the test ends.
async fn fresh() -> (SqliteStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&dir.path().join("meta.db"))
        .await
        .unwrap();
    (store, dir)
}

oxisoft_drive_server_store::conformance_tests!(fresh());
