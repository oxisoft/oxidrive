//! The metadata store conformance suite on PostgreSQL, each case in a fresh database.
//!
//! Needs `OXIDRIVE_TEST_POSTGRES_URL`: a server URL whose user may create databases (for
//! example `postgres://postgres:secret@127.0.0.1:5432/postgres`). `cargo xtask ci` starts a
//! throwaway server and sets it; CI provides a service container. Without it these tests
//! fail rather than skip (server crate G3).

#![cfg(test)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use oxisoft_drive_server_postgres::PostgresStore;
use sqlx::Connection;

/// A fresh store in a database of its own (the throwaway server goes away with them all).
async fn fresh() -> (PostgresStore, ()) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let base = std::env::var("OXIDRIVE_TEST_POSTGRES_URL")
        .expect("OXIDRIVE_TEST_POSTGRES_URL must point at a PostgreSQL server for these tests");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!(
        "t{}_{}_{}",
        std::process::id(),
        stamp,
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let mut admin = sqlx::PgConnection::connect(&base).await.unwrap();
    // The name is made of digits and underscores only.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&mut admin)
        .await
        .unwrap();
    let (prefix, _) = base.rsplit_once('/').unwrap();
    let store = PostgresStore::open(&format!("{prefix}/{name}"))
        .await
        .unwrap();
    (store, ())
}

oxisoft_drive_server_store::conformance_tests!(fresh());
