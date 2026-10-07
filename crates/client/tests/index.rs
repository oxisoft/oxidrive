//! [`SqliteIndex`]: the index conformance suite, and what only a file has (surviving a
//! reopen, refusing a newer format).

#![cfg(test)]

use oxisoft_drive_client::SqliteIndex;
use oxisoft_drive_core::{IndexStore, IndexTxn};

async fn fresh() -> (SqliteIndex, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let index = SqliteIndex::open(&dir.path().join("index.sqlite"))
        .await
        .unwrap();
    (index, dir)
}

oxisoft_drive_testkit::index_conformance_tests!(fresh());

#[tokio::test]
async fn the_index_survives_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("index.sqlite");
    let index = SqliteIndex::open(&file).await.unwrap();
    oxisoft_drive_testkit::index_conformance::round_trips_every_kind(&index).await;
    let before = index.load().await.unwrap();
    drop(index);
    let reopened = SqliteIndex::open(&file).await.unwrap();
    assert_eq!(reopened.load().await.unwrap(), before);
    reopened
        .apply(IndexTxn {
            counter: Some(99),
            ..IndexTxn::default()
        })
        .await
        .unwrap();
    assert_eq!(reopened.load().await.unwrap().counter, 99);
}

#[tokio::test]
async fn a_newer_format_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("index.sqlite");
    drop(SqliteIndex::open(&file).await.unwrap());
    // Options rather than a URL: a Windows path doesn't make a valid URL.
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(&file);
    let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
    sqlx::query("UPDATE state SET format = 2")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let refused = SqliteIndex::open(&file).await.unwrap_err();
    assert!(refused.0.contains("format 2"), "{refused}");
    assert!(
        SqliteIndex::open(&dir.path().join("missing").join("index.sqlite"))
            .await
            .is_err()
    );
}
