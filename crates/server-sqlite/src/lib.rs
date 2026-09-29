//! oxidrive server: the SQLite metadata store (server storage §2), the default backend.
//!
//! Queries are checked at compile time against the schema in `migrations/` (offline data in
//! `.sqlx/`). Writes run in `BEGIN IMMEDIATE` transactions, so writers queue for the lock
//! instead of failing on an upgrade; the database runs in WAL mode with foreign keys on and
//! full synchronisation.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use oxisoft_drive_crypto::hash::Digest;
use oxisoft_drive_proto::api::Head;
use oxisoft_drive_proto::{
    AccountId, ChunkId, CollectionId, CommitHash, DeviceId, LeaseId, RecordHash, Seq,
};
use oxisoft_drive_server_store::{
    AccountRow, AccountStatus, AppendOutcome, ChunkRow, CollectionRow, LeaseRow, MetaStore,
    NewAccount, NewChunk, NewCollection, NewLease, PreparedAppend, RecordRef, StoreError,
    StoredCertificate, StoredCommit, StoredDeviceList, StoredSlot,
};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{Sqlite, Transaction};

/// Connections kept open; SQLite serialises writers anyway.
const MAX_CONNECTIONS: u32 = 8;
/// How long a writer waits for the lock before failing.
const BUSY_TIMEOUT: Duration = Duration::from_secs(30);

/// The SQLite metadata store.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Opens (creating if needed) the database at `path` and brings its schema up to date.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] if the database can't be opened, or was written by a newer
    /// version (a migration this code doesn't know).
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str("sqlite:")
            .map_err(backend)?
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(BUSY_TIMEOUT);
        let pool = SqlitePoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .connect_with(options)
            .await
            .map_err(backend)?;
        sqlx::migrate!()
            .run(&pool)
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        Ok(Self { pool })
    }

    async fn write(&self) -> Result<Transaction<'static, Sqlite>, StoreError> {
        self.pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(backend)
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "passed to `map_err`, which hands over the error"
)]
fn backend(error: sqlx::Error) -> StoreError {
    match &error {
        sqlx::Error::Database(database) if database.is_unique_violation() => StoreError::Duplicate,
        sqlx::Error::Database(database) if database.is_foreign_key_violation() => {
            StoreError::NotFound
        }
        _ => StoreError::Backend(error.to_string()),
    }
}

/// A number for the database: SQLite integers are signed, so bounds past `i64::MAX` clamp.
fn int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn uint(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt(format!("negative number {value}")))
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{} bytes where {N} belong", bytes.len())))
}

fn digest(bytes: &[u8]) -> Result<Digest, StoreError> {
    fixed(bytes).map(Digest::from_bytes)
}

fn head_of(seq: i64, hash: &[u8]) -> Result<Head, StoreError> {
    Ok(Head {
        seq: uint(seq)?,
        hash: CommitHash(digest(hash)?),
    })
}

fn status(text: &str) -> Result<AccountStatus, StoreError> {
    match text {
        "active" => Ok(AccountStatus::Active),
        "disabled" => Ok(AccountStatus::Disabled),
        other => Err(StoreError::Corrupt(format!("account status {other}"))),
    }
}

async fn head_in(
    tx: &mut Transaction<'static, Sqlite>,
    collection: &[u8],
) -> Result<Option<Head>, StoreError> {
    let row = sqlx::query!(
        "SELECT seq, hash FROM commits WHERE collection = ? ORDER BY seq DESC LIMIT 1",
        collection
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(backend)?;
    row.map(|row| head_of(row.seq, &row.hash)).transpose()
}

impl MetaStore for SqliteStore {
    async fn create_account(&self, account: &NewAccount) -> Result<(), StoreError> {
        let (id, quota, created) = (
            account.id.as_bytes().as_slice(),
            int(account.quota_bytes),
            int(account.created_ms),
        );
        sqlx::query!(
            "INSERT INTO accounts (id, signing_key, status, quota_bytes, used_bytes, created_ms)
             VALUES (?, ?, 'active', ?, 0, ?)",
            id,
            account.signing_key,
            quota,
            created
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn account(&self, id: AccountId) -> Result<Option<AccountRow>, StoreError> {
        let key = id.as_bytes().as_slice();
        let row = sqlx::query!(
            "SELECT signing_key, status, quota_bytes, used_bytes, created_ms FROM accounts
             WHERE id = ?",
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(AccountRow {
                id,
                signing_key: row.signing_key,
                status: status(&row.status)?,
                quota_bytes: uint(row.quota_bytes)?,
                used_bytes: uint(row.used_bytes)?,
                created_ms: uint(row.created_ms)?,
            })
        })
        .transpose()
    }

    async fn put_device_list(
        &self,
        account: AccountId,
        expected: Option<u64>,
        list: &StoredDeviceList,
        certificates: &[StoredCertificate],
    ) -> Result<(), StoreError> {
        let key = account.as_bytes().as_slice();
        let mut tx = self.write().await?;
        let current =
            sqlx::query_scalar!("SELECT version FROM device_lists WHERE account = ?", key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
        if current.map(uint).transpose()? != expected {
            return Err(StoreError::Conflict);
        }
        let version = int(list.version);
        sqlx::query!(
            "INSERT INTO device_lists (account, version, signed) VALUES (?, ?, ?)
             ON CONFLICT (account) DO UPDATE SET version = excluded.version,
                                                 signed = excluded.signed",
            key,
            version,
            list.signed
        )
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        for certificate in certificates {
            let device = certificate.device.as_bytes().as_slice();
            sqlx::query!(
                "INSERT INTO device_certificates (account, device, signed) VALUES (?, ?, ?)
                 ON CONFLICT DO NOTHING",
                key,
                device,
                certificate.signed
            )
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        }
        tx.commit().await.map_err(backend)
    }

    async fn device_list(
        &self,
        account: AccountId,
    ) -> Result<Option<StoredDeviceList>, StoreError> {
        let key = account.as_bytes().as_slice();
        let row = sqlx::query!(
            "SELECT version, signed FROM device_lists WHERE account = ?",
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(StoredDeviceList {
                version: uint(row.version)?,
                signed: row.signed,
            })
        })
        .transpose()
    }

    async fn certificate(
        &self,
        account: AccountId,
        device: DeviceId,
    ) -> Result<Option<StoredCertificate>, StoreError> {
        let (key, id) = (account.as_bytes().as_slice(), device.as_bytes().as_slice());
        let signed = sqlx::query_scalar!(
            "SELECT signed FROM device_certificates WHERE account = ? AND device = ?",
            key,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        Ok(signed.map(|signed| StoredCertificate { device, signed }))
    }

    async fn create_collection(&self, collection: &NewCollection) -> Result<(), StoreError> {
        let (id, account) = (
            collection.id.as_bytes().as_slice(),
            collection.account.as_bytes().as_slice(),
        );
        let (retention, created) = (
            i64::from(collection.retention_days),
            int(collection.created_ms),
        );
        sqlx::query!(
            "INSERT INTO collections (id, account, config, retention_days, created_ms)
             VALUES (?, ?, ?, ?, ?)",
            id,
            account,
            collection.config,
            retention,
            created
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn collection(&self, id: CollectionId) -> Result<Option<CollectionRow>, StoreError> {
        let key = id.as_bytes().as_slice();
        let row = sqlx::query!(
            "SELECT account, config, retention_days, created_ms FROM collections WHERE id = ?",
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(CollectionRow {
                id,
                account: AccountId::from_bytes(fixed(&row.account)?),
                config: row.config,
                retention_days: u32::try_from(row.retention_days)
                    .map_err(|_| StoreError::Corrupt("retention days".into()))?,
                created_ms: uint(row.created_ms)?,
            })
        })
        .transpose()
    }

    async fn head(&self, id: CollectionId) -> Result<Option<Head>, StoreError> {
        let key = id.as_bytes().as_slice();
        let row = sqlx::query!(
            "SELECT seq, hash FROM commits WHERE collection = ? ORDER BY seq DESC LIMIT 1",
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| head_of(row.seq, &row.hash)).transpose()
    }

    async fn append(&self, append: &PreparedAppend) -> Result<AppendOutcome, StoreError> {
        let collection = append.collection.as_bytes().as_slice();
        let mut tx = self.write().await?;
        let current = head_in(&mut tx, collection).await?;
        if current != append.expected || append.head.seq != append.expected.map_or(1, |h| h.seq + 1)
        {
            return Ok(AppendOutcome::Conflict(current));
        }
        let mut missing: Vec<ChunkId> = Vec::new();
        for chunk in append.records.iter().flat_map(|record| &record.chunks) {
            let bytes = chunk.0.as_bytes().as_slice();
            let known = sqlx::query_scalar!(
                "SELECT 1 AS known FROM chunks WHERE collection = ? AND chunk = ?",
                collection,
                bytes
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
            if known.is_none() && !missing.contains(chunk) {
                missing.push(*chunk);
            }
        }
        if !missing.is_empty() {
            return Ok(AppendOutcome::MissingChunks(missing));
        }
        let (seq, received) = (int(append.head.seq), int(append.received_ms));
        let (hash, device) = (
            append.head.hash.0.as_bytes().as_slice(),
            append.device.as_bytes().as_slice(),
        );
        sqlx::query!(
            "INSERT INTO commits (collection, seq, hash, header, device, received_ms)
             VALUES (?, ?, ?, ?, ?, ?)",
            collection,
            seq,
            hash,
            append.header,
            device,
            received
        )
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        for (index, record) in (0_i64..).zip(&append.records) {
            let (node, record_hash) = (
                record.node.as_bytes().as_slice(),
                record.hash.0.as_bytes().as_slice(),
            );
            sqlx::query!(
                "UPDATE records SET superseded_ms = ?
                 WHERE collection = ? AND node = ? AND superseded_ms IS NULL",
                received,
                collection,
                node
            )
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            sqlx::query!(
                "INSERT INTO records (collection, seq, idx, node, hash, body, superseded_ms)
                 VALUES (?, ?, ?, ?, ?, ?, NULL)",
                collection,
                seq,
                index,
                node,
                record_hash,
                record.body
            )
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            for chunk in &record.chunks {
                let chunk = chunk.0.as_bytes().as_slice();
                sqlx::query!(
                    "INSERT INTO record_chunks (collection, seq, idx, chunk) VALUES (?, ?, ?, ?)
                     ON CONFLICT DO NOTHING",
                    collection,
                    seq,
                    index,
                    chunk
                )
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
            }
        }
        tx.commit().await.map_err(backend)?;
        Ok(AppendOutcome::Appended(append.head))
    }

    async fn commits_after(
        &self,
        id: CollectionId,
        after: Seq,
        limit: u32,
    ) -> Result<Vec<StoredCommit>, StoreError> {
        let (key, after, limit) = (id.as_bytes().as_slice(), int(after), i64::from(limit));
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let commits = sqlx::query!(
            "SELECT seq, hash, header FROM commits WHERE collection = ? AND seq > ?
             ORDER BY seq LIMIT ?",
            key,
            after,
            limit
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(backend)?;
        let Some(last) = commits.last().map(|commit| commit.seq) else {
            return Ok(Vec::new());
        };
        let records = sqlx::query!(
            "SELECT seq, hash, body FROM records WHERE collection = ? AND seq > ? AND seq <= ?
             ORDER BY seq, idx",
            key,
            after,
            last
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        let mut records = records.into_iter().peekable();
        commits
            .into_iter()
            .map(|commit| {
                let mut slots = Vec::new();
                while let Some(record) = records.next_if(|record| record.seq == commit.seq) {
                    slots.push(match record.body {
                        Some(body) => StoredSlot::Present(body),
                        None => StoredSlot::Pruned(RecordHash(digest(&record.hash)?)),
                    });
                }
                Ok(StoredCommit {
                    seq: uint(commit.seq)?,
                    hash: CommitHash(digest(&commit.hash)?),
                    header: commit.header,
                    records: slots,
                })
            })
            .collect()
    }

    async fn missing(
        &self,
        id: CollectionId,
        chunks: &[ChunkId],
    ) -> Result<Vec<ChunkId>, StoreError> {
        let key = id.as_bytes().as_slice();
        let mut connection = self.pool.acquire().await.map_err(backend)?;
        let mut missing: Vec<ChunkId> = Vec::new();
        for chunk in chunks {
            if missing.contains(chunk) {
                continue;
            }
            let bytes = chunk.0.as_bytes().as_slice();
            let known = sqlx::query_scalar!(
                "SELECT 1 AS known FROM chunks WHERE collection = ? AND chunk = ?",
                key,
                bytes
            )
            .fetch_optional(&mut *connection)
            .await
            .map_err(backend)?;
            if known.is_none() {
                missing.push(*chunk);
            }
        }
        Ok(missing)
    }

    async fn create_lease(&self, lease: &NewLease) -> Result<(), StoreError> {
        let (id, collection, expires) = (
            lease.id.as_bytes().as_slice(),
            lease.collection.as_bytes().as_slice(),
            int(lease.expires_ms),
        );
        let mut tx = self.write().await?;
        sqlx::query!(
            "INSERT INTO leases (id, collection, expires_ms) VALUES (?, ?, ?)",
            id,
            collection,
            expires
        )
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        for chunk in &lease.chunks {
            let chunk = chunk.0.as_bytes().as_slice();
            sqlx::query!(
                "INSERT INTO lease_chunks (lease, chunk) VALUES (?, ?) ON CONFLICT DO NOTHING",
                id,
                chunk
            )
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        }
        tx.commit().await.map_err(backend)
    }

    async fn lease(&self, id: LeaseId) -> Result<Option<LeaseRow>, StoreError> {
        let key = id.as_bytes().as_slice();
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let Some(row) = sqlx::query!(
            "SELECT collection, expires_ms FROM leases WHERE id = ?",
            key
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?
        else {
            return Ok(None);
        };
        let chunks = sqlx::query_scalar!(
            "SELECT chunk FROM lease_chunks WHERE lease = ? ORDER BY chunk",
            key
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(Some(LeaseRow {
            id,
            collection: CollectionId::from_bytes(fixed(&row.collection)?),
            expires_ms: uint(row.expires_ms)?,
            chunks: chunks
                .iter()
                .map(|chunk| digest(chunk).map(ChunkId))
                .collect::<Result<_, _>>()?,
        }))
    }

    async fn add_chunk(&self, chunk: &NewChunk) -> Result<bool, StoreError> {
        let (collection, id) = (
            chunk.collection.as_bytes().as_slice(),
            chunk.chunk.0.as_bytes().as_slice(),
        );
        let (size, stored) = (int(chunk.size), int(chunk.stored_ms));
        let mut tx = self.write().await?;
        let inserted = sqlx::query!(
            "INSERT INTO chunks (collection, chunk, size, stored_ms) VALUES (?, ?, ?, ?)
             ON CONFLICT DO NOTHING",
            collection,
            id,
            size,
            stored
        )
        .execute(&mut *tx)
        .await
        .map_err(backend)?
        .rows_affected();
        if inserted == 0 {
            return Ok(false);
        }
        sqlx::query!(
            "UPDATE accounts SET used_bytes = used_bytes + ?
             WHERE id = (SELECT account FROM collections WHERE id = ?)",
            size,
            collection
        )
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(true)
    }

    async fn chunk(
        &self,
        id: CollectionId,
        chunk: ChunkId,
    ) -> Result<Option<ChunkRow>, StoreError> {
        let (key, bytes) = (id.as_bytes().as_slice(), chunk.0.as_bytes().as_slice());
        let row = sqlx::query!(
            "SELECT c.account, ch.size, ch.stored_ms FROM chunks ch
             JOIN collections c ON c.id = ch.collection
             WHERE ch.collection = ? AND ch.chunk = ?",
            key,
            bytes
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(ChunkRow {
                account: AccountId::from_bytes(fixed(&row.account)?),
                collection: id,
                chunk,
                size: uint(row.size)?,
                stored_ms: uint(row.stored_ms)?,
            })
        })
        .transpose()
    }

    async fn prunable(&self, now_ms: u64, limit: u32) -> Result<Vec<RecordRef>, StoreError> {
        let (now, limit) = (int(now_ms), i64::from(limit));
        let rows = sqlx::query!(
            "SELECT r.collection, r.seq, r.idx FROM records r
             JOIN collections c ON c.id = r.collection
             WHERE r.body IS NOT NULL AND r.superseded_ms IS NOT NULL
               AND r.superseded_ms + c.retention_days * 86400000 <= ?
             ORDER BY r.collection, r.seq, r.idx LIMIT ?",
            now,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                Ok(RecordRef {
                    collection: CollectionId::from_bytes(fixed(&row.collection)?),
                    seq: uint(row.seq)?,
                    index: u32::try_from(row.idx)
                        .map_err(|_| StoreError::Corrupt("record index".into()))?,
                })
            })
            .collect()
    }

    async fn prune(&self, records: &[RecordRef]) -> Result<(), StoreError> {
        let mut tx = self.write().await?;
        for record in records {
            let (collection, seq, index) = (
                record.collection.as_bytes().as_slice(),
                int(record.seq),
                i64::from(record.index),
            );
            sqlx::query!(
                "DELETE FROM record_chunks WHERE collection = ? AND seq = ? AND idx = ?",
                collection,
                seq,
                index
            )
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            sqlx::query!(
                "UPDATE records SET body = NULL WHERE collection = ? AND seq = ? AND idx = ?",
                collection,
                seq,
                index
            )
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        }
        tx.commit().await.map_err(backend)
    }

    async fn drop_expired_leases(&self, now_ms: u64) -> Result<u64, StoreError> {
        let now = int(now_ms);
        let mut tx = self.write().await?;
        sqlx::query!(
            "DELETE FROM lease_chunks WHERE lease IN (SELECT id FROM leases WHERE expires_ms <= ?)",
            now
        )
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        let dropped = sqlx::query!("DELETE FROM leases WHERE expires_ms <= ?", now)
            .execute(&mut *tx)
            .await
            .map_err(backend)?
            .rows_affected();
        tx.commit().await.map_err(backend)?;
        Ok(dropped)
    }

    async fn garbage(&self, now_ms: u64, limit: u32) -> Result<Vec<ChunkRow>, StoreError> {
        let (now, limit) = (int(now_ms), i64::from(limit));
        let rows = sqlx::query!(
            "SELECT c.account, ch.collection, ch.chunk, ch.size, ch.stored_ms FROM chunks ch
             JOIN collections c ON c.id = ch.collection
             WHERE NOT EXISTS (SELECT 1 FROM record_chunks rc
                               WHERE rc.collection = ch.collection AND rc.chunk = ch.chunk)
               AND NOT EXISTS (SELECT 1 FROM lease_chunks lc JOIN leases l ON l.id = lc.lease
                               WHERE l.collection = ch.collection AND lc.chunk = ch.chunk
                                 AND l.expires_ms > ?)
             ORDER BY ch.collection, ch.chunk LIMIT ?",
            now,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                Ok(ChunkRow {
                    account: AccountId::from_bytes(fixed(&row.account)?),
                    collection: CollectionId::from_bytes(fixed(&row.collection)?),
                    chunk: ChunkId(digest(&row.chunk)?),
                    size: uint(row.size)?,
                    stored_ms: uint(row.stored_ms)?,
                })
            })
            .collect()
    }

    async fn forget_chunks(
        &self,
        chunks: &[ChunkRow],
        now_ms: u64,
    ) -> Result<Vec<ChunkRow>, StoreError> {
        let now = int(now_ms);
        let mut tx = self.write().await?;
        let mut forgotten = Vec::new();
        for row in chunks {
            let (collection, chunk) = (
                row.collection.as_bytes().as_slice(),
                row.chunk.0.as_bytes().as_slice(),
            );
            let size = sqlx::query_scalar!(
                "DELETE FROM chunks
                 WHERE collection = ? AND chunk = ?
                   AND NOT EXISTS (SELECT 1 FROM record_chunks rc
                                   WHERE rc.collection = chunks.collection
                                     AND rc.chunk = chunks.chunk)
                   AND NOT EXISTS (SELECT 1 FROM lease_chunks lc JOIN leases l ON l.id = lc.lease
                                   WHERE l.collection = chunks.collection
                                     AND lc.chunk = chunks.chunk AND l.expires_ms > ?)
                 RETURNING size",
                collection,
                chunk,
                now
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(backend)?;
            let Some(size) = size else {
                continue;
            };
            sqlx::query!(
                "UPDATE accounts SET used_bytes = used_bytes - ?
                 WHERE id = (SELECT account FROM collections WHERE id = ?)",
                size,
                collection
            )
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
            forgotten.push(row.clone());
        }
        tx.commit().await.map_err(backend)?;
        Ok(forgotten)
    }

    async fn all_chunks(
        &self,
        after: Option<(CollectionId, ChunkId)>,
        limit: u32,
    ) -> Result<Vec<ChunkRow>, StoreError> {
        let (after_collection, after_chunk) = after.map_or((Vec::new(), Vec::new()), |(c, ch)| {
            (c.as_bytes().to_vec(), ch.0.as_bytes().to_vec())
        });
        let limit = i64::from(limit);
        // An empty blob sorts before every ID, so "after nothing" is "after the empty key".
        let rows = sqlx::query!(
            "SELECT c.account, ch.collection, ch.chunk, ch.size, ch.stored_ms FROM chunks ch
             JOIN collections c ON c.id = ch.collection
             WHERE ch.collection > ? OR (ch.collection = ? AND ch.chunk > ?)
             ORDER BY ch.collection, ch.chunk LIMIT ?",
            after_collection,
            after_collection,
            after_chunk,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                Ok(ChunkRow {
                    account: AccountId::from_bytes(fixed(&row.account)?),
                    collection: CollectionId::from_bytes(fixed(&row.collection)?),
                    chunk: ChunkId(digest(&row.chunk)?),
                    size: uint(row.size)?,
                    stored_ms: uint(row.stored_ms)?,
                })
            })
            .collect()
    }
}
