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
    AccountId, ChunkId, CollectionId, CommitHash, DeviceId, LeaseId, PairingId, RecordHash, Seq,
};
use oxisoft_drive_server_store::{
    AccountRow, AccountStatus, AppendOutcome, ChunkRow, CollectionRow, LeaseRow, MetaStore,
    NewAccount, NewChunk, NewCollection, NewLease, PairingRow, PreparedAppend, RecordRef,
    SessionRow, StoreError, StoredAttestation, StoredCertificate, StoredCommit, StoredDeviceList,
    StoredEnvelope, StoredSlot,
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

fn collection_row(
    id: &[u8],
    account: &[u8],
    config: Vec<u8>,
    retention_days: i64,
    created_ms: i64,
    deleted_ms: Option<i64>,
) -> Result<CollectionRow, StoreError> {
    Ok(CollectionRow {
        id: CollectionId::from_bytes(fixed(id)?),
        account: AccountId::from_bytes(fixed(account)?),
        config,
        retention_days: u32::try_from(retention_days)
            .map_err(|_| StoreError::Corrupt("retention days".into()))?,
        created_ms: uint(created_ms)?,
        deleted_ms: deleted_ms.map(uint).transpose()?,
    })
}

fn envelope_row(
    kind: i64,
    epoch: i64,
    device: &[u8],
    collection: &[u8],
    encoded: Vec<u8>,
) -> Result<StoredEnvelope, StoreError> {
    Ok(StoredEnvelope {
        kind: u8::try_from(kind).map_err(|_| StoreError::Corrupt("envelope kind".into()))?,
        epoch: u32::try_from(epoch).map_err(|_| StoreError::Corrupt("envelope epoch".into()))?,
        device: (!device.is_empty())
            .then(|| fixed(device).map(DeviceId::from_bytes))
            .transpose()?,
        collection: (!collection.is_empty())
            .then(|| fixed(collection).map(CollectionId::from_bytes))
            .transpose()?,
        encoded,
    })
}

async fn insert_account(
    tx: &mut Transaction<'static, Sqlite>,
    account: &NewAccount,
) -> Result<(), StoreError> {
    let (id, quota, created) = (
        account.id.as_bytes().as_slice(),
        int(account.quota_bytes),
        int(account.created_ms),
    );
    sqlx::query!(
        "INSERT INTO accounts (id, signing_key, kem_key, status, quota_bytes, used_bytes,
                               created_ms)
         VALUES (?, ?, ?, 'active', ?, 0, ?)",
        id,
        account.signing_key,
        account.kem_key,
        quota,
        created
    )
    .execute(&mut **tx)
    .await
    .map_err(backend)?;
    Ok(())
}

async fn write_list(
    tx: &mut Transaction<'static, Sqlite>,
    account: AccountId,
    list: &StoredDeviceList,
) -> Result<(), StoreError> {
    let (key, version) = (account.as_bytes().as_slice(), int(list.version));
    sqlx::query!(
        "INSERT INTO device_lists (account, version, signed) VALUES (?, ?, ?)
         ON CONFLICT (account) DO UPDATE SET version = excluded.version,
                                             signed = excluded.signed",
        key,
        version,
        list.signed
    )
    .execute(&mut **tx)
    .await
    .map_err(backend)?;
    Ok(())
}

async fn insert_certificates(
    tx: &mut Transaction<'static, Sqlite>,
    account: AccountId,
    certificates: &[StoredCertificate],
) -> Result<(), StoreError> {
    let key = account.as_bytes().as_slice();
    for certificate in certificates {
        let device = certificate.device.as_bytes().as_slice();
        sqlx::query!(
            "INSERT INTO device_certificates (account, device, signed) VALUES (?, ?, ?)
             ON CONFLICT DO NOTHING",
            key,
            device,
            certificate.signed
        )
        .execute(&mut **tx)
        .await
        .map_err(backend)?;
    }
    Ok(())
}

/// Stores envelopes; one already stored under the same address is replaced.
async fn insert_envelopes(
    tx: &mut Transaction<'static, Sqlite>,
    account: AccountId,
    envelopes: &[StoredEnvelope],
) -> Result<(), StoreError> {
    let key = account.as_bytes().as_slice();
    for envelope in envelopes {
        let (kind, epoch) = (i64::from(envelope.kind), i64::from(envelope.epoch));
        let device = envelope
            .device
            .map(|device| device.as_bytes().to_vec())
            .unwrap_or_default();
        let collection = envelope
            .collection
            .map(|collection| collection.as_bytes().to_vec())
            .unwrap_or_default();
        sqlx::query!(
            "INSERT INTO envelopes (account, kind, epoch, device, collection, encoded)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (account, kind, epoch, device, collection)
             DO UPDATE SET encoded = excluded.encoded",
            key,
            kind,
            epoch,
            device,
            collection,
            envelope.encoded
        )
        .execute(&mut **tx)
        .await
        .map_err(backend)?;
    }
    Ok(())
}

impl MetaStore for SqliteStore {
    async fn create_account(&self, account: &NewAccount) -> Result<(), StoreError> {
        let mut tx = self.write().await?;
        insert_account(&mut tx, account).await?;
        tx.commit().await.map_err(backend)
    }

    async fn account(&self, id: AccountId) -> Result<Option<AccountRow>, StoreError> {
        let key = id.as_bytes().as_slice();
        let row = sqlx::query!(
            "SELECT signing_key, kem_key, status, quota_bytes, used_bytes, created_ms
             FROM accounts WHERE id = ?",
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(AccountRow {
                id,
                signing_key: row.signing_key,
                kem_key: row.kem_key,
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
        envelopes: &[StoredEnvelope],
        revoked: &[DeviceId],
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
        write_list(&mut tx, account, list).await?;
        insert_certificates(&mut tx, account, certificates).await?;
        insert_envelopes(&mut tx, account, envelopes).await?;
        for device in revoked {
            let device = device.as_bytes().as_slice();
            sqlx::query!(
                "DELETE FROM sessions WHERE account = ? AND device = ?",
                key,
                device
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
        let mut tx = self.write().await?;
        sqlx::query!(
            "INSERT INTO collections (id, account, config, retention_days, created_ms)
             VALUES (?, ?, ?, ?, ?)",
            id,
            account,
            collection.config,
            retention,
            created
        )
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        insert_envelopes(&mut tx, collection.account, collection.key.as_slice()).await?;
        tx.commit().await.map_err(backend)
    }

    async fn collection(&self, id: CollectionId) -> Result<Option<CollectionRow>, StoreError> {
        let key = id.as_bytes().as_slice();
        let row = sqlx::query!(
            "SELECT account, config, retention_days, created_ms, deleted_ms
             FROM collections WHERE id = ?",
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            collection_row(
                id.as_bytes(),
                &row.account,
                row.config,
                row.retention_days,
                row.created_ms,
                row.deleted_ms,
            )
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

    async fn certificates(&self, account: AccountId) -> Result<Vec<StoredCertificate>, StoreError> {
        let key = account.as_bytes().as_slice();
        let rows = sqlx::query!(
            "SELECT device, signed FROM device_certificates WHERE account = ? ORDER BY device",
            key
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                Ok(StoredCertificate {
                    device: DeviceId::from_bytes(fixed(&row.device)?),
                    signed: row.signed,
                })
            })
            .collect()
    }

    async fn account_of_device(&self, device: DeviceId) -> Result<Option<AccountId>, StoreError> {
        let key = device.as_bytes().as_slice();
        let account = sqlx::query_scalar!(
            "SELECT account FROM device_certificates WHERE device = ? LIMIT 1",
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        account
            .map(|account| fixed(&account).map(AccountId::from_bytes))
            .transpose()
    }

    async fn create_invite(&self, hash: [u8; 32], expires_ms: u64) -> Result<(), StoreError> {
        let (key, expires) = (hash.as_slice(), int(expires_ms));
        sqlx::query!(
            "INSERT INTO invites (hash, expires_ms, used_ms) VALUES (?, ?, NULL)",
            key,
            expires
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn create_account_by_invite(
        &self,
        invite: [u8; 32],
        now_ms: u64,
        account: &NewAccount,
        list: &StoredDeviceList,
        certificate: &StoredCertificate,
        envelopes: &[StoredEnvelope],
    ) -> Result<(), StoreError> {
        let (key, now) = (invite.as_slice(), int(now_ms));
        let mut tx = self.write().await?;
        let used = sqlx::query!(
            "UPDATE invites SET used_ms = ? WHERE hash = ? AND used_ms IS NULL AND expires_ms > ?",
            now,
            key,
            now
        )
        .execute(&mut *tx)
        .await
        .map_err(backend)?
        .rows_affected();
        if used == 0 {
            return Err(StoreError::NotFound);
        }
        insert_account(&mut tx, account).await?;
        write_list(&mut tx, account.id, list).await?;
        insert_certificates(&mut tx, account.id, std::slice::from_ref(certificate)).await?;
        insert_envelopes(&mut tx, account.id, envelopes).await?;
        tx.commit().await.map_err(backend)
    }

    async fn put_challenge(
        &self,
        device: DeviceId,
        nonce: [u8; 32],
        expires_ms: u64,
    ) -> Result<(), StoreError> {
        let (key, nonce, expires) = (
            device.as_bytes().as_slice(),
            nonce.as_slice(),
            int(expires_ms),
        );
        sqlx::query!(
            "INSERT INTO challenges (device, nonce, expires_ms) VALUES (?, ?, ?)
             ON CONFLICT (device) DO UPDATE SET nonce = excluded.nonce,
                                                expires_ms = excluded.expires_ms",
            key,
            nonce,
            expires
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn take_challenge(
        &self,
        device: DeviceId,
    ) -> Result<Option<([u8; 32], u64)>, StoreError> {
        let key = device.as_bytes().as_slice();
        let row = sqlx::query!(
            "DELETE FROM challenges WHERE device = ? RETURNING nonce, expires_ms",
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| Ok((fixed(&row.nonce)?, uint(row.expires_ms)?)))
            .transpose()
    }

    async fn create_session(&self, hash: [u8; 32], session: &SessionRow) -> Result<(), StoreError> {
        let (key, account, device, expires) = (
            hash.as_slice(),
            session.account.as_bytes().as_slice(),
            session.device.as_bytes().as_slice(),
            int(session.expires_ms),
        );
        sqlx::query!(
            "INSERT INTO sessions (hash, account, device, expires_ms) VALUES (?, ?, ?, ?)",
            key,
            account,
            device,
            expires
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn session(&self, hash: [u8; 32]) -> Result<Option<SessionRow>, StoreError> {
        let key = hash.as_slice();
        let row = sqlx::query!(
            "SELECT account, device, expires_ms FROM sessions WHERE hash = ?",
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(SessionRow {
                account: AccountId::from_bytes(fixed(&row.account)?),
                device: DeviceId::from_bytes(fixed(&row.device)?),
                expires_ms: uint(row.expires_ms)?,
            })
        })
        .transpose()
    }

    async fn drop_expired_sessions(&self, now_ms: u64) -> Result<u64, StoreError> {
        let now = int(now_ms);
        let mut tx = self.write().await?;
        let sessions = sqlx::query!("DELETE FROM sessions WHERE expires_ms <= ?", now)
            .execute(&mut *tx)
            .await
            .map_err(backend)?
            .rows_affected();
        let challenges = sqlx::query!("DELETE FROM challenges WHERE expires_ms <= ?", now)
            .execute(&mut *tx)
            .await
            .map_err(backend)?
            .rows_affected();
        tx.commit().await.map_err(backend)?;
        Ok(sessions + challenges)
    }

    async fn envelopes(&self, account: AccountId) -> Result<Vec<StoredEnvelope>, StoreError> {
        let key = account.as_bytes().as_slice();
        let rows = sqlx::query!(
            "SELECT kind, epoch, device, collection, encoded FROM envelopes WHERE account = ?
             ORDER BY kind, epoch, device, collection",
            key
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                envelope_row(
                    row.kind,
                    row.epoch,
                    &row.device,
                    &row.collection,
                    row.encoded,
                )
            })
            .collect()
    }

    async fn add_epoch(
        &self,
        account: AccountId,
        epoch: u32,
        envelopes: &[StoredEnvelope],
    ) -> Result<(), StoreError> {
        let key = account.as_bytes().as_slice();
        let mut tx = self.write().await?;
        let newest = sqlx::query_scalar!(
            r#"SELECT MAX(epoch) AS "newest: i64" FROM envelopes WHERE account = ?"#,
            key
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(backend)?;
        if newest != Some(i64::from(epoch) - 1) {
            return Err(StoreError::Conflict);
        }
        insert_envelopes(&mut tx, account, envelopes).await?;
        tx.commit().await.map_err(backend)
    }

    async fn collections(&self, account: AccountId) -> Result<Vec<CollectionRow>, StoreError> {
        let key = account.as_bytes().as_slice();
        let rows = sqlx::query!(
            "SELECT id, account, config, retention_days, created_ms, deleted_ms FROM collections
             WHERE account = ? AND deleted_ms IS NULL ORDER BY id",
            key
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                collection_row(
                    &row.id,
                    &row.account,
                    row.config,
                    row.retention_days,
                    row.created_ms,
                    row.deleted_ms,
                )
            })
            .collect()
    }

    async fn update_collection(
        &self,
        id: CollectionId,
        retention_days: Option<u32>,
        config: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        let key = id.as_bytes().as_slice();
        let retention = retention_days.map(i64::from);
        let changed = sqlx::query!(
            "UPDATE collections SET retention_days = COALESCE(?, retention_days),
                                    config = COALESCE(?, config)
             WHERE id = ?",
            retention,
            config,
            key
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?
        .rows_affected();
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn delete_collection(&self, id: CollectionId, now_ms: u64) -> Result<(), StoreError> {
        let (key, now) = (id.as_bytes().as_slice(), int(now_ms));
        let changed = sqlx::query!(
            "UPDATE collections SET deleted_ms = ? WHERE id = ? AND deleted_ms IS NULL",
            now,
            key
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?
        .rows_affected();
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn collection_usage(&self, id: CollectionId) -> Result<u64, StoreError> {
        let key = id.as_bytes().as_slice();
        let used = sqlx::query_scalar!(
            r#"SELECT COALESCE(SUM(size), 0) AS "used!: i64" FROM chunks WHERE collection = ?"#,
            key
        )
        .fetch_one(&self.pool)
        .await
        .map_err(backend)?;
        uint(used)
    }

    async fn purgeable_collections(&self, now_ms: u64) -> Result<Vec<CollectionId>, StoreError> {
        let now = int(now_ms);
        let ids = sqlx::query_scalar!(
            "SELECT id FROM collections
             WHERE deleted_ms IS NOT NULL AND purged = 0
               AND deleted_ms + retention_days * 86400000 <= ?
             ORDER BY id",
            now
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        ids.iter()
            .map(|id| fixed(id).map(CollectionId::from_bytes))
            .collect()
    }

    async fn purge_collection(&self, id: CollectionId) -> Result<(), StoreError> {
        let key = id.as_bytes().as_slice();
        let mut tx = self.write().await?;
        sqlx::query!("DELETE FROM record_chunks WHERE collection = ?", key)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        sqlx::query!("DELETE FROM records WHERE collection = ?", key)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        sqlx::query!("DELETE FROM commits WHERE collection = ?", key)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        sqlx::query!(
            "DELETE FROM lease_chunks WHERE lease IN (SELECT id FROM leases WHERE collection = ?)",
            key
        )
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        sqlx::query!("DELETE FROM leases WHERE collection = ?", key)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        sqlx::query!("DELETE FROM attestations WHERE collection = ?", key)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        sqlx::query!("DELETE FROM envelopes WHERE collection = ?", key)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        sqlx::query!("UPDATE collections SET purged = 1 WHERE id = ?", key)
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        tx.commit().await.map_err(backend)
    }

    async fn create_pairing(&self, pairing: &PairingRow) -> Result<(), StoreError> {
        let (id, expires) = (pairing.id.as_bytes().as_slice(), int(pairing.expires_ms));
        sqlx::query!(
            "INSERT INTO pairings (id, request, expires_ms, approval) VALUES (?, ?, ?, ?)",
            id,
            pairing.request,
            expires,
            pairing.approval
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn pairing(&self, id: PairingId) -> Result<Option<PairingRow>, StoreError> {
        let key = id.as_bytes().as_slice();
        let row = sqlx::query!(
            "SELECT request, expires_ms, approval FROM pairings WHERE id = ?",
            key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(PairingRow {
                id,
                request: row.request,
                expires_ms: uint(row.expires_ms)?,
                approval: row.approval,
            })
        })
        .transpose()
    }

    async fn approve_pairing(
        &self,
        id: PairingId,
        approval: &[u8],
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (key, now) = (id.as_bytes().as_slice(), int(now_ms));
        let changed = sqlx::query!(
            "UPDATE pairings SET approval = ?
             WHERE id = ? AND approval IS NULL AND expires_ms > ?",
            approval,
            key,
            now
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?
        .rows_affected();
        Ok(changed == 1)
    }

    async fn drop_expired_pairings(&self, now_ms: u64) -> Result<u64, StoreError> {
        let now = int(now_ms);
        let dropped = sqlx::query!("DELETE FROM pairings WHERE expires_ms <= ?", now)
            .execute(&self.pool)
            .await
            .map_err(backend)?
            .rows_affected();
        Ok(dropped)
    }

    async fn put_attestation(
        &self,
        collection: CollectionId,
        attestation: &StoredAttestation,
    ) -> Result<(), StoreError> {
        let (key, device) = (
            collection.as_bytes().as_slice(),
            attestation.device.as_bytes().as_slice(),
        );
        sqlx::query!(
            "INSERT INTO attestations (collection, device, signed) VALUES (?, ?, ?)
             ON CONFLICT (collection, device) DO UPDATE SET signed = excluded.signed",
            key,
            device,
            attestation.signed
        )
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn attestations(
        &self,
        collection: CollectionId,
    ) -> Result<Vec<StoredAttestation>, StoreError> {
        let key = collection.as_bytes().as_slice();
        let rows = sqlx::query!(
            "SELECT device, signed FROM attestations WHERE collection = ? ORDER BY device",
            key
        )
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                Ok(StoredAttestation {
                    device: DeviceId::from_bytes(fixed(&row.device)?),
                    signed: row.signed,
                })
            })
            .collect()
    }
}
