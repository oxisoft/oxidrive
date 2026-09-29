//! The server's rules (server storage §4), above the metadata and blob stores: who may
//! commit, what a commit must satisfy, leases, quotas, pruning, garbage collection and fsck.
//! The HTTP layer (6b) only decodes, authenticates, calls these and encodes.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use oxisoft_drive_chunking::object_epoch;
use oxisoft_drive_crypto::CryptoRng;
use oxisoft_drive_crypto::sign::VerifyingKey;
use oxisoft_drive_proto::api::{Commits, Head, Limits, Missing};
use oxisoft_drive_proto::{
    AccountId, CertificateHash, ChunkId, CollectionId, Commit, DeviceCertificate, DeviceList,
    LeaseId, RecordSlot, Seq, Signed, verify_chain,
};
use oxisoft_drive_server_store::{
    AccountRow, AccountStatus, AppendOutcome, CollectionRow, MetaStore, NewAccount, NewChunk,
    NewCollection, NewLease, PreparedAppend, PreparedRecord, StoreError, StoredCertificate,
    StoredDeviceList, StoredSlot,
};

use crate::blob::{BlobError, BlobKey, BlobStore};

/// Milliseconds since the Unix epoch, as the service sees them.
pub trait Clock: Send + Sync {
    /// Now.
    fn now_ms(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// Limits and defaults of one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// The limits advertised in `/v1/info`.
    pub limits: Limits,
    /// How long an upload lease protects chunks.
    pub lease_ms: u64,
    /// Rows handled per batch in maintenance.
    pub batch: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            limits: Limits {
                // The chunk format's largest object: 16 MiB plus headers and tag.
                max_object: 16 * 1024 * 1024 + 1024,
                // Engines write at most 1 MiB of records per commit (core X2).
                max_commit: 4 * 1024 * 1024,
                max_batch: 10_000,
            },
            lease_ms: 24 * 3_600_000,
            batch: 500,
        }
    }
}

/// Why the service refused or failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    /// No such account, collection or chunk (or not the caller's).
    #[error("not found")]
    NotFound,
    /// The account is disabled.
    #[error("account disabled")]
    Disabled,
    /// The writing device isn't trusted by the account.
    #[error("device not trusted")]
    Untrusted,
    /// Malformed, badly signed or inconsistent input.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The expected head or version is stale; the current head, if any.
    #[error("conflict")]
    Conflict(Option<Head>),
    /// A commit references chunks the collection doesn't store.
    #[error("{} chunks missing", .0.len())]
    MissingChunks(Vec<ChunkId>),
    /// The lease is unknown, expired, for another collection, or doesn't cover the chunk.
    #[error("no valid lease")]
    BadLease,
    /// Over a size or batch limit.
    #[error("too large")]
    TooLarge,
    /// The account's quota is used up.
    #[error("quota exceeded")]
    QuotaExceeded,
    /// The metadata store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The blob store failed.
    #[error(transparent)]
    Blob(#[from] BlobError),
}

fn invalid(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Invalid(error.to_string())
}

fn encode<T: minicbor::Encode<()>>(value: &T) -> Result<Vec<u8>, ServiceError> {
    minicbor::to_vec(value).map_err(invalid)
}

fn decode<T: for<'b> minicbor::Decode<'b, ()>>(bytes: &[u8]) -> Result<T, ServiceError> {
    minicbor::decode(bytes)
        .map_err(|error| ServiceError::Store(StoreError::Corrupt(error.to_string())))
}

/// What a garbage collection did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Expired leases dropped.
    pub leases: u64,
    /// Chunks deleted.
    pub chunks: u64,
    /// Bytes freed.
    pub bytes: u64,
}

/// What fsck found. Empty everywhere means consistent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsckReport {
    /// Chunks the database lists without their object.
    pub missing_objects: Vec<BlobKey>,
    /// Objects the database doesn't list (left by a crash; safe to delete with the server
    /// stopped).
    pub orphan_objects: Vec<BlobKey>,
    /// Objects whose size differs from the database's.
    pub wrong_sizes: Vec<BlobKey>,
}

impl FsckReport {
    /// Whether nothing is wrong.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.missing_objects.is_empty()
            && self.orphan_objects.is_empty()
            && self.wrong_sizes.is_empty()
    }
}

/// The server's rules over a metadata store `M` and a blob store `B`.
#[derive(Debug)]
pub struct Service<M, B, C, R> {
    meta: M,
    blobs: B,
    clock: C,
    rng: Mutex<R>,
    settings: Settings,
}

impl<M, B, C, R> Service<M, B, C, R>
where
    M: MetaStore,
    B: BlobStore,
    C: Clock,
    R: CryptoRng + Send,
{
    /// A service over these stores.
    pub fn new(meta: M, blobs: B, clock: C, rng: R, settings: Settings) -> Self {
        Self {
            meta,
            blobs,
            clock,
            rng: Mutex::new(rng),
            settings,
        }
    }

    /// The limits clients must respect.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The metadata store (for administration).
    #[must_use]
    pub const fn meta(&self) -> &M {
        &self.meta
    }

    // ── accounts and devices ────────────────────────────────────────────────────────

    /// Creates an account with its signing key's public half.
    ///
    /// # Errors
    ///
    /// [`StoreError::Duplicate`] if it exists.
    pub async fn create_account(
        &self,
        id: AccountId,
        signing_key: &VerifyingKey,
        quota_bytes: u64,
    ) -> Result<(), ServiceError> {
        self.meta
            .create_account(&NewAccount {
                id,
                signing_key: signing_key.to_bytes().to_vec(),
                quota_bytes,
                created_ms: self.clock.now_ms(),
            })
            .await?;
        Ok(())
    }

    async fn active_account(&self, id: AccountId) -> Result<AccountRow, ServiceError> {
        let account = self.meta.account(id).await?.ok_or(ServiceError::NotFound)?;
        if account.status == AccountStatus::Disabled {
            return Err(ServiceError::Disabled);
        }
        Ok(account)
    }

    fn account_key(account: &AccountRow) -> Result<VerifyingKey, ServiceError> {
        let bytes = account
            .signing_key
            .as_slice()
            .try_into()
            .map_err(|_| ServiceError::Store(StoreError::Corrupt("account key".into())))?;
        VerifyingKey::from_bytes(bytes)
            .map_err(|error| ServiceError::Store(StoreError::Corrupt(error.to_string())))
    }

    /// Replaces the account's device list (adding or revoking devices), if the stored list
    /// still has version `expected`. The list and every new certificate must be signed by
    /// the account key, and every trusted device must have a certificate matching its entry.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Invalid`] for bad signatures, a rollback, a revoked device trusted
    /// again or a missing certificate; [`ServiceError::Conflict`] if the version moved on.
    pub async fn put_device_list(
        &self,
        account: AccountId,
        expected: Option<u64>,
        list: &Signed<DeviceList>,
        certificates: &[Signed<DeviceCertificate>],
    ) -> Result<(), ServiceError> {
        let row = self.active_account(account).await?;
        let key = Self::account_key(&row)?;
        let new = list.verify(&key).map_err(invalid)?;
        if new.account != account {
            return Err(invalid("device list of another account"));
        }
        let stored = self.meta.device_list(account).await?;
        if stored.as_ref().map(|stored| stored.version) != expected {
            return Err(ServiceError::Conflict(None));
        }
        let previous = match &stored {
            Some(stored) => Some(
                decode::<Signed<DeviceList>>(&stored.signed)?
                    .verify(&key)
                    .map_err(invalid)?,
            ),
            None => None,
        };
        new.check_update(previous.as_ref()).map_err(invalid)?;
        let mut added = Vec::new();
        for signed in certificates {
            let certificate = DeviceCertificate::verify(signed, account, &key).map_err(invalid)?;
            added.push((certificate.device, CertificateHash(signed.hash()), signed));
        }
        for entry in &new.devices {
            let hash = if let Some((_, hash, _)) =
                added.iter().find(|(device, ..)| *device == entry.device)
            {
                *hash
            } else {
                let stored = self
                    .meta
                    .certificate(account, entry.device)
                    .await?
                    .ok_or_else(|| invalid("a trusted device has no certificate"))?;
                CertificateHash(decode::<Signed<DeviceCertificate>>(&stored.signed)?.hash())
            };
            if hash != entry.certificate {
                return Err(invalid("certificate doesn't match the list"));
            }
        }
        let certificates = added
            .iter()
            .map(|(device, _, signed)| {
                Ok(StoredCertificate {
                    device: *device,
                    signed: encode(*signed)?,
                })
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;
        let list = StoredDeviceList {
            version: new.version,
            signed: encode(list)?,
        };
        match self
            .meta
            .put_device_list(account, expected, &list, &certificates)
            .await
        {
            Err(StoreError::Conflict) => Err(ServiceError::Conflict(None)),
            other => Ok(other?),
        }
    }

    // ── collections and commits ─────────────────────────────────────────────────────

    /// Creates a collection in the account.
    ///
    /// # Errors
    ///
    /// [`StoreError::Duplicate`] if the ID is taken.
    pub async fn create_collection(
        &self,
        account: AccountId,
        id: CollectionId,
        config: Vec<u8>,
        retention_days: u32,
    ) -> Result<(), ServiceError> {
        self.active_account(account).await?;
        self.meta
            .create_collection(&NewCollection {
                id,
                account,
                config,
                retention_days,
                created_ms: self.clock.now_ms(),
            })
            .await?;
        Ok(())
    }

    /// The caller's collection, and its account (active).
    async fn owned(
        &self,
        account: AccountId,
        collection: CollectionId,
    ) -> Result<(AccountRow, CollectionRow), ServiceError> {
        let row = self.active_account(account).await?;
        let collection = self
            .meta
            .collection(collection)
            .await?
            .filter(|found| found.account == account)
            .ok_or(ServiceError::NotFound)?;
        Ok((row, collection))
    }

    /// A collection's head.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`] for another account's collection.
    pub async fn head(
        &self,
        account: AccountId,
        collection: CollectionId,
    ) -> Result<Option<Head>, ServiceError> {
        self.owned(account, collection).await?;
        Ok(self.meta.head(collection).await?)
    }

    /// Up to `limit` commits after `after`, oldest first.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`] for another account's collection.
    pub async fn commits_after(
        &self,
        account: AccountId,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> Result<Commits, ServiceError> {
        self.owned(account, collection).await?;
        let limit = limit.clamp(1, self.settings.limits.max_batch);
        let mut stored = self
            .meta
            .commits_after(collection, after, limit.saturating_add(1))
            .await?;
        let more = stored.len() > limit as usize;
        stored.truncate(limit as usize);
        let commits = stored
            .into_iter()
            .map(|commit| {
                Ok(Commit {
                    header: decode(&commit.header)?,
                    records: commit
                        .records
                        .into_iter()
                        .map(|slot| match slot {
                            StoredSlot::Present(body) => RecordSlot::Present(body),
                            StoredSlot::Pruned(hash) => RecordSlot::Pruned(hash),
                        })
                        .collect(),
                })
            })
            .collect::<Result<_, ServiceError>>()?;
        Ok(Commits { commits, more })
    }

    /// Appends a commit (sync §2, server API §5): signed by a device the account trusts,
    /// following `expected`, every record present and hashed as signed, every referenced
    /// chunk stored, within the size limits.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Conflict`] with the current head if `expected` is stale;
    /// [`ServiceError::Untrusted`], [`ServiceError::Invalid`], [`ServiceError::TooLarge`] or
    /// [`ServiceError::MissingChunks`] otherwise.
    pub async fn append(
        &self,
        account: AccountId,
        collection: CollectionId,
        expected: Option<Head>,
        commit: &Commit,
    ) -> Result<Head, ServiceError> {
        let (row, _) = self.owned(account, collection).await?;
        let size = commit.header.bytes().len()
            + commit
                .records
                .iter()
                .map(|slot| match slot {
                    RecordSlot::Present(body) => body.len(),
                    RecordSlot::Pruned(_) => 0,
                })
                .sum::<usize>();
        if size > self.settings.limits.max_commit as usize {
            return Err(ServiceError::TooLarge);
        }
        let key = Self::account_key(&row)?;
        let list = match self.meta.device_list(account).await? {
            Some(stored) => decode::<Signed<DeviceList>>(&stored.signed)?
                .verify(&key)
                .map_err(invalid)?,
            None => return Err(ServiceError::Untrusted),
        };
        let claimed = commit.header.decode_unverified().map_err(invalid)?;
        if !list.is_trusted(&claimed.device) {
            return Err(ServiceError::Untrusted);
        }
        let certificate = self
            .meta
            .certificate(account, claimed.device)
            .await?
            .ok_or(ServiceError::Untrusted)?;
        let certificate = DeviceCertificate::verify(&decode(&certificate.signed)?, account, &key)
            .map_err(invalid)?;
        let current = self.meta.head(collection).await?;
        if current != expected {
            return Err(ServiceError::Conflict(current));
        }
        let previous = expected.map(|head| (head.seq, head.hash));
        let headers = verify_chain(
            collection,
            previous,
            std::slice::from_ref(commit),
            |device| (*device == certificate.device).then_some(certificate.verifying_key),
        )
        .map_err(invalid)?;
        let header = headers.first().ok_or_else(|| invalid("no header"))?;
        if commit
            .records
            .iter()
            .any(|slot| matches!(slot, RecordSlot::Pruned(_)))
        {
            return Err(invalid("a new commit carries pruned records"));
        }
        let records = commit.records().map_err(invalid)?;
        let prepared: Vec<PreparedRecord> = commit
            .records
            .iter()
            .zip(&records)
            .zip(&header.record_hashes)
            .map(|((slot, record), hash)| PreparedRecord {
                node: record.node,
                hash: *hash,
                body: match slot {
                    RecordSlot::Present(body) => body.clone(),
                    RecordSlot::Pruned(_) => Vec::new(),
                },
                chunks: record.chunks.clone(),
            })
            .collect();
        let head = Head {
            seq: header.seq,
            hash: commit.hash(),
        };
        let outcome = self
            .meta
            .append(&PreparedAppend {
                collection,
                expected,
                head,
                header: encode(&commit.header)?,
                device: claimed.device,
                received_ms: self.clock.now_ms(),
                records: prepared,
            })
            .await?;
        match outcome {
            AppendOutcome::Appended(head) => Ok(head),
            AppendOutcome::Conflict(current) => Err(ServiceError::Conflict(current)),
            AppendOutcome::MissingChunks(missing) => Err(ServiceError::MissingChunks(missing)),
        }
    }

    // ── chunks ──────────────────────────────────────────────────────────────────────

    /// Which of `ids` the collection lacks, and a lease protecting all of them from garbage
    /// collection until the commit lands.
    ///
    /// # Errors
    ///
    /// [`ServiceError::TooLarge`] past the batch limit; [`ServiceError::QuotaExceeded`] if
    /// the account is full.
    pub async fn missing(
        &self,
        account: AccountId,
        collection: CollectionId,
        ids: &[ChunkId],
    ) -> Result<Missing, ServiceError> {
        let (row, _) = self.owned(account, collection).await?;
        if ids.len() > self.settings.limits.max_batch as usize {
            return Err(ServiceError::TooLarge);
        }
        let mut unique: Vec<ChunkId> = Vec::with_capacity(ids.len());
        for id in ids {
            if !unique.contains(id) {
                unique.push(*id);
            }
        }
        let missing = self.meta.missing(collection, &unique).await?;
        if !missing.is_empty() && row.used_bytes >= row.quota_bytes {
            return Err(ServiceError::QuotaExceeded);
        }
        let lease = LeaseId::random(&mut *self.rng.lock().unwrap_or_else(PoisonError::into_inner));
        let expires_ms = self.clock.now_ms().saturating_add(self.settings.lease_ms);
        self.meta
            .create_lease(&NewLease {
                id: lease,
                collection,
                expires_ms,
                chunks: unique,
            })
            .await?;
        Ok(Missing {
            ids: missing,
            lease,
            lease_expires_ms: expires_ms,
        })
    }

    /// Stores a chunk object under a lease. Storing a known chunk again is a no-op.
    ///
    /// # Errors
    ///
    /// [`ServiceError::BadLease`], [`ServiceError::TooLarge`], [`ServiceError::Invalid`] for
    /// something that isn't a chunk object, [`ServiceError::QuotaExceeded`].
    pub async fn put_chunk(
        &self,
        account: AccountId,
        collection: CollectionId,
        lease: LeaseId,
        id: ChunkId,
        object: &[u8],
    ) -> Result<(), ServiceError> {
        let (row, _) = self.owned(account, collection).await?;
        let now = self.clock.now_ms();
        let valid = self.meta.lease(lease).await?.is_some_and(|lease| {
            lease.collection == collection && now < lease.expires_ms && lease.chunks.contains(&id)
        });
        if !valid {
            return Err(ServiceError::BadLease);
        }
        if object.len() > self.settings.limits.max_object as usize {
            return Err(ServiceError::TooLarge);
        }
        object_epoch(object).map_err(invalid)?;
        if self.meta.chunk(collection, id).await?.is_some() {
            return Ok(());
        }
        let size = object.len() as u64;
        if row.used_bytes.saturating_add(size) > row.quota_bytes {
            return Err(ServiceError::QuotaExceeded);
        }
        // The object first: a row always has its object.
        self.blobs
            .put(&BlobKey::new(account, collection, id), object)
            .await?;
        self.meta
            .add_chunk(&NewChunk {
                collection,
                chunk: id,
                size,
                stored_ms: now,
            })
            .await?;
        Ok(())
    }

    /// Reads a chunk object.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`] if the collection doesn't store it.
    pub async fn get_chunk(
        &self,
        account: AccountId,
        collection: CollectionId,
        id: ChunkId,
    ) -> Result<Vec<u8>, ServiceError> {
        self.owned(account, collection).await?;
        self.meta
            .chunk(collection, id)
            .await?
            .ok_or(ServiceError::NotFound)?;
        Ok(self
            .blobs
            .get(&BlobKey::new(account, collection, id))
            .await?)
    }

    // ── maintenance ─────────────────────────────────────────────────────────────────

    /// Prunes every record past its collection's retention (sync §7). Returns how many.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn prune(&self) -> Result<u64, ServiceError> {
        let now = self.clock.now_ms();
        let mut pruned = 0;
        loop {
            let records = self.meta.prunable(now, self.settings.batch).await?;
            if records.is_empty() {
                return Ok(pruned);
            }
            self.meta.prune(&records).await?;
            pruned += records.len() as u64;
        }
    }

    /// Drops expired leases, then deletes chunks nothing references or leases: the row
    /// first, then the object, so a crash leaves at most an orphan object (fsck reports it).
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn collect_garbage(&self) -> Result<GcReport, ServiceError> {
        let now = self.clock.now_ms();
        let mut report = GcReport {
            leases: self.meta.drop_expired_leases(now).await?,
            ..GcReport::default()
        };
        loop {
            let garbage = self.meta.garbage(now, self.settings.batch).await?;
            if garbage.is_empty() {
                return Ok(report);
            }
            let forgotten = self.meta.forget_chunks(&garbage, now).await?;
            if forgotten.is_empty() {
                return Ok(report);
            }
            for row in &forgotten {
                self.blobs
                    .delete(&BlobKey::new(row.account, row.collection, row.chunk))
                    .await?;
                report.chunks += 1;
                report.bytes += row.size;
            }
        }
    }

    /// Compares the database's chunks with the stored objects.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn fsck(&self) -> Result<FsckReport, ServiceError> {
        let mut rows: BTreeMap<BlobKey, u64> = BTreeMap::new();
        let mut after = None;
        loop {
            let page = self.meta.all_chunks(after, self.settings.batch).await?;
            let Some(last) = page.last() else {
                break;
            };
            after = Some((last.collection, last.chunk));
            for row in page {
                rows.insert(
                    BlobKey::new(row.account, row.collection, row.chunk),
                    row.size,
                );
            }
        }
        let mut report = FsckReport::default();
        let mut after = None;
        loop {
            let page = self.blobs.list(after, self.settings.batch as usize).await?;
            let Some(last) = page.last() else {
                break;
            };
            after = Some(*last);
            for key in page {
                match rows.remove(&key) {
                    None => report.orphan_objects.push(key),
                    Some(size) => {
                        if self.blobs.size(&key).await? != size {
                            report.wrong_sizes.push(key);
                        }
                    }
                }
            }
        }
        report.missing_objects = rows.into_keys().collect();
        Ok(report)
    }
}
