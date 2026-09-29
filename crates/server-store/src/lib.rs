//! oxidrive server: the metadata store interface (server storage §2).
//!
//! [`MetaStore`] is implemented by `oxisoft-drive-server-sqlite` and
//! `oxisoft-drive-server-postgres`. It holds no rules: the server's service layer checks
//! signatures, device lists, chunks and limits, and hands the store only prepared, valid
//! writes. Each write is one transaction. Signed objects are stored as their exact encoded
//! bytes. With feature `conformance`, [`conformance`] holds the tests both backends pass.

#[cfg(feature = "conformance")]
pub mod conformance;
mod types;

use std::future::Future;

pub use types::{
    AccountRow, AccountStatus, AppendOutcome, ChunkRow, CollectionRow, LeaseRow, NewAccount,
    NewChunk, NewCollection, NewLease, PreparedAppend, PreparedRecord, RecordRef,
    StoredCertificate, StoredCommit, StoredDeviceList, StoredSlot,
};

use oxisoft_drive_proto::api::Head;
use oxisoft_drive_proto::{AccountId, ChunkId, CollectionId, DeviceId, LeaseId, Seq};

/// Store failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The expected version moved on (device lists).
    #[error("conflict: the stored version changed")]
    Conflict,
    /// The row exists already.
    #[error("already exists")]
    Duplicate,
    /// The row a write refers to doesn't exist.
    #[error("not found")]
    NotFound,
    /// Stored data that doesn't make sense (a value out of range, say).
    #[error("corrupt data: {0}")]
    Corrupt(String),
    /// The database failed.
    #[error("database: {0}")]
    Backend(String),
}

/// The metadata database (server storage §2).
pub trait MetaStore: Send + Sync {
    /// Creates an account. [`StoreError::Duplicate`] if its ID exists.
    fn create_account(
        &self,
        account: &NewAccount,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// An account.
    fn account(
        &self,
        id: AccountId,
    ) -> impl Future<Output = Result<Option<AccountRow>, StoreError>> + Send;

    /// Replaces an account's device list and adds certificates, if the stored list still has
    /// version `expected` (`None`: no list yet). [`StoreError::Conflict`] otherwise.
    fn put_device_list(
        &self,
        account: AccountId,
        expected: Option<u64>,
        list: &StoredDeviceList,
        certificates: &[StoredCertificate],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// An account's current device list.
    fn device_list(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Option<StoredDeviceList>, StoreError>> + Send;

    /// A device's certificate.
    fn certificate(
        &self,
        account: AccountId,
        device: DeviceId,
    ) -> impl Future<Output = Result<Option<StoredCertificate>, StoreError>> + Send;

    /// Creates a collection. [`StoreError::Duplicate`] if its ID exists,
    /// [`StoreError::NotFound`] if the account doesn't.
    fn create_collection(
        &self,
        collection: &NewCollection,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// A collection.
    fn collection(
        &self,
        id: CollectionId,
    ) -> impl Future<Output = Result<Option<CollectionRow>, StoreError>> + Send;

    /// A collection's head (`None` before its first commit).
    fn head(
        &self,
        id: CollectionId,
    ) -> impl Future<Output = Result<Option<Head>, StoreError>> + Send;

    /// Appends a commit if the head is still `append.expected` and every referenced chunk is
    /// stored: the commit, its records, their chunk references, and "superseded" on each
    /// node's previous record, in one transaction. Of two racing appends with the same
    /// expectation, one wins; a chunk can't be garbage-collected while an append that needs
    /// it runs.
    fn append(
        &self,
        append: &PreparedAppend,
    ) -> impl Future<Output = Result<AppendOutcome, StoreError>> + Send;

    /// Up to `limit` commits after sequence number `after`, oldest first. Pruned records come
    /// back as their hashes.
    fn commits_after(
        &self,
        id: CollectionId,
        after: Seq,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<StoredCommit>, StoreError>> + Send;

    /// Which of `chunks` the collection doesn't store, each once, in the given order.
    fn missing(
        &self,
        id: CollectionId,
        chunks: &[ChunkId],
    ) -> impl Future<Output = Result<Vec<ChunkId>, StoreError>> + Send;

    /// Records an upload lease.
    fn create_lease(&self, lease: &NewLease)
    -> impl Future<Output = Result<(), StoreError>> + Send;

    /// A lease, with the chunks it covers.
    fn lease(
        &self,
        id: LeaseId,
    ) -> impl Future<Output = Result<Option<LeaseRow>, StoreError>> + Send;

    /// Records a stored chunk and adds its size to the account's usage. `false` if the
    /// chunk was known (nothing changes).
    fn add_chunk(&self, chunk: &NewChunk) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// A stored chunk.
    fn chunk(
        &self,
        id: CollectionId,
        chunk: ChunkId,
    ) -> impl Future<Output = Result<Option<ChunkRow>, StoreError>> + Send;

    /// Up to `limit` records that may be pruned at `now_ms`: superseded, and superseded longer
    /// ago than their collection's retention.
    fn prunable(
        &self,
        now_ms: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<RecordRef>, StoreError>> + Send;

    /// Drops the bodies and chunk references of these records; their hashes stay.
    fn prune(&self, records: &[RecordRef]) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Deletes leases that expired before `now_ms`; returns how many.
    fn drop_expired_leases(
        &self,
        now_ms: u64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Up to `limit` chunks referenced by no unpruned record and covered by no lease that is
    /// unexpired at `now_ms`.
    fn garbage(
        &self,
        now_ms: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<ChunkRow>, StoreError>> + Send;

    /// Forgets chunks (their blobs go afterwards) and takes their sizes off the accounts'
    /// usage. Chunks referenced or leased meanwhile are kept, including by an append running
    /// at the same time; returns those forgotten.
    fn forget_chunks(
        &self,
        chunks: &[ChunkRow],
        now_ms: u64,
    ) -> impl Future<Output = Result<Vec<ChunkRow>, StoreError>> + Send;

    /// Every stored chunk, in (collection, chunk) order, `limit` at a time after `after`.
    fn all_chunks(
        &self,
        after: Option<(CollectionId, ChunkId)>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<ChunkRow>, StoreError>> + Send;
}
