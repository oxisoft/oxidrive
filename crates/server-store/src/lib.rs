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
    NewChunk, NewCollection, NewLease, PairingRow, PreparedAppend, PreparedRecord, RecordRef,
    SessionRow, StoredAttestation, StoredCertificate, StoredCommit, StoredDeviceList,
    StoredEnvelope, StoredSlot,
};

use oxisoft_drive_proto::api::Head;
use oxisoft_drive_proto::{AccountId, ChunkId, CollectionId, DeviceId, LeaseId, PairingId, Seq};

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

    /// Every account, deleted ones included, in ID order.
    fn accounts(&self) -> impl Future<Output = Result<Vec<AccountRow>, StoreError>> + Send;

    /// Enables or disables an account; disabling ends its sessions in the same transaction.
    /// [`StoreError::NotFound`] if it doesn't exist, [`StoreError::Conflict`] if it is
    /// deleted or `status` is [`AccountStatus::Deleted`].
    fn set_account_status(
        &self,
        id: AccountId,
        status: AccountStatus,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Sets an account's quota. [`StoreError::NotFound`] if it doesn't exist.
    fn set_quota(
        &self,
        id: AccountId,
        quota_bytes: u64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Deletes a disabled account at `now_ms`: it is marked deleted and every collection of
    /// it goes to the trash with no retention, so garbage collection frees its data. The row
    /// stays, so the ID can't come back. [`StoreError::NotFound`] if it doesn't exist,
    /// [`StoreError::Conflict`] unless it is disabled.
    fn delete_account(
        &self,
        id: AccountId,
        now_ms: u64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Replaces an account's device list, adds certificates and envelopes (for the new
    /// devices), and ends the sessions of `revoked` devices, if the stored list still has
    /// version `expected` (`None`: no list yet). [`StoreError::Conflict`] otherwise.
    fn put_device_list(
        &self,
        account: AccountId,
        expected: Option<u64>,
        list: &StoredDeviceList,
        certificates: &[StoredCertificate],
        envelopes: &[StoredEnvelope],
        revoked: &[DeviceId],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Every certificate of an account, in device order.
    fn certificates(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Vec<StoredCertificate>, StoreError>> + Send;

    /// The account a device's certificate belongs to.
    fn account_of_device(
        &self,
        device: DeviceId,
    ) -> impl Future<Output = Result<Option<AccountId>, StoreError>> + Send;

    // ── invites, sign-in ──────────────────────────────────────────────────────────

    /// Records a one-time invite by the hash of its code, with the admin's label for the
    /// account it creates.
    fn create_invite(
        &self,
        hash: [u8; 32],
        expires_ms: u64,
        label: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Uses up an invite and creates the account (with the invite's label) and its first
    /// device list, certificate and envelopes, in one transaction. [`StoreError::NotFound`] if the invite is unknown,
    /// used or expired at `now_ms`; [`StoreError::Duplicate`] if the account exists.
    fn create_account_by_invite(
        &self,
        invite: [u8; 32],
        now_ms: u64,
        account: &NewAccount,
        list: &StoredDeviceList,
        certificate: &StoredCertificate,
        envelopes: &[StoredEnvelope],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Stores a device's sign-in challenge, replacing any earlier one.
    fn put_challenge(
        &self,
        device: DeviceId,
        nonce: [u8; 32],
        expires_ms: u64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Takes (and so uses up) a device's challenge: the nonce and its expiry.
    fn take_challenge(
        &self,
        device: DeviceId,
    ) -> impl Future<Output = Result<Option<([u8; 32], u64)>, StoreError>> + Send;

    /// Records a session by the hash of its token.
    fn create_session(
        &self,
        hash: [u8; 32],
        session: &SessionRow,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The session with this token hash.
    fn session(
        &self,
        hash: [u8; 32],
    ) -> impl Future<Output = Result<Option<SessionRow>, StoreError>> + Send;

    /// Deletes sessions and challenges that expired before `now_ms`; returns how many.
    fn drop_expired_sessions(
        &self,
        now_ms: u64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    // ── keys ──────────────────────────────────────────────────────────────────────

    /// Every envelope of an account.
    fn envelopes(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Vec<StoredEnvelope>, StoreError>> + Send;

    /// Adds a new key epoch's envelopes if the account's newest epoch is `epoch - 1`
    /// ([`StoreError::Conflict`] otherwise).
    fn add_epoch(
        &self,
        account: AccountId,
        epoch: u32,
        envelopes: &[StoredEnvelope],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    // ── collections ───────────────────────────────────────────────────────────────

    /// An account's collections that aren't in the trash.
    fn collections(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Vec<CollectionRow>, StoreError>> + Send;

    /// Changes a collection's retention and/or configuration.
    fn update_collection(
        &self,
        id: CollectionId,
        retention_days: Option<u32>,
        config: Option<&[u8]>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Moves a collection to the trash at `now_ms`.
    fn delete_collection(
        &self,
        id: CollectionId,
        now_ms: u64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Stored bytes of a collection.
    fn collection_usage(
        &self,
        id: CollectionId,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Collections in the trash longer than their retention and not yet emptied.
    fn purgeable_collections(
        &self,
        now_ms: u64,
    ) -> impl Future<Output = Result<Vec<CollectionId>, StoreError>> + Send;

    /// Empties a trashed collection: its commits, records, leases, envelopes and
    /// attestations go; its chunks become garbage. The collection row stays, marked.
    fn purge_collection(
        &self,
        id: CollectionId,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    // ── pairings and attestations ─────────────────────────────────────────────────

    /// Records a pending pairing.
    fn create_pairing(
        &self,
        pairing: &PairingRow,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// A pairing.
    fn pairing(
        &self,
        id: PairingId,
    ) -> impl Future<Output = Result<Option<PairingRow>, StoreError>> + Send;

    /// Stores the approval of a pairing that is pending and unexpired at `now_ms`; `false`
    /// otherwise.
    fn approve_pairing(
        &self,
        id: PairingId,
        approval: &[u8],
        now_ms: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Deletes pairings that expired before `now_ms`; returns how many.
    fn drop_expired_pairings(
        &self,
        now_ms: u64,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Replaces a device's attestation for a collection.
    fn put_attestation(
        &self,
        collection: CollectionId,
        attestation: &StoredAttestation,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Every device's latest attestation for a collection, in device order.
    fn attestations(
        &self,
        collection: CollectionId,
    ) -> impl Future<Output = Result<Vec<StoredAttestation>, StoreError>> + Send;

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
    /// stored: the commit, its records, their chunk references, "superseded" on each node's
    /// previous record, and the referenced chunks' garbage marks cleared, in one transaction. Of two racing appends with the same
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

    /// Records an upload lease. Its chunks lose their garbage mark in the same transaction.
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

    /// Marks garbage (server binary §5): stamps `now_ms` on every chunk without a mark that
    /// no unpruned record references and no lease unexpired at `now_ms` covers, then clears
    /// the mark of every marked chunk that is referenced or leased after all (one that an
    /// append running meanwhile took). Returns how many were newly marked.
    fn mark_garbage(&self, now_ms: u64) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Up to `limit` chunks marked at or before `marked_before_ms`, referenced by no unpruned
    /// record and covered by no lease that is unexpired at `now_ms`.
    fn garbage(
        &self,
        now_ms: u64,
        marked_before_ms: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<ChunkRow>, StoreError>> + Send;

    /// Forgets chunks (their blobs go afterwards) and takes their sizes off the accounts'
    /// usage. Chunks referenced or leased meanwhile, or no longer marked at or before
    /// `marked_before_ms`, are kept, including against an append running at the same time;
    /// returns those forgotten.
    fn forget_chunks(
        &self,
        chunks: &[ChunkRow],
        now_ms: u64,
        marked_before_ms: u64,
    ) -> impl Future<Output = Result<Vec<ChunkRow>, StoreError>> + Send;

    /// Every stored chunk, in (collection, chunk) order, `limit` at a time after `after`.
    fn all_chunks(
        &self,
        after: Option<(CollectionId, ChunkId)>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<ChunkRow>, StoreError>> + Send;

    // ── maintenance ───────────────────────────────────────────────────────────────

    /// Records that the process called `name` is alive at `now_ms`.
    fn beat(&self, name: &str, now_ms: u64) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// When `name` last recorded it was alive, if it did and hasn't stopped.
    fn last_beat(&self, name: &str)
    -> impl Future<Output = Result<Option<u64>, StoreError>> + Send;

    /// Forgets `name`'s heartbeat, when it stops.
    fn stop_beat(&self, name: &str) -> impl Future<Output = Result<(), StoreError>> + Send;
}
