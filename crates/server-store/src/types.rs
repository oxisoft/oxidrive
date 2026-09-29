//! Rows written to and read from a [`MetaStore`](crate::MetaStore).

use oxisoft_drive_proto::api::Head;
use oxisoft_drive_proto::{
    AccountId, ChunkId, CollectionId, CommitHash, DeviceId, LeaseId, NodeId, RecordHash, Seq,
};

/// Whether an account may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    /// In use.
    Active,
    /// Disabled by the admin: nothing but reading its status works.
    Disabled,
}

/// A new account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccount {
    /// Its ID.
    pub id: AccountId,
    /// The account signing key (ASK) public key, which signs its device lists and
    /// certificates.
    pub signing_key: Vec<u8>,
    /// Stored bytes allowed.
    pub quota_bytes: u64,
    /// Milliseconds since the Unix epoch.
    pub created_ms: u64,
}

/// A stored account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRow {
    /// Its ID.
    pub id: AccountId,
    /// The account signing key (ASK) public key.
    pub signing_key: Vec<u8>,
    /// Whether it may be used.
    pub status: AccountStatus,
    /// Stored bytes allowed.
    pub quota_bytes: u64,
    /// Stored bytes used: the sizes of its collections' chunks.
    pub used_bytes: u64,
    /// Milliseconds since the Unix epoch.
    pub created_ms: u64,
}

/// An account's device list, as signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDeviceList {
    /// The list's version (inside the signed bytes too).
    pub version: u64,
    /// The encoded `Signed<DeviceList>`.
    pub signed: Vec<u8>,
}

/// A device certificate, as signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCertificate {
    /// The device.
    pub device: DeviceId,
    /// The encoded `Signed<DeviceCertificate>`.
    pub signed: Vec<u8>,
}

/// A new collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCollection {
    /// Its ID, chosen by the client.
    pub id: CollectionId,
    /// The owning account.
    pub account: AccountId,
    /// The encrypted configuration, opaque to the server.
    pub config: Vec<u8>,
    /// Days superseded records are kept.
    pub retention_days: u32,
    /// Milliseconds since the Unix epoch.
    pub created_ms: u64,
}

/// A stored collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRow {
    /// Its ID.
    pub id: CollectionId,
    /// The owning account.
    pub account: AccountId,
    /// The encrypted configuration.
    pub config: Vec<u8>,
    /// Days superseded records are kept.
    pub retention_days: u32,
    /// Milliseconds since the Unix epoch.
    pub created_ms: u64,
}

/// One record of a commit, prepared by the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRecord {
    /// The node it changes.
    pub node: NodeId,
    /// Its hash, as listed in the signed header.
    pub hash: RecordHash,
    /// The encoded record.
    pub body: Vec<u8>,
    /// The chunks it references (visible, D4).
    pub chunks: Vec<ChunkId>,
}

/// A verified commit, ready to append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAppend {
    /// The collection.
    pub collection: CollectionId,
    /// The head the writer saw.
    pub expected: Option<Head>,
    /// The new head: the commit's sequence number and hash.
    pub head: Head,
    /// The encoded `Signed<CommitHeader>`.
    pub header: Vec<u8>,
    /// The writing device.
    pub device: DeviceId,
    /// Milliseconds since the Unix epoch, when the server took it.
    pub received_ms: u64,
    /// Its records, in order.
    pub records: Vec<PreparedRecord>,
}

/// What an append did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendOutcome {
    /// Appended; the new head.
    Appended(Head),
    /// The head moved on (or never existed); the current head.
    Conflict(Option<Head>),
    /// Referenced chunks the collection doesn't store (checked inside the transaction, so
    /// garbage collection can't remove one meanwhile), each once.
    MissingChunks(Vec<ChunkId>),
}

/// A record slot as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredSlot {
    /// The encoded record.
    Present(Vec<u8>),
    /// Pruned; only its hash remains.
    Pruned(RecordHash),
}

/// A commit as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCommit {
    /// Its sequence number.
    pub seq: Seq,
    /// Its hash.
    pub hash: CommitHash,
    /// The encoded `Signed<CommitHeader>`.
    pub header: Vec<u8>,
    /// Its records, in order.
    pub records: Vec<StoredSlot>,
}

/// One record, by position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordRef {
    /// The collection.
    pub collection: CollectionId,
    /// The commit's sequence number.
    pub seq: Seq,
    /// The record's position in the commit.
    pub index: u32,
}

/// A new upload lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLease {
    /// Its ID.
    pub id: LeaseId,
    /// The collection.
    pub collection: CollectionId,
    /// When it expires, milliseconds since the Unix epoch.
    pub expires_ms: u64,
    /// The chunks it protects, each once.
    pub chunks: Vec<ChunkId>,
}

/// A stored lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    /// Its ID.
    pub id: LeaseId,
    /// The collection.
    pub collection: CollectionId,
    /// When it expires, milliseconds since the Unix epoch.
    pub expires_ms: u64,
    /// The chunks it protects, in ID order.
    pub chunks: Vec<ChunkId>,
}

/// A newly stored chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewChunk {
    /// The collection.
    pub collection: CollectionId,
    /// The chunk.
    pub chunk: ChunkId,
    /// The stored object's size.
    pub size: u64,
    /// Milliseconds since the Unix epoch.
    pub stored_ms: u64,
}

/// A stored chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRow {
    /// The collection's account (where the blob lives).
    pub account: AccountId,
    /// The collection.
    pub collection: CollectionId,
    /// The chunk.
    pub chunk: ChunkId,
    /// The stored object's size.
    pub size: u64,
    /// Milliseconds since the Unix epoch.
    pub stored_ms: u64,
}
