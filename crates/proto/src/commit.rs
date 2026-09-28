//! Commits and the hash chain (sync protocol §1–§2, crypto design §8).
//!
//! A commit is a signed header plus the records it covers. The header lists a hash per record,
//! so a record can be pruned on its own (replaced by its hash) and the signature still
//! verifies (sync protocol §7). The server prunes only records that are superseded and past
//! retention, never the current record of a node. Each header points at the previous
//! commit's hash.

use minicbor::{Decode, Encode};
use oxisoft_drive_crypto::hash;
use oxisoft_drive_crypto::sign::{SignContext, SigningKey, VerifyingKey};

use crate::cbor;
use crate::signed::{Signable, Signed};
use crate::{
    ChainError, CollectionId, CommitHash, DeviceId, NodeRecord, ProtoError, RecordHash, Seq,
};

/// Commit format version written by this code.
pub const COMMIT_FORMAT: u8 = 1;

/// The signed part of a commit.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct CommitHeader {
    /// Format version; [`COMMIT_FORMAT`].
    #[n(0)]
    pub format: u8,
    /// The collection this commit belongs to.
    #[n(1)]
    pub collection: CollectionId,
    /// Position in the collection's log, starting at 1.
    #[n(2)]
    pub seq: Seq,
    /// Hash of the previous commit; `None` only for the first.
    #[n(3)]
    pub prev: Option<CommitHash>,
    /// The writing device.
    #[n(4)]
    pub device: DeviceId,
    /// Key epoch the records are encrypted under.
    #[n(5)]
    pub epoch: u32,
    /// When it was written, milliseconds since the Unix epoch (informational only).
    #[n(6)]
    pub time_ms: u64,
    /// BLAKE3 of each encoded record, in order.
    #[n(7)]
    pub record_hashes: Vec<RecordHash>,
}

impl Signable for CommitHeader {
    const CONTEXT: SignContext = SignContext::Commit;
}

/// What the writer decides; the rest of the header is derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitDraft {
    /// The collection.
    pub collection: CollectionId,
    /// The sequence number this commit will have (current head + 1).
    pub seq: Seq,
    /// The current head's hash; `None` for the first commit.
    pub prev: Option<CommitHash>,
    /// Key epoch of the records.
    pub epoch: u32,
    /// Current time, milliseconds since the Unix epoch.
    pub time_ms: u64,
}

/// One record of a commit: its encoded bytes, or only its hash once pruned.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum RecordSlot {
    /// The encoded record, exactly as hashed.
    #[n(0)]
    Present(#[cbor(n(0), with = "minicbor::bytes")] Vec<u8>),
    /// Pruned; only the hash remains.
    #[n(1)]
    Pruned(#[n(0)] RecordHash),
}

impl RecordSlot {
    fn hash(&self) -> RecordHash {
        match self {
            Self::Present(bytes) => RecordHash(hash::hash(bytes)),
            Self::Pruned(hash) => *hash,
        }
    }
}

/// A commit as stored and transferred.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Commit {
    /// The signed header.
    #[n(0)]
    pub header: Signed<CommitHeader>,
    /// The records, in the order of the header's hashes.
    #[n(1)]
    pub records: Vec<RecordSlot>,
}

impl Commit {
    /// Encodes `records` and signs a header over them with the device's key.
    #[must_use]
    pub fn create(key: &SigningKey, draft: &CommitDraft, records: &[NodeRecord]) -> Self {
        let slots: Vec<RecordSlot> = records
            .iter()
            .map(|record| RecordSlot::Present(cbor::to_vec(record)))
            .collect();
        let header = CommitHeader {
            format: COMMIT_FORMAT,
            collection: draft.collection,
            seq: draft.seq,
            prev: draft.prev,
            device: DeviceId::from_key(&key.verifying_key()),
            epoch: draft.epoch,
            time_ms: draft.time_ms,
            record_hashes: slots.iter().map(RecordSlot::hash).collect(),
        };
        Self {
            header: Signed::sign(key, &header),
            records: slots,
        }
    }

    /// This commit's hash, which the next commit links to.
    #[must_use]
    pub fn hash(&self) -> CommitHash {
        CommitHash(self.header.hash())
    }

    /// Decodes the records still present, in order; pruned ones are skipped. Call only on
    /// commits that passed [`verify_chain`].
    ///
    /// # Errors
    ///
    /// [`ProtoError::Decode`] for a malformed record.
    pub fn records(&self) -> Result<Vec<NodeRecord>, ProtoError> {
        self.records
            .iter()
            .filter_map(|slot| match slot {
                RecordSlot::Present(bytes) => {
                    Some(minicbor::decode(bytes).map_err(ProtoError::from))
                }
                RecordSlot::Pruned(_) => None,
            })
            .collect()
    }

    /// Replaces record `index` with its hash; the commit still verifies. Returns whether a
    /// present record was pruned.
    pub fn prune(&mut self, index: usize) -> bool {
        match self.records.get_mut(index) {
            Some(slot @ RecordSlot::Present(_)) => {
                *slot = RecordSlot::Pruned(slot.hash());
                true
            }
            _ => false,
        }
    }
}

/// Verifies a run of commits continuing a known head.
///
/// `previous` is the last verified commit's sequence number and hash (`None` when starting
/// from the beginning). `device_key` returns the verifying key of a trusted device, or `None`
/// for an unknown or revoked one. Returns the verified headers.
///
/// # Errors
///
/// [`ProtoError::Chain`] for an unknown device, a wrong collection, sequence number, link or
/// records hash; [`ProtoError::Crypto`] for a bad signature; [`ProtoError::UnsupportedFormat`]
/// for a header from a newer format.
pub fn verify_chain(
    collection: CollectionId,
    previous: Option<(Seq, CommitHash)>,
    commits: &[Commit],
    device_key: impl Fn(&DeviceId) -> Option<VerifyingKey>,
) -> Result<Vec<CommitHeader>, ProtoError> {
    let first_seq = previous.map_or(1, |(seq, _)| seq + 1);
    let mut expected_prev = previous.map(|(_, hash)| hash);
    let mut headers = Vec::with_capacity(commits.len());
    for (expected_seq, commit) in (first_seq..).zip(commits) {
        let claimed = commit.header.decode_unverified()?;
        let key = device_key(&claimed.device)
            .filter(|key| DeviceId::from_key(key) == claimed.device)
            .ok_or(ProtoError::Chain(ChainError::UnknownDevice))?;
        let header = commit.header.verify(&key)?;
        if header.format != COMMIT_FORMAT {
            return Err(ProtoError::UnsupportedFormat(header.format));
        }
        let fail = |reason| Err(ProtoError::Chain(reason));
        if header.collection != collection {
            return fail(ChainError::Collection);
        }
        if header.seq != expected_seq {
            return fail(ChainError::Sequence);
        }
        if header.prev != expected_prev {
            return fail(ChainError::Link);
        }
        let hashes: Vec<RecordHash> = commit.records.iter().map(RecordSlot::hash).collect();
        if hashes != header.record_hashes {
            return fail(ChainError::RecordsHash);
        }
        expected_prev = Some(commit.hash());
        headers.push(header);
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeId;
    use crate::node::tests::{context, file_payload};
    use crate::test_util::rng;
    use oxisoft_drive_crypto::keys::CollectionKey;

    struct Fixture {
        device: SigningKey,
        collection: CollectionId,
        commits: Vec<Commit>,
    }

    fn chain(len: u64) -> Fixture {
        let device = SigningKey::generate(&mut rng(1));
        let meta = CollectionKey::generate(&mut rng(2), 1).meta();
        let collection = context().collection;
        let mut commits: Vec<Commit> = Vec::new();
        for seq in 1..=len {
            let record = NodeRecord::seal(
                NodeId::from_bytes([u8::try_from(seq).unwrap(); 16]),
                &file_payload("f", &[b"c"]),
                &meta,
                &mut rng(3),
                &context(),
            )
            .unwrap();
            let draft = CommitDraft {
                collection,
                seq,
                prev: commits.last().map(Commit::hash),
                epoch: 1,
                time_ms: 1000 * seq,
            };
            commits.push(Commit::create(&device, &draft, &[record]));
        }
        Fixture {
            device,
            collection,
            commits,
        }
    }

    fn keys(fixture: &Fixture) -> impl Fn(&DeviceId) -> Option<VerifyingKey> + '_ {
        |id| {
            let key = fixture.device.verifying_key();
            (DeviceId::from_key(&key) == *id).then_some(key)
        }
    }

    #[test]
    fn a_chain_verifies_whole_in_parts_and_pruned() {
        let fixture = chain(4);
        let headers =
            verify_chain(fixture.collection, None, &fixture.commits, keys(&fixture)).unwrap();
        assert_eq!(
            headers.iter().map(|h| h.seq).collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        let head = (2, fixture.commits[1].hash());
        assert!(
            verify_chain(
                fixture.collection,
                Some(head),
                &fixture.commits[2..],
                keys(&fixture)
            )
            .is_ok()
        );

        let mut pruned = fixture.commits.clone();
        assert!(pruned[1].prune(0));
        assert!(!pruned[1].prune(0), "already pruned");
        assert!(!pruned[1].prune(5), "no such record");
        assert!(pruned[1].records().unwrap().is_empty());
        assert!(verify_chain(fixture.collection, None, &pruned, keys(&fixture)).is_ok());
        assert_eq!(pruned[0].records().unwrap().len(), 1);

        let bytes = minicbor::to_vec(&fixture.commits[0]).unwrap();
        assert_eq!(
            minicbor::decode::<Commit>(&bytes).unwrap(),
            fixture.commits[0]
        );
    }

    #[test]
    fn records_are_pruned_one_by_one() {
        let device = SigningKey::generate(&mut rng(1));
        let meta = CollectionKey::generate(&mut rng(2), 1).meta();
        let records: Vec<NodeRecord> = (1..=3)
            .map(|n| {
                NodeRecord::seal(
                    NodeId::from_bytes([n; 16]),
                    &file_payload("f", &[b"c"]),
                    &meta,
                    &mut rng(3),
                    &context(),
                )
                .unwrap()
            })
            .collect();
        let draft = CommitDraft {
            collection: context().collection,
            seq: 1,
            prev: None,
            epoch: 1,
            time_ms: 0,
        };
        let mut commit = Commit::create(&device, &draft, &records);
        let key = device.verifying_key();
        let trusted = |id: &DeviceId| (DeviceId::from_key(&key) == *id).then_some(key);
        assert!(commit.prune(1));
        let kept: Vec<NodeId> = commit.records().unwrap().iter().map(|r| r.node).collect();
        assert_eq!(
            kept,
            [NodeId::from_bytes([1; 16]), NodeId::from_bytes([3; 16])]
        );
        assert!(verify_chain(draft.collection, None, &[commit.clone()], trusted).is_ok());
        // A present record that doesn't match its signed hash is rejected.
        commit.records[0] = RecordSlot::Present(cbor::to_vec(&records[2]));
        assert_eq!(
            verify_chain(draft.collection, None, &[commit.clone()], trusted),
            Err(ProtoError::Chain(ChainError::RecordsHash))
        );
        // So is a commit that lost a record entirely.
        commit.records.truncate(1);
        assert_eq!(
            verify_chain(draft.collection, None, &[commit], trusted),
            Err(ProtoError::Chain(ChainError::RecordsHash))
        );
    }

    #[test]
    fn every_break_is_detected() {
        let fixture = chain(3);
        let verify = |commits: &[Commit], previous| {
            verify_chain(fixture.collection, previous, commits, keys(&fixture)).unwrap_err()
        };
        let chain_error = ProtoError::Chain;

        // Missing first commit: sequence starts at 2.
        assert_eq!(
            verify(&fixture.commits[1..], None),
            chain_error(ChainError::Sequence)
        );
        // Continuing from a wrong head.
        let wrong_head = Some((1, fixture.commits[1].hash()));
        assert_eq!(
            verify(&fixture.commits[1..], wrong_head),
            chain_error(ChainError::Link)
        );
        // Records swapped between commits.
        let mut swapped = fixture.commits.clone();
        swapped[1].records.clone_from(&fixture.commits[2].records);
        assert_eq!(verify(&swapped, None), chain_error(ChainError::RecordsHash));
        // Another collection.
        assert_eq!(
            verify_chain(
                CollectionId::from_bytes([0; 16]),
                None,
                &fixture.commits,
                keys(&fixture)
            )
            .unwrap_err(),
            chain_error(ChainError::Collection)
        );
        // An unknown device, or a key that doesn't belong to the claimed ID.
        assert_eq!(
            verify_chain(fixture.collection, None, &fixture.commits, |_| None).unwrap_err(),
            chain_error(ChainError::UnknownDevice)
        );
        let stranger = SigningKey::generate(&mut rng(9)).verifying_key();
        assert_eq!(
            verify_chain(fixture.collection, None, &fixture.commits, |_| Some(
                stranger
            ))
            .unwrap_err(),
            chain_error(ChainError::UnknownDevice)
        );
    }

    #[test]
    fn forged_and_future_headers_are_rejected() {
        let fixture = chain(1);
        let draft = CommitDraft {
            collection: fixture.collection,
            seq: 1,
            prev: None,
            epoch: 1,
            time_ms: 0,
        };
        // Signed by someone else while claiming the fixture device's ID.
        let impostor = SigningKey::generate(&mut rng(8));
        let mut forged = Commit::create(&impostor, &draft, &[]);
        let mut header = forged.header.decode_unverified().unwrap();
        header.device = DeviceId::from_key(&fixture.device.verifying_key());
        forged.header = Signed::sign(&impostor, &header);
        assert!(matches!(
            verify_chain(fixture.collection, None, &[forged], keys(&fixture)),
            Err(ProtoError::Crypto(_))
        ));

        let mut future = Commit::create(&fixture.device, &draft, &[]);
        let mut header = future.header.decode_unverified().unwrap();
        header.format = 2;
        future.header = Signed::sign(&fixture.device, &header);
        assert_eq!(
            verify_chain(fixture.collection, None, &[future], keys(&fixture)),
            Err(ProtoError::UnsupportedFormat(2))
        );

        let broken = Commit {
            records: vec![RecordSlot::Present(vec![0xff])],
            ..Commit::create(&fixture.device, &draft, &[])
        };
        assert!(matches!(broken.records(), Err(ProtoError::Decode(_))));
    }
}
