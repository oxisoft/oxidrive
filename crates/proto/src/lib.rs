//! oxidrive wire and storage formats: identifiers, names, node records, signed commits and
//! their hash chain, device certificates and lists, head attestations, key envelopes, the
//! pairing code, and every server API message.
//!
//! Everything is CBOR. Top-level formats are maps with integer keys, so optional fields can
//! be added later without breaking older readers (requirement N4). Signed objects keep the
//! exact bytes that were signed ([`Signed`]); they are decoded only after the signature
//! checks out.
//!
//! The crate performs no I/O and never reads a clock: timestamps are passed in.

pub mod api;
mod cbor;
mod commit;
mod device;
mod envelope;
mod error;
mod ids;
mod name;
mod node;
mod pairing;
mod signed;

pub use commit::{COMMIT_FORMAT, Commit, CommitDraft, CommitHeader, RecordSlot, verify_chain};
pub use device::{
    DEVICE_FORMAT, DeviceCertificate, DeviceEntry, DeviceList, HeadAttestation, KemKeyPublication,
};
pub use envelope::{Envelope, EnvelopeKind};
pub use error::{ChainError, NameError, ProtoError};
pub use ids::{
    AccountId, CertificateHash, ChunkId, CollectionId, CommitHash, ContentHash, DeviceId, ID_LEN,
    KeysHash, LeaseId, NodeId, PairingId, RecordHash, Seq, Version,
};
pub use name::{MAX_NAME_LEN, Name};
pub use node::{ChunkRef, FileInfo, NODE_FORMAT, NodeKind, NodePayload, NodeRecord, RecordContext};
pub use pairing::{PAIRING_FORMAT, PairingCode, approval_mac_data, auth_message, keys_hash};
pub use signed::{Signable, Signed};

#[cfg(test)]
mod test_util {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    pub(crate) fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }
}
