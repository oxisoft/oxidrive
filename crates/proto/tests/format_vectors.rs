//! Frozen format vectors (engineering standards §2, requirement N4).
//!
//! Every object below is built from a seeded RNG, so its encoding is deterministic; the
//! BLAKE3 fingerprints are frozen. A failure means a stored or transmitted format changed:
//! that needs a new format version, not an updated constant.

use std::fmt::Write as _;

use oxisoft_drive_crypto::hash;
use oxisoft_drive_crypto::keys::{AccountKey, AccountSigningKey, CollectionKey, DeviceIdentity};
use oxisoft_drive_crypto::pairing::PairingSecret;
use oxisoft_drive_proto::{
    AccountId, ChunkId, ChunkRef, CollectionId, Commit, CommitDraft, ContentHash,
    DeviceCertificate, DeviceId, Envelope, EnvelopeKind, FileInfo, NODE_FORMAT, Name, NodeId,
    NodeKind, NodePayload, NodeRecord, PairingCode, PairingId, ProtoError, RecordContext, Signed,
    Version, auth_message, keys_hash,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn fingerprint(bytes: &[u8]) -> String {
    hash::hash(bytes)
        .as_bytes()
        .iter()
        .fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn cbor<T: minicbor::Encode<()>>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = minicbor::encode(value, &mut out);
    out
}

fn outputs() -> Result<Vec<(&'static str, String)>, ProtoError> {
    let mut rng = ChaCha20Rng::from_seed([0x0e; 32]);
    let account = AccountId::random(&mut rng);
    let account_key = AccountKey::generate(&mut rng, 0);
    let signing = AccountSigningKey::generate(&mut rng);
    let device = DeviceIdentity::generate(&mut rng);
    let collection_key = CollectionKey::generate(&mut rng, 0);
    let collection = CollectionId::random(&mut rng);
    let device_id = DeviceId::from_key(&device.verifying_key());

    let certificate = DeviceCertificate::new(
        account,
        (device.verifying_key(), device.kem_public_key()),
        "laptop",
        &account_key.meta(),
        &mut rng,
        1_790_000_000_000,
    )?;
    let signed_certificate = Signed::sign(signing.signing_key(), &certificate);

    let payload = NodePayload {
        format: NODE_FORMAT,
        parent: None,
        name: Name::new("report.pdf")?,
        kind: NodeKind::File(FileInfo {
            size: 1234,
            mtime_ms: 1_790_000_000_000,
            executable: false,
            content_hash: ContentHash(hash::hash(b"content")),
            chunks: vec![ChunkRef {
                id: ChunkId(hash::hash(b"chunk")),
                len: 1234,
            }],
        }),
        version: Version {
            device: device_id,
            counter: 1,
        },
        base: None,
    };
    let record = NodeRecord::seal(
        NodeId::random(&mut rng),
        &payload,
        &collection_key.meta(),
        &mut rng,
        &RecordContext {
            collection,
            seq: 1,
            epoch: 0,
        },
    )?;
    let commit = Commit::create(
        device.signing_key(),
        &CommitDraft {
            collection,
            seq: 1,
            prev: None,
            epoch: 0,
            time_ms: 1_790_000_000_000,
        },
        std::slice::from_ref(&record),
    );
    let envelope = Envelope {
        kind: EnvelopeKind::CollectionKey,
        epoch: 0,
        device: None,
        collection: Some(collection),
        wrapped: account_key.wrap(&mut rng, b"placeholder", &collection_key)?,
    };
    let secret = PairingSecret::generate(&mut rng);
    let code = PairingCode::new(
        "https://drive.example".into(),
        PairingId::random(&mut rng),
        keys_hash(&device.verifying_key(), &device.kem_public_key()),
        &secret,
    );

    Ok(vec![
        ("device id", fingerprint(device_id.as_bytes())),
        (
            "signed certificate",
            fingerprint(&cbor(&signed_certificate)),
        ),
        ("node record", fingerprint(&cbor(&record))),
        ("commit", fingerprint(&cbor(&commit))),
        ("commit hash", fingerprint(commit.hash().0.as_bytes())),
        ("envelope", fingerprint(&cbor(&envelope))),
        ("envelope aad", fingerprint(&envelope.aad(account))),
        (
            "auth message",
            fingerprint(&auth_message("https://drive.example", &[7; 32], device_id)),
        ),
        ("pairing code", fingerprint(&code.to_bytes())),
    ])
}

const FROZEN: [(&str, &str); 9] = [
    (
        "device id",
        "f2cd08a5297126d9670efd391a88662a06d19d74a9c1e419cd1d79809c2ed845",
    ),
    (
        "signed certificate",
        "23ef00a791b6bcb91f88d988546cbfd2a5d574caebdbcbf92d7abdae7a01ac4f",
    ),
    (
        "node record",
        "689b7aba1767b121c8e900ba2bbde4eec574a267e7e87e15b2c9396a4893e75b",
    ),
    (
        "commit",
        "b01240f47d89cc996033691013ecaa6187f5c27420353d86b6ba6139d003969f",
    ),
    (
        "commit hash",
        "776f4c6d8fb7dc915d7fcb8fb3ad9b05f4b53476957b3b7c6ab0fd2b1443d44e",
    ),
    (
        "envelope",
        "26a938d76472b80698a3a5308462a5ab39250e1bf1ccef88ff4d58e0b5959bc8",
    ),
    (
        "envelope aad",
        "02ab287b37b173e3fefaf03b4ac451c757d2950acea81f98cfce0ab386f67f58",
    ),
    (
        "auth message",
        "10957406324bbefdb6821ddf71c341770be351b4c385935200cae5f8897e8f00",
    ),
    (
        "pairing code",
        "f5f1182e5efda14992167849024abae2b6d51f39e19cd5dbba9c15705375eb06",
    ),
];

#[test]
fn formats_are_frozen() {
    let expected: Vec<(&str, String)> = FROZEN
        .iter()
        .map(|(name, digest)| (*name, (*digest).to_owned()))
        .collect();
    assert_eq!(outputs().unwrap(), expected);
}
