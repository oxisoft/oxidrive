//! Frozen format vectors (engineering standards §2, requirement N4).
//!
//! Chunk boundaries, IDs and uncompressed objects from a seeded RNG are fully deterministic;
//! their BLAKE3 fingerprints are frozen here. A failure means the stored format or the
//! chunking changed: that breaks existing data and deduplication, and needs a new format
//! version, not an updated constant.
//!
//! zstd output may legitimately change between zstd versions, so compressed objects are not
//! fingerprinted. Instead, a compressed object written on 2026-09-28 is stored whole and must
//! keep opening.

use std::fmt::Write as _;

use oxisoft_drive_chunking::{ChunkError, ChunkKeys, ChunkParams, Chunker, open_chunk, seal_chunk};
use oxisoft_drive_crypto::hash;
use oxisoft_drive_crypto::keys::CollectionKey;
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

const COLLECTION_ID: [u8; 16] = [0x42; 16];

fn fingerprint(bytes: &[u8]) -> String {
    hash::hash(bytes)
        .as_bytes()
        .iter()
        .fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn text() -> String {
    "frozen format vector ".repeat(1000)
}

fn outputs() -> Result<Vec<(&'static str, String)>, ChunkError> {
    let mut rng = ChaCha20Rng::from_seed([0x0c; 32]);
    let collection = CollectionKey::generate(&mut rng, 1);
    let mut data = vec![0; 6 * 1024 * 1024];
    rng.fill_bytes(&mut data);

    let chunker = Chunker::new(&collection.chunking(), ChunkParams::DEFAULT);
    let lengths: Vec<u8> = chunker
        .chunks(&data)
        .flat_map(|chunk| u32::try_from(chunk.len()).unwrap_or(u32::MAX).to_le_bytes())
        .collect();

    let keys = ChunkKeys::new(&collection);
    let compressed = seal_chunk(&keys, &mut rng, &COLLECTION_ID, text().as_bytes())?;
    let raw = seal_chunk(&keys, &mut rng, &COLLECTION_ID, &data[..100_000])?;
    open_chunk(&keys, &COLLECTION_ID, &raw.id, &raw.object)?;

    Ok(vec![
        ("chunk lengths", fingerprint(&lengths)),
        ("compressed id", fingerprint(compressed.id.as_bytes())),
        ("raw id", fingerprint(raw.id.as_bytes())),
        ("raw object", fingerprint(&raw.object)),
    ])
}

const FROZEN: [(&str, &str); 4] = [
    (
        "chunk lengths",
        "51a623e9a89fb244cac72b4123500fd1652faa01b3e5a51c20e611de049e79d1",
    ),
    (
        "compressed id",
        "bd946ff0fd602d3c49f2ef6424c24902cb9ad4830856fb6b752f2e4d54a4773b",
    ),
    (
        "raw id",
        "3cc5d9708039a59f86fba24f45274245d91a862e111250facce3e64fb86958c8",
    ),
    (
        "raw object",
        "92716188de576f0a9c799e0c64871fd0d06603175636a73b1f4803fb4c7d0189",
    ),
];

/// A compressed chunk object as written on 2026-09-28 (collection key from seed `0x0c`).
const STORED_COMPRESSED_OBJECT: [&str; 3] = [
    "010101000000b4ee695ee9fbf310e5478d94ce54a4a86d897eadeb08d5a60577",
    "d3162d7cdb6ab07f04dbf0eaafdc439f641814cc403f1b71eefde4f737aa059c",
    "1698ad70237ed6c94d4729bff3c12bc231e121b575847020dea14a8cff02",
];

#[test]
fn formats_are_frozen() {
    let expected: Vec<(&str, String)> = FROZEN
        .iter()
        .map(|(name, digest)| (*name, (*digest).to_owned()))
        .collect();
    assert_eq!(outputs().unwrap(), expected);
}

#[test]
fn a_stored_compressed_object_still_opens() {
    let object: Vec<u8> = STORED_COMPRESSED_OBJECT
        .concat()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let mut rng = ChaCha20Rng::from_seed([0x0c; 32]);
    let keys = ChunkKeys::new(&CollectionKey::generate(&mut rng, 1));
    let text = text();
    let id = keys.chunk_id(text.as_bytes());
    let opened = open_chunk(&keys, &COLLECTION_ID, &id, &object).unwrap();
    assert_eq!(&*opened, text.as_bytes());
    assert!(object.len() < 200, "stored compressed");
}
