//! Chunk objects: what the server stores for one chunk (chunking design §4).
//!
//! ```text
//! object     = format version (1) ‖ suite (1) ‖ epoch (u32 LE) ‖ nonce (24) ‖ ciphertext ‖ tag (16)
//! plaintext  = flags (1) ‖ original length (u32 LE) ‖ stored length (u32 LE) ‖ stored bytes ‖ zeros
//! AAD        = "oxidrive chunk v1" ‖ version ‖ suite ‖ epoch ‖ collection ID (16) ‖ chunk ID (32)
//! ```
//!
//! The plaintext is padded to its Padmé length. `flags` bit 0 means the stored bytes are
//! zstd-compressed, which is only done when it makes the padded object smaller (decision H1).

use std::fmt;

use oxisoft_drive_crypto::CryptoRng;
use oxisoft_drive_crypto::aead;
use oxisoft_drive_crypto::hash::{Digest, keyed_hash};
use oxisoft_drive_crypto::keys::{CollectionKey, DataKey, IdKey};
use oxisoft_drive_crypto::suite::Suite;
use zeroize::Zeroizing;

use crate::ChunkError;
use crate::padding::padme;

/// Chunk object format version written by this code.
pub const FORMAT_VERSION: u8 = 1;
/// Largest chunk accepted: 16 MiB, the largest `FastCDC` supports.
pub const MAX_CHUNK_LEN: usize = 16 * 1024 * 1024;
/// zstd compression level (decision H2).
pub const COMPRESSION_LEVEL: i32 = 3;

const HEADER_LEN: usize = 1 + 1 + 4;
const PLAINTEXT_HEADER_LEN: usize = 1 + 4 + 4;
const FLAG_COMPRESSED: u8 = 1;
const AAD_LABEL: &[u8] = b"oxidrive chunk v1";

/// The keys one collection epoch needs for its chunks, derived once and reused.
pub struct ChunkKeys {
    data: DataKey,
    id: IdKey,
    epoch: u32,
}

impl ChunkKeys {
    /// Derives the chunk keys of a collection key.
    #[must_use]
    pub fn new(collection: &CollectionKey) -> Self {
        Self {
            data: collection.data(),
            id: collection.id(),
            epoch: collection.epoch(),
        }
    }

    /// The key epoch these keys belong to.
    #[must_use]
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The chunk ID of `plaintext`.
    #[must_use]
    pub fn chunk_id(&self, plaintext: &[u8]) -> Digest {
        keyed_hash(&self.id, plaintext)
    }
}

impl fmt::Debug for ChunkKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkKeys(epoch {}, ..)", self.epoch)
    }
}

/// A chunk ready for upload: its ID and the object to store under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedChunk {
    /// Keyed hash of the plaintext; the name the server stores the object under.
    pub id: Digest,
    /// The encrypted object.
    pub object: Vec<u8>,
}

/// Compresses (when worthwhile), pads and encrypts one chunk.
///
/// # Errors
///
/// [`ChunkError::TooLarge`] for chunks over [`MAX_CHUNK_LEN`].
pub fn seal_chunk<R: CryptoRng>(
    keys: &ChunkKeys,
    rng: &mut R,
    collection_id: &[u8; 16],
    plaintext: &[u8],
) -> Result<SealedChunk, ChunkError> {
    if plaintext.len() > MAX_CHUNK_LEN {
        return Err(ChunkError::TooLarge);
    }
    let original_len = u32::try_from(plaintext.len()).map_err(|_| ChunkError::TooLarge)?;
    let id = keys.chunk_id(plaintext);

    let compressed = zstd::bulk::compress(plaintext, COMPRESSION_LEVEL)
        .ok()
        .map(Zeroizing::new)
        .filter(|compressed| padded_len(compressed.len()) < padded_len(plaintext.len()));
    let (flags, stored): (u8, &[u8]) = match &compressed {
        Some(compressed) => (FLAG_COMPRESSED, compressed),
        None => (0, plaintext),
    };
    let stored_len = u32::try_from(stored.len()).map_err(|_| ChunkError::TooLarge)?;

    let padded = usize::try_from(padded_len(stored.len())).map_err(|_| ChunkError::TooLarge)?;
    let mut inner = Zeroizing::new(Vec::with_capacity(padded));
    inner.push(flags);
    inner.extend_from_slice(&original_len.to_le_bytes());
    inner.extend_from_slice(&stored_len.to_le_bytes());
    inner.extend_from_slice(stored);
    inner.resize(padded, 0);

    let header = header(keys.epoch);
    let sealed = aead::seal(&keys.data, rng, &aad(header, collection_id, &id), &inner)?;
    let mut object = Vec::with_capacity(HEADER_LEN + sealed.len());
    object.extend_from_slice(&header);
    object.extend_from_slice(&sealed);
    Ok(SealedChunk { id, object })
}

/// Checks and decrypts a chunk object stored under `id`, and verifies that the content really
/// hashes to `id` (requirement E3). The plaintext is wiped when dropped.
///
/// # Errors
///
/// - [`ChunkError::UnsupportedVersion`] or a suite error for objects from unknown formats;
/// - [`ChunkError::EpochMismatch`] if `keys` are for another epoch (see [`object_epoch`]);
/// - [`ChunkError::Crypto`] if authentication fails: wrong key, collection or ID, or any
///   modification;
/// - [`ChunkError::Malformed`] for authenticated but ill-formed content;
/// - [`ChunkError::IdMismatch`] if the content doesn't hash to `id`.
pub fn open_chunk(
    keys: &ChunkKeys,
    collection_id: &[u8; 16],
    id: &Digest,
    object: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ChunkError> {
    let (header, sealed) = object
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(ChunkError::Malformed)?;
    let epoch = parse_header(*header)?;
    if epoch != keys.epoch {
        return Err(ChunkError::EpochMismatch {
            object: epoch,
            keys: keys.epoch,
        });
    }
    let inner = aead::open(&keys.data, &aad(*header, collection_id, id), sealed)?;
    let plaintext = unpack(&inner)?;
    if keys.chunk_id(&plaintext) != *id {
        return Err(ChunkError::IdMismatch);
    }
    Ok(plaintext)
}

/// The key epoch an object was sealed with, so the caller can pick the right keys.
///
/// # Errors
///
/// [`ChunkError::Malformed`], [`ChunkError::UnsupportedVersion`] or a suite error if the
/// header can't be read.
pub fn object_epoch(object: &[u8]) -> Result<u32, ChunkError> {
    let (header, _) = object
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(ChunkError::Malformed)?;
    parse_header(*header)
}

fn header(epoch: u32) -> [u8; HEADER_LEN] {
    let mut header = [0; HEADER_LEN];
    header[0] = FORMAT_VERSION;
    header[1] = Suite::CURRENT.id();
    header[2..].copy_from_slice(&epoch.to_le_bytes());
    header
}

fn parse_header(header: [u8; HEADER_LEN]) -> Result<u32, ChunkError> {
    let [version, suite, epoch @ ..] = header;
    if version != FORMAT_VERSION {
        return Err(ChunkError::UnsupportedVersion(version));
    }
    Suite::from_id(suite)?;
    Ok(u32::from_le_bytes(epoch))
}

fn aad(header: [u8; HEADER_LEN], collection_id: &[u8; 16], id: &Digest) -> Vec<u8> {
    [AAD_LABEL, &header, collection_id, id.as_bytes()].concat()
}

/// Padded plaintext length for `stored` bytes of content.
fn padded_len(stored: usize) -> u64 {
    PLAINTEXT_HEADER_LEN
        .checked_add(stored)
        .and_then(|len| u32::try_from(len).ok())
        .map_or(u64::MAX, padme)
}

/// Reads the decrypted plaintext: checks lengths and padding, decompresses if flagged.
fn unpack(inner: &[u8]) -> Result<Zeroizing<Vec<u8>>, ChunkError> {
    let (&flags, rest) = inner.split_first().ok_or(ChunkError::Malformed)?;
    let (original_len, rest) = rest.split_first_chunk::<4>().ok_or(ChunkError::Malformed)?;
    let (stored_len, rest) = rest.split_first_chunk::<4>().ok_or(ChunkError::Malformed)?;
    let original_len = u32::from_le_bytes(*original_len) as usize;
    let stored_len = u32::from_le_bytes(*stored_len) as usize;
    if flags & !FLAG_COMPRESSED != 0 || original_len > MAX_CHUNK_LEN {
        return Err(ChunkError::Malformed);
    }
    let (stored, padding) = rest
        .split_at_checked(stored_len)
        .ok_or(ChunkError::Malformed)?;
    if padding.iter().any(|&byte| byte != 0) || padded_len(stored_len) != inner.len() as u64 {
        return Err(ChunkError::Malformed);
    }
    let plaintext = if flags & FLAG_COMPRESSED == 0 {
        Zeroizing::new(stored.to_vec())
    } else {
        // Capped at the declared length, so a hostile object can't expand without bound.
        zstd::bulk::decompress(stored, original_len)
            .map(Zeroizing::new)
            .map_err(|_| ChunkError::Malformed)?
    };
    if plaintext.len() == original_len {
        Ok(plaintext)
    } else {
        Err(ChunkError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxisoft_drive_crypto::CryptoError;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{Rng, SeedableRng};

    const COLLECTION: [u8; 16] = [7; 16];

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn keys(seed: u8, epoch: u32) -> ChunkKeys {
        ChunkKeys::new(&CollectionKey::generate(&mut rng(seed), epoch))
    }

    fn random_bytes(seed: u8, len: usize) -> Vec<u8> {
        let mut data = vec![0; len];
        rng(seed).fill_bytes(&mut data);
        data
    }

    /// Builds an object around an arbitrary plaintext, to test what `unpack` rejects.
    fn forge(keys: &ChunkKeys, id: &Digest, inner: &[u8]) -> Vec<u8> {
        let header = header(keys.epoch);
        let sealed = aead::seal(
            &keys.data,
            &mut rng(99),
            &aad(header, &COLLECTION, id),
            inner,
        )
        .unwrap();
        [&header[..], &sealed].concat()
    }

    fn inner(flags: u8, original: u32, stored: &[u8], extra_padding: usize) -> Vec<u8> {
        let mut inner = vec![flags];
        inner.extend_from_slice(&original.to_le_bytes());
        inner.extend_from_slice(&u32::try_from(stored.len()).unwrap().to_le_bytes());
        inner.extend_from_slice(stored);
        let padded = usize::try_from(padded_len(stored.len())).unwrap();
        inner.resize(padded + extra_padding, 0);
        inner
    }

    #[test]
    fn compressible_chunks_are_compressed_and_random_ones_are_not() {
        let keys = keys(1, 0);
        let text = "the quick brown fox jumps over the lazy dog ".repeat(20_000);
        let sealed = seal_chunk(&keys, &mut rng(2), &COLLECTION, text.as_bytes()).unwrap();
        assert!(sealed.object.len() < text.len() / 10);
        let opened = open_chunk(&keys, &COLLECTION, &sealed.id, &sealed.object).unwrap();
        assert_eq!(&*opened, text.as_bytes());

        let random = random_bytes(3, 100_000);
        let sealed = seal_chunk(&keys, &mut rng(4), &COLLECTION, &random).unwrap();
        let expected =
            usize::try_from(padded_len(random.len())).unwrap() + HEADER_LEN + aead::OVERHEAD;
        assert_eq!(sealed.object.len(), expected);
        let opened = open_chunk(&keys, &COLLECTION, &sealed.id, &sealed.object).unwrap();
        assert_eq!(*opened, random);
    }

    #[test]
    fn empty_and_maximum_chunks() {
        let keys = keys(5, 0);
        let empty = seal_chunk(&keys, &mut rng(6), &COLLECTION, &[]).unwrap();
        assert!(
            open_chunk(&keys, &COLLECTION, &empty.id, &empty.object)
                .unwrap()
                .is_empty()
        );
        let max = vec![1; MAX_CHUNK_LEN];
        let sealed = seal_chunk(&keys, &mut rng(7), &COLLECTION, &max).unwrap();
        assert_eq!(
            open_chunk(&keys, &COLLECTION, &sealed.id, &sealed.object)
                .unwrap()
                .len(),
            MAX_CHUNK_LEN
        );
        let too_big = vec![0; MAX_CHUNK_LEN + 1];
        assert_eq!(
            seal_chunk(&keys, &mut rng(8), &COLLECTION, &too_big),
            Err(ChunkError::TooLarge)
        );
    }

    #[test]
    fn objects_are_bound_to_collection_id_and_epoch() {
        let keys = keys(9, 4);
        let sealed = seal_chunk(&keys, &mut rng(10), &COLLECTION, b"content").unwrap();
        assert_eq!(object_epoch(&sealed.object), Ok(4));
        let crypto = Err(ChunkError::Crypto(CryptoError::Decrypt));
        assert_eq!(
            open_chunk(&keys, &[8; 16], &sealed.id, &sealed.object),
            crypto
        );
        let other_id = keys.chunk_id(b"other");
        assert_eq!(
            open_chunk(&keys, &COLLECTION, &other_id, &sealed.object),
            crypto
        );
        let other_epoch = self::keys(9, 5);
        assert_eq!(
            open_chunk(&other_epoch, &COLLECTION, &sealed.id, &sealed.object),
            Err(ChunkError::EpochMismatch { object: 4, keys: 5 })
        );
        assert_eq!(
            open_chunk(&self::keys(11, 4), &COLLECTION, &sealed.id, &sealed.object),
            crypto
        );
    }

    #[test]
    fn headers_are_checked() {
        let keys = keys(12, 0);
        let sealed = seal_chunk(&keys, &mut rng(13), &COLLECTION, b"x").unwrap();
        assert_eq!(object_epoch(&[1, 1, 0]), Err(ChunkError::Malformed));
        assert_eq!(
            open_chunk(&keys, &COLLECTION, &sealed.id, &[1]),
            Err(ChunkError::Malformed)
        );
        let mut future = sealed.object.clone();
        future[0] = 2;
        assert_eq!(
            object_epoch(&future),
            Err(ChunkError::UnsupportedVersion(2))
        );
        let mut unknown_suite = sealed.object.clone();
        unknown_suite[1] = 9;
        assert_eq!(
            open_chunk(&keys, &COLLECTION, &sealed.id, &unknown_suite),
            Err(ChunkError::Crypto(CryptoError::UnsupportedSuite(9)))
        );
    }

    #[test]
    fn forged_contents_are_rejected() {
        let keys = keys(14, 0);
        // 9 header bytes + 6 content bytes pad to 16: one padding byte to tamper with.
        let content = b"hello!".as_slice();
        let id = keys.chunk_id(content);
        let open = |inner: &[u8]| open_chunk(&keys, &COLLECTION, &id, &forge(&keys, &id, inner));

        assert_eq!(inner(0, 6, content, 0).len(), 16);
        assert_eq!(&*open(&inner(0, 6, content, 0)).unwrap(), content);
        let malformed = Err(ChunkError::Malformed);
        assert_eq!(open(&[]), malformed);
        assert_eq!(open(&[0, 5, 0]), malformed);
        assert_eq!(open(&[0, 5, 0, 0, 0, 5]), malformed);
        assert_eq!(open(&inner(2, 6, content, 0)), malformed, "unknown flag");
        assert_eq!(open(&inner(0, 7, content, 0)), malformed, "length mismatch");
        assert_eq!(open(&inner(0, 6, content, 1)), malformed, "over-padded");
        let mut dirty = inner(0, 6, content, 0);
        *dirty.last_mut().unwrap() = 1;
        assert_eq!(open(&dirty), malformed, "non-zero padding");
        let mut stored_too_long = inner(0, 6, content, 0);
        stored_too_long[5] = 200;
        assert_eq!(
            open(&stored_too_long),
            malformed,
            "stored length past the end"
        );
        let huge = u32::try_from(MAX_CHUNK_LEN + 1).unwrap();
        assert_eq!(
            open(&inner(0, huge, content, 0)),
            malformed,
            "declared too large"
        );
        assert_eq!(
            open(&inner(FLAG_COMPRESSED, 6, b"not zstd", 0)),
            malformed,
            "undecodable"
        );

        // A decompression bomb: a tiny frame that expands far beyond its declared length.
        let bomb = zstd::bulk::compress(&vec![0; 1_000_000], 19).unwrap();
        assert!(bomb.len() < 1000);
        assert_eq!(
            open(&inner(FLAG_COMPRESSED, 6, &bomb, 0)),
            malformed,
            "bomb"
        );

        // Well-formed content that doesn't hash to its ID.
        let wrong = b"jello!".as_slice();
        assert_eq!(open(&inner(0, 6, wrong, 0)), Err(ChunkError::IdMismatch));
    }

    #[test]
    fn keys_debug_and_id() {
        let keys = keys(15, 6);
        assert_eq!(format!("{keys:?}"), "ChunkKeys(epoch 6, ..)");
        assert_eq!(keys.epoch(), 6);
        assert_eq!(keys.chunk_id(b"a"), keys.chunk_id(b"a"));
        assert_ne!(keys.chunk_id(b"a"), self::keys(16, 6).chunk_id(b"a"));
        assert_eq!(padded_len(usize::MAX), u64::MAX);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn round_trips(data in prop::collection::vec(any::<u8>(), 0..20_000), repeat in 1usize..4) {
            let keys = keys(20, 1);
            let data = data.repeat(repeat);
            let sealed = seal_chunk(&keys, &mut rng(21), &COLLECTION, &data).unwrap();
            prop_assert_eq!(sealed.id, keys.chunk_id(&data));
            let opened = open_chunk(&keys, &COLLECTION, &sealed.id, &sealed.object).unwrap();
            prop_assert_eq!(&*opened, &data);
        }

        #[test]
        fn any_bit_flip_is_detected(data in prop::collection::vec(any::<u8>(), 0..2000),
                                    flip in any::<prop::sample::Index>(), bit in 0u8..8) {
            let keys = keys(22, 0);
            let sealed = seal_chunk(&keys, &mut rng(23), &COLLECTION, &data).unwrap();
            let mut object = sealed.object.clone();
            let i = flip.index(object.len());
            object[i] ^= 1 << bit;
            prop_assert!(open_chunk(&keys, &COLLECTION, &sealed.id, &object).is_err());
        }
    }
}
