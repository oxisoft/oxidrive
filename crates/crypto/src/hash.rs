//! BLAKE3: plain hashes, keyed hashes (chunk and photo IDs), key derivation, and the gear
//! table for keyed content-defined chunking.

use std::fmt;

use zeroize::Zeroize;

use crate::context;
use crate::keys::sealed::SymmetricKey;
use crate::keys::{ChunkingKey, IdKey};
use crate::secret::Secret32;

/// Length of a [`Digest`] in bytes.
pub const DIGEST_LEN: usize = 32;

/// A 32-byte BLAKE3 output. Compared in constant time.
#[derive(Clone, Copy, Eq)]
pub struct Digest([u8; DIGEST_LEN]);

impl Digest {
    /// Wraps stored bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        blake3::Hash::from_bytes(self.0) == blake3::Hash::from_bytes(other.0)
    }
}

impl std::hash::Hash for Digest {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", blake3::Hash::from_bytes(self.0).to_hex())
    }
}

/// Plain BLAKE3 hash, for public data.
#[must_use]
pub fn hash(data: &[u8]) -> Digest {
    Digest(*blake3::hash(data).as_bytes())
}

/// Keyed hash: chunk IDs and photo IDs. Without the key, the server can't compute or confirm
/// an ID.
#[must_use]
pub fn keyed_hash(key: &IdKey, data: &[u8]) -> Digest {
    Digest(*blake3::keyed_hash(key.secret().expose(), data).as_bytes())
}

/// Streaming version of [`keyed_hash`], for whole-file content hashes.
pub struct KeyedHasher(blake3::Hasher);

impl KeyedHasher {
    /// Starts a keyed hash.
    #[must_use]
    pub fn new(key: &IdKey) -> Self {
        Self(blake3::Hasher::new_keyed(key.secret().expose()))
    }

    /// Adds data.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    /// The hash of everything added so far.
    #[must_use]
    pub fn finalize(&self) -> Digest {
        Digest(*self.0.finalize().as_bytes())
    }
}

impl Drop for KeyedHasher {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for KeyedHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyedHasher(..)")
    }
}

/// Number of entries in the gear table.
pub const GEAR_TABLE_LEN: usize = 256;

/// Expands a chunking key into the `FastCDC` gear table: 256 pseudo-random 64-bit values, unique
/// to the collection and epoch (chunking design §3).
#[must_use]
pub fn gear_table(key: &ChunkingKey) -> Box<[u64; GEAR_TABLE_LEN]> {
    let mut hasher = blake3::Hasher::new_keyed(key.secret().expose());
    hasher.update(context::GEAR_TABLE);
    let mut reader = hasher.finalize_xof();
    hasher.zeroize();
    let mut table = Box::new([0; GEAR_TABLE_LEN]);
    let mut entry = [0; 8];
    for slot in table.iter_mut() {
        reader.fill(&mut entry);
        *slot = u64::from_le_bytes(entry);
    }
    reader.zeroize();
    entry.zeroize();
    table
}

/// BLAKE3 key derivation. Crate-private: other crates get derived keys only through the typed
/// methods on [`CollectionKey`](crate::keys::CollectionKey) and friends.
pub(crate) fn derive_key(context: &'static str, material: &[u8]) -> Secret32 {
    Secret32::from_bytes(blake3::derive_key(context, material))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::CollectionKey;
    use crate::test_util::{rng, to_hex};
    use proptest::prelude::*;

    /// Inputs of the official BLAKE3 test vectors: byte `i` is `i % 251`.
    fn input(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    const KEY: &[u8; 32] = b"whats the Elvish word for friend";
    const CONTEXT: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    /// From BLAKE3's `test_vectors/test_vectors.json`: input length, hash, keyed hash,
    /// derived key (first 32 bytes of each).
    const VECTORS: [(usize, &str, &str, &str); 8] = [
        (
            0,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
            "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d",
        ),
        (
            1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
            "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c",
        ),
        (
            1023,
            "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
            "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e",
            "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5",
        ),
        (
            1024,
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
            "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
            "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706",
        ),
        (
            1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
            "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb",
        ),
        (
            2048,
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
            "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1",
            "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23",
        ),
        (
            8192,
            "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
            "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a",
            "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d",
        ),
        (
            102_400,
            "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
            "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7",
            "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6",
        ),
    ];

    #[test]
    fn matches_the_official_blake3_vectors() {
        let id_key = IdKey(Secret32::from_bytes(*KEY));
        for (len, plain, keyed, derived) in VECTORS {
            let data = input(len);
            assert_eq!(to_hex(hash(&data).as_bytes()), plain, "hash, len {len}");
            assert_eq!(
                to_hex(keyed_hash(&id_key, &data).as_bytes()),
                keyed,
                "keyed, len {len}"
            );
            let mut streaming = KeyedHasher::new(&id_key);
            for part in data.chunks(100) {
                streaming.update(part);
            }
            assert_eq!(
                to_hex(streaming.finalize().as_bytes()),
                keyed,
                "stream, len {len}"
            );
            let key = blake3::derive_key(CONTEXT, &data);
            assert_eq!(to_hex(&key), derived, "derive_key, len {len}");
            assert_eq!(derive_key(CONTEXT, &data).expose(), &key);
        }
    }

    #[test]
    fn gear_tables_are_keyed() {
        let a = CollectionKey::generate(&mut rng(40), 0).chunking();
        let b = CollectionKey::generate(&mut rng(41), 0).chunking();
        let table = gear_table(&a);
        assert_eq!(table, gear_table(&a));
        assert_ne!(table, gear_table(&b));
        let distinct: std::collections::HashSet<u64> = table.iter().copied().collect();
        assert_eq!(distinct.len(), GEAR_TABLE_LEN);
    }

    #[test]
    fn digests_compare_hash_and_print() {
        let a = hash(b"a");
        assert_eq!(a, Digest::from_bytes(*a.as_bytes()));
        assert_ne!(a, hash(b"b"));
        let set: std::collections::HashSet<Digest> = [a, a, hash(b"b")].into_iter().collect();
        assert_eq!(set.len(), 2);
        assert_eq!(
            format!("{a:?}"),
            format!("Digest({})", to_hex(a.as_bytes()))
        );
        let key = CollectionKey::generate(&mut rng(42), 0).id();
        assert_eq!(format!("{:?}", KeyedHasher::new(&key)), "KeyedHasher(..)");
    }

    proptest! {
        #[test]
        fn streaming_equals_one_shot(data in prop::collection::vec(any::<u8>(), 0..4096),
                                     split in any::<prop::sample::Index>()) {
            let key = CollectionKey::generate(&mut rng(43), 0).id();
            let (head, tail) = data.split_at(split.index(data.len() + 1));
            let mut streaming = KeyedHasher::new(&key);
            streaming.update(head).update(tail);
            prop_assert_eq!(streaming.finalize(), keyed_hash(&key, &data));
        }
    }
}
