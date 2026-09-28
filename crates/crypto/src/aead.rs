//! XChaCha20-Poly1305 authenticated encryption with random 192-bit nonces.
//!
//! A sealed blob is `nonce (24) ‖ ciphertext ‖ tag (16)`. With a 192-bit nonce, random nonces
//! are safe at any volume, so no nonce state is ever kept.

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::keys::sealed::SymmetricKey;
use crate::secret::Secret32;

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Bytes a sealed blob adds to its plaintext.
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// A key that may encrypt data directly: [`MetaKey`](crate::keys::MetaKey),
/// [`DataKey`](crate::keys::DataKey) and [`ThumbKey`](crate::keys::ThumbKey). Keys that only
/// wrap other keys don't implement it.
pub trait AeadKey: SymmetricKey {}

/// Encrypts and authenticates `plaintext`, and authenticates `aad` (which is not stored).
///
/// # Errors
///
/// [`CryptoError::TooLarge`] if `plaintext` exceeds the cipher's limit (256 GiB).
pub fn seal<K: AeadKey, R: CryptoRng>(
    key: &K,
    rng: &mut R,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    seal_with(key.secret(), rng, aad, plaintext)
}

/// Checks and decrypts a blob made by [`seal`] with the same key and `aad`. The plaintext is
/// wiped when dropped.
///
/// # Errors
///
/// [`CryptoError::Decrypt`] for a wrong key, a different `aad`, or any modification of the
/// blob.
pub fn open<K: AeadKey>(
    key: &K,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    open_with(key.secret(), aad, sealed)
}

pub(crate) fn seal_with<R: CryptoRng>(
    key: &Secret32,
    rng: &mut R,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let mut nonce = XNonce::default();
    rng.fill_bytes(&mut nonce);
    let mut sealed = Vec::with_capacity(plaintext.len() + OVERHEAD);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, InOutBuf::from(&mut sealed[NONCE_LEN..]))
        .map_err(|_| CryptoError::TooLarge)?;
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

pub(crate) fn open_with(
    key: &Secret32,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (nonce, rest) = sealed
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(CryptoError::Decrypt)?;
    let (ciphertext, tag) = rest
        .split_last_chunk::<TAG_LEN>()
        .ok_or(CryptoError::Decrypt)?;
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(
            &XNonce::from(*nonce),
            aad,
            InOutBuf::from(plaintext.as_mut_slice()),
            &Tag::from(*tag),
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::CollectionKey;
    use crate::test_util::{from_hex, rng};
    use proptest::prelude::*;
    use rand_core::{Infallible, TryCryptoRng, TryRng};

    /// An "RNG" that returns fixed bytes, to reproduce the published test vector's nonce.
    struct FixedBytes(Vec<u8>);

    impl TryRng for FixedBytes {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            let taken: Vec<u8> = self.0.drain(..dst.len()).collect();
            dst.copy_from_slice(&taken);
            Ok(())
        }
    }

    impl TryCryptoRng for FixedBytes {}

    /// draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    #[test]
    fn matches_the_xchacha_draft_vector() {
        let key = Secret32::from_bytes(
            from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap(),
        );
        let nonce = from_hex("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = from_hex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73
             637265656e20776f756c642062652069742e",
        );
        let ciphertext = from_hex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
             21f9664c97637da9768812f615c68b13b52e",
        );
        let tag = from_hex("c0875924c1c7987947deafd8780acf49");

        let sealed = seal_with(&key, &mut FixedBytes(nonce.clone()), &aad, &plaintext).unwrap();
        assert_eq!(sealed, [nonce, ciphertext, tag].concat());
        assert_eq!(*open_with(&key, &aad, &sealed).unwrap(), plaintext);
    }

    #[test]
    fn short_or_empty_input_is_rejected() {
        let key = CollectionKey::generate(&mut rng(10), 0).data();
        for len in [0, 1, NONCE_LEN, OVERHEAD - 1] {
            assert_eq!(
                open(&key, b"", &vec![0; len]).unwrap_err(),
                CryptoError::Decrypt
            );
        }
        let empty = seal(&key, &mut rng(11), b"", b"").unwrap();
        assert_eq!(empty.len(), OVERHEAD);
        assert!(open(&key, b"", &empty).unwrap().is_empty());
    }

    #[test]
    fn nonces_are_fresh() {
        let key = CollectionKey::generate(&mut rng(12), 0).meta();
        let mut rng = rng(13);
        let a = seal(&key, &mut rng, b"", b"same").unwrap();
        let b = seal(&key, &mut rng, b"", b"same").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }

    proptest! {
        #[test]
        fn round_trips(plaintext in prop::collection::vec(any::<u8>(), 0..2048),
                       aad in prop::collection::vec(any::<u8>(), 0..64),
                       seed in any::<u8>()) {
            let key = CollectionKey::generate(&mut rng(seed), 0).thumb();
            let sealed = seal(&key, &mut rng(seed.wrapping_add(1)), &aad, &plaintext).unwrap();
            prop_assert_eq!(sealed.len(), plaintext.len() + OVERHEAD);
            prop_assert_eq!(&*open(&key, &aad, &sealed).unwrap(), &plaintext);
        }

        #[test]
        fn any_bit_flip_is_detected(plaintext in prop::collection::vec(any::<u8>(), 0..256),
                                    flip in any::<prop::sample::Index>(),
                                    bit in 0u8..8) {
            let key = CollectionKey::generate(&mut rng(20), 0).data();
            let mut sealed = seal(&key, &mut rng(21), b"aad", &plaintext).unwrap();
            let i = flip.index(sealed.len());
            sealed[i] ^= 1 << bit;
            prop_assert_eq!(open(&key, b"aad", &sealed).unwrap_err(), CryptoError::Decrypt);
        }

        #[test]
        fn wrong_aad_or_key_is_detected(aad in prop::collection::vec(any::<u8>(), 0..32)) {
            let collection = CollectionKey::generate(&mut rng(30), 0);
            let sealed = seal(&collection.data(), &mut rng(31), &aad, b"secret").unwrap();
            let mut other_aad = aad.clone();
            other_aad.push(0);
            prop_assert!(open(&collection.data(), &other_aad, &sealed).is_err());
            prop_assert!(open(&collection.meta(), &aad, &sealed).is_err());
        }
    }
}
