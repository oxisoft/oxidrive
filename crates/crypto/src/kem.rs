//! Wrapping keys to a public key: HPKE (RFC 9180) in base mode with the X-Wing hybrid KEM
//! (X25519 + ML-KEM-768), HKDF-SHA256 and ChaCha20-Poly1305.
//!
//! A key is lost only if **both** X25519 and ML-KEM-768 are broken, which protects envelopes
//! stored for years against a future quantum computer (crypto design D1). A wrapped key is
//! `encapsulated key (1120) ‖ ciphertext`.

use std::fmt;

use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::context;
use crate::keys::{WrappableKey, decode_wrapped, encode_wrapped};

type XWing = hpke::kem::XWing;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

/// Public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 1216;
/// Length of the encapsulated key at the start of every wrapped key.
pub const ENCAPSULATED_LEN: usize = 1120;

/// What a key is being wrapped for. Becomes HPKE's `info`, so a wrapped key made for one
/// purpose can't be opened as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WrapContext {
    /// The account key, wrapped to a device's KEM key.
    AccountKeyToDevice,
    /// A collection key, wrapped to another account's KEM key (sharing, later).
    CollectionKeyToAccount,
}

impl WrapContext {
    const fn info(self) -> &'static [u8] {
        match self {
            Self::AccountKeyToDevice => context::WRAP_ACCOUNT_KEY_TO_DEVICE,
            Self::CollectionKeyToAccount => context::WRAP_COLLECTION_KEY_TO_ACCOUNT,
        }
    }
}

/// An X-Wing private key (a 32-byte seed). Wiped on drop.
pub struct KemSecretKey(<XWing as hpke::Kem>::PrivateKey);

impl KemSecretKey {
    /// A new random key.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        Self(XWing::gen_keypair_with_rng(rng).0)
    }

    /// The public half.
    #[must_use]
    pub fn public_key(&self) -> KemPublicKey {
        KemPublicKey(XWing::sk_to_pk(&self.0))
    }

    pub(crate) fn to_keystore_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut bytes = Zeroizing::new([0; 32]);
        self.0.write_exact(bytes.as_mut_slice());
        bytes
    }

    pub(crate) fn from_keystore_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        <XWing as hpke::Kem>::PrivateKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }
}

impl fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KemSecretKey(..)")
    }
}

/// An X-Wing public key.
#[derive(Clone, PartialEq, Eq)]
pub struct KemPublicKey(<XWing as hpke::Kem>::PublicKey);

impl KemPublicKey {
    /// Reads a stored public key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidLength`] or [`CryptoError::InvalidKey`] for bad input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidLength {
                expected: PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        <XWing as hpke::Kem>::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// The stored form.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fingerprint = blake3::hash(&self.0.to_bytes());
        write!(f, "KemPublicKey({}..)", &fingerprint.to_hex()[..16])
    }
}

/// Wraps `key` to the holder of `to`'s private key. `aad` must bind the envelope to what it
/// belongs to (IDs, epochs); the same `aad` is needed to unwrap.
///
/// # Errors
///
/// [`CryptoError::InvalidKey`] if encapsulation to `to` fails.
pub fn wrap_to<K: WrappableKey, R: CryptoRng>(
    rng: &mut R,
    to: &KemPublicKey,
    context: WrapContext,
    aad: &[u8],
    key: &K,
) -> Result<Vec<u8>, CryptoError> {
    let (encapsulated, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, XWing>(
        &OpModeS::Base,
        &to.0,
        context.info(),
        &encode_wrapped(key),
        aad,
        rng,
    )
    .map_err(|_| CryptoError::InvalidKey)?;
    let mut wrapped = encapsulated.to_bytes().to_vec();
    wrapped.extend_from_slice(&ciphertext);
    Ok(wrapped)
}

/// Unwraps a key made by [`wrap_to`] for this private key, context and `aad`.
///
/// # Errors
///
/// [`CryptoError::Decrypt`] for a different recipient, context or `aad`, any modification, or
/// a key of another type than `K`.
pub fn unwrap_with<K: WrappableKey>(
    secret: &KemSecretKey,
    context: WrapContext,
    aad: &[u8],
    wrapped: &[u8],
) -> Result<K, CryptoError> {
    let (encapsulated, ciphertext) = wrapped
        .split_first_chunk::<ENCAPSULATED_LEN>()
        .ok_or(CryptoError::Decrypt)?;
    let encapsulated = <XWing as hpke::Kem>::EncappedKey::from_bytes(encapsulated)
        .map_err(|_| CryptoError::Decrypt)?;
    let plaintext = Zeroizing::new(
        hpke::single_shot_open::<Aead, Kdf, XWing>(
            &OpModeR::Base,
            &secret.0,
            &encapsulated,
            context.info(),
            ciphertext,
            aad,
        )
        .map_err(|_| CryptoError::Decrypt)?,
    );
    decode_wrapped(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{AccountKey, CollectionKey};
    use crate::test_util::rng;
    use proptest::prelude::*;

    #[test]
    fn wraps_and_unwraps_to_a_device() {
        let mut rng = rng(60);
        let device = KemSecretKey::generate(&mut rng);
        let account = AccountKey::generate(&mut rng, 3);
        let wrapped = wrap_to(
            &mut rng,
            &device.public_key(),
            WrapContext::AccountKeyToDevice,
            b"aad",
            &account,
        )
        .unwrap();
        assert!(wrapped.len() > ENCAPSULATED_LEN);
        let back: AccountKey =
            unwrap_with(&device, WrapContext::AccountKeyToDevice, b"aad", &wrapped).unwrap();
        assert_eq!(back.epoch(), 3);
        // Same key: it unwraps what the original can.
        let collection = CollectionKey::generate(&mut rng, 0);
        let sealed = account.wrap(&mut rng, b"x", &collection).unwrap();
        assert!(back.unwrap::<CollectionKey>(b"x", &sealed).is_ok());
    }

    #[test]
    fn wrong_recipient_context_aad_or_type_fails() {
        let mut rng = rng(61);
        let device = KemSecretKey::generate(&mut rng);
        let other = KemSecretKey::generate(&mut rng);
        let account = AccountKey::generate(&mut rng, 0);
        let wrapped = wrap_to(
            &mut rng,
            &device.public_key(),
            WrapContext::AccountKeyToDevice,
            b"aad",
            &account,
        )
        .unwrap();
        let ctx = WrapContext::AccountKeyToDevice;
        assert!(unwrap_with::<AccountKey>(&other, ctx, b"aad", &wrapped).is_err());
        assert!(
            unwrap_with::<AccountKey>(
                &device,
                WrapContext::CollectionKeyToAccount,
                b"aad",
                &wrapped
            )
            .is_err()
        );
        assert!(unwrap_with::<AccountKey>(&device, ctx, b"aax", &wrapped).is_err());
        assert!(unwrap_with::<CollectionKey>(&device, ctx, b"aad", &wrapped).is_err());
        assert!(unwrap_with::<AccountKey>(&device, ctx, b"aad", &wrapped[..100]).is_err());
    }

    #[test]
    fn keys_round_trip_through_bytes() {
        let mut rng = rng(62);
        let secret = KemSecretKey::generate(&mut rng);
        let public = secret.public_key();
        assert_eq!(
            KemPublicKey::from_bytes(&public.to_bytes()).unwrap(),
            public
        );
        let restored = KemSecretKey::from_keystore_bytes(&secret.to_keystore_bytes()).unwrap();
        assert_eq!(restored.public_key(), public);
        assert_eq!(
            KemPublicKey::from_bytes(&[0; 10]),
            Err(CryptoError::InvalidLength {
                expected: PUBLIC_KEY_LEN,
                actual: 10
            })
        );
    }

    #[test]
    fn debug_shows_no_secrets() {
        let secret = KemSecretKey::generate(&mut rng(63));
        assert_eq!(format!("{secret:?}"), "KemSecretKey(..)");
        let text = format!("{:?}", secret.public_key());
        assert!(
            text.starts_with("KemPublicKey(") && text.ends_with("..)"),
            "{text}"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn any_bit_flip_is_detected(flip in any::<prop::sample::Index>(), bit in 0u8..8) {
            let mut rng = rng(64);
            let device = KemSecretKey::generate(&mut rng);
            let key = CollectionKey::generate(&mut rng, 1);
            let ctx = WrapContext::CollectionKeyToAccount;
            let mut wrapped = wrap_to(&mut rng, &device.public_key(), ctx, b"", &key).unwrap();
            let i = flip.index(wrapped.len());
            wrapped[i] ^= 1 << bit;
            prop_assert!(unwrap_with::<CollectionKey>(&device, ctx, b"", &wrapped).is_err());
        }
    }
}
