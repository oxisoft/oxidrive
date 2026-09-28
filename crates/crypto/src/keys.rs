//! The key hierarchy (crypto design §3), one type per key.
//!
//! ```text
//! RecoveryKey ──▶ RecoveryWrapKey ──wraps──▶ AccountKey ◀──wraps(HPKE)── device KEM keys
//!                                              │ wraps
//!                  ┌───────────────────────────┼──────────────────────┐
//!                  ▼                           ▼                      ▼
//!          AccountSigningKey            AccountKemKey          CollectionKey
//!                                                                     │ derives
//!                                   MetaKey, DataKey, IdKey, ChunkingKey, ThumbKey
//! ```
//!
//! Distinct types mean the compiler rejects, for example, encrypting a chunk with a meta key
//! or hashing with a data key. Wrapped keys also carry their type inside the encryption, so an
//! envelope holding a collection key can't be unwrapped as an account key.

use std::fmt;

use rand_core::CryptoRng;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;
use crate::aead;
use crate::context;
use crate::hash;
use crate::kem::{KemPublicKey, KemSecretKey};
use crate::secret::Secret32;
use crate::sign::{SigningKey, VerifyingKey};

pub(crate) mod sealed {
    use zeroize::Zeroizing;

    use crate::CryptoError;
    use crate::secret::Secret32;

    /// Gives this crate access to a symmetric key's bytes. Unnameable outside the crate, so no
    /// one else can read them.
    pub trait SymmetricKey {
        fn secret(&self) -> &Secret32;
    }

    /// Converts a key to and from the plaintext of an envelope.
    pub trait Wrappable: Sized {
        const TYPE_TAG: u8;
        fn epoch(&self) -> u32;
        fn material(&self) -> Zeroizing<[u8; 32]>;
        fn from_material(epoch: u32, material: &[u8; 32]) -> Result<Self, CryptoError>;
    }
}

/// A key that may be put into an envelope: [`AccountKey`], [`CollectionKey`],
/// [`AccountSigningKey`] and [`AccountKemKey`].
pub trait WrappableKey: sealed::Wrappable {}

macro_rules! secret_type {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        pub struct $name(pub(crate) Secret32);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }

        // The only field is a `Secret32`, which wipes itself on drop.
        impl ZeroizeOnDrop for $name {}

        impl sealed::SymmetricKey for $name {
            fn secret(&self) -> &Secret32 {
                &self.0
            }
        }
    };
}

macro_rules! epoch_key_type {
    ($(#[$attr:meta])* $name:ident, tag = $tag:expr) => {
        $(#[$attr])*
        pub struct $name {
            secret: Secret32,
            epoch: u32,
        }

        impl $name {
            /// A new random key for the given epoch.
            pub fn generate<R: CryptoRng>(rng: &mut R, epoch: u32) -> Self {
                Self {
                    secret: Secret32::random(rng),
                    epoch,
                }
            }

            /// The key epoch this key belongs to (crypto design §5.3).
            #[must_use]
            pub const fn epoch(&self) -> u32 {
                self.epoch
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "(epoch {}, ..)"), self.epoch)
            }
        }

        // `secret` wipes itself on drop; `epoch` is not secret.
        impl ZeroizeOnDrop for $name {}

        impl sealed::Wrappable for $name {
            const TYPE_TAG: u8 = $tag;

            fn epoch(&self) -> u32 {
                self.epoch
            }

            fn material(&self) -> Zeroizing<[u8; 32]> {
                Zeroizing::new(*self.secret.expose())
            }

            fn from_material(epoch: u32, material: &[u8; 32]) -> Result<Self, CryptoError> {
                Ok(Self {
                    secret: Secret32::from_bytes(*material),
                    epoch,
                })
            }
        }

        impl WrappableKey for $name {}
    };
}

epoch_key_type!(
    /// The root of one user's data. Wraps collection keys, the account's private keys and the
    /// previous account key epoch.
    AccountKey,
    tag = 1
);

epoch_key_type!(
    /// The key of one collection (a synced folder root, or the photo library). Every key used
    /// on that collection's data is derived from it.
    CollectionKey,
    tag = 2
);

secret_type!(
    /// Encrypts node records: names, folder structure, metadata.
    MetaKey
);
secret_type!(
    /// Encrypts chunk contents.
    DataKey
);
secret_type!(
    /// Keys the hash that computes chunk IDs and photo IDs.
    IdKey
);
secret_type!(
    /// Seeds the gear table of keyed content-defined chunking.
    ChunkingKey
);
secret_type!(
    /// Encrypts thumbnails.
    ThumbKey
);
secret_type!(
    /// Wraps the account key under the recovery key. Only obtainable from a
    /// [`RecoveryKey`](crate::recovery::RecoveryKey).
    RecoveryWrapKey
);

secret_type!(
    /// Encrypts account-level metadata that every device of the account may read: device
    /// display names, collection names and configuration.
    AccountMetaKey
);

impl aead::AeadKey for AccountMetaKey {}
impl aead::AeadKey for MetaKey {}
impl aead::AeadKey for DataKey {}
impl aead::AeadKey for ThumbKey {}

impl CollectionKey {
    /// The key for this collection's node records.
    #[must_use]
    pub fn meta(&self) -> MetaKey {
        MetaKey(hash::derive_key(
            context::COLLECTION_META,
            self.secret.expose(),
        ))
    }

    /// The key for this collection's chunk contents.
    #[must_use]
    pub fn data(&self) -> DataKey {
        DataKey(hash::derive_key(
            context::COLLECTION_DATA,
            self.secret.expose(),
        ))
    }

    /// The key for this collection's chunk and photo IDs.
    #[must_use]
    pub fn id(&self) -> IdKey {
        IdKey(hash::derive_key(
            context::COLLECTION_ID,
            self.secret.expose(),
        ))
    }

    /// The key for this collection's chunk boundaries.
    #[must_use]
    pub fn chunking(&self) -> ChunkingKey {
        ChunkingKey(hash::derive_key(
            context::COLLECTION_CHUNKING,
            self.secret.expose(),
        ))
    }

    /// The key for this collection's thumbnails.
    #[must_use]
    pub fn thumb(&self) -> ThumbKey {
        ThumbKey(hash::derive_key(
            context::COLLECTION_THUMB,
            self.secret.expose(),
        ))
    }
}

impl RecoveryWrapKey {
    pub(crate) const fn new(secret: Secret32) -> Self {
        Self(secret)
    }

    /// Wraps the account key for storage on the server.
    ///
    /// # Errors
    ///
    /// Only if encryption itself fails, which can't happen for a key-sized input.
    pub fn wrap_account_key<R: CryptoRng>(
        &self,
        rng: &mut R,
        aad: &[u8],
        account_key: &AccountKey,
    ) -> Result<Vec<u8>, CryptoError> {
        wrap_symmetric(&self.0, rng, aad, account_key)
    }

    /// Unwraps the account key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Decrypt`] if the envelope was not made with this key and `aad`, was
    /// tampered with, or holds another kind of key.
    pub fn unwrap_account_key(&self, aad: &[u8], sealed: &[u8]) -> Result<AccountKey, CryptoError> {
        unwrap_symmetric(&self.0, aad, sealed)
    }
}

impl AccountKey {
    /// The key for account-level metadata (device names, collection configuration).
    #[must_use]
    pub fn meta(&self) -> AccountMetaKey {
        AccountMetaKey(hash::derive_key(
            context::ACCOUNT_META,
            self.secret.expose(),
        ))
    }

    /// Wraps `key` (a collection key, an account private key, or an older account key) for
    /// storage on the server. `aad` must bind the envelope to what it belongs to (IDs,
    /// epochs); the same `aad` is needed to unwrap.
    ///
    /// # Errors
    ///
    /// Only if encryption itself fails, which can't happen for a key-sized input.
    pub fn wrap<K: WrappableKey, R: CryptoRng>(
        &self,
        rng: &mut R,
        aad: &[u8],
        key: &K,
    ) -> Result<Vec<u8>, CryptoError> {
        wrap_symmetric(&self.secret, rng, aad, key)
    }

    /// Unwraps a key wrapped with [`AccountKey::wrap`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::Decrypt`] if the envelope was not made with this key and `aad`, was
    /// tampered with, or holds another kind of key than `K`.
    pub fn unwrap<K: WrappableKey>(&self, aad: &[u8], sealed: &[u8]) -> Result<K, CryptoError> {
        unwrap_symmetric(&self.secret, aad, sealed)
    }
}

/// The account's signing key: signs device certificates and device lists.
#[derive(Debug)]
pub struct AccountSigningKey(SigningKey);

impl AccountSigningKey {
    /// A new random key.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        Self(SigningKey::generate(rng))
    }

    /// Signs with this key.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.0
    }

    /// The public half.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl sealed::Wrappable for AccountSigningKey {
    const TYPE_TAG: u8 = 3;

    fn epoch(&self) -> u32 {
        0
    }

    fn material(&self) -> Zeroizing<[u8; 32]> {
        self.0.to_keystore_bytes()
    }

    fn from_material(_epoch: u32, material: &[u8; 32]) -> Result<Self, CryptoError> {
        Ok(Self(SigningKey::from_keystore_bytes(material)))
    }
}

impl WrappableKey for AccountSigningKey {}

/// The account's KEM key: lets other users wrap a shared collection's key to this account
/// (sharing, later).
#[derive(Debug)]
pub struct AccountKemKey(KemSecretKey);

impl AccountKemKey {
    /// A new random key.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        Self(KemSecretKey::generate(rng))
    }

    /// Unwraps with this key.
    #[must_use]
    pub const fn secret_key(&self) -> &KemSecretKey {
        &self.0
    }

    /// The public half, published so others can wrap keys to this account.
    #[must_use]
    pub fn public_key(&self) -> KemPublicKey {
        self.0.public_key()
    }
}

impl sealed::Wrappable for AccountKemKey {
    const TYPE_TAG: u8 = 4;

    fn epoch(&self) -> u32 {
        0
    }

    fn material(&self) -> Zeroizing<[u8; 32]> {
        self.0.to_keystore_bytes()
    }

    fn from_material(_epoch: u32, material: &[u8; 32]) -> Result<Self, CryptoError> {
        KemSecretKey::from_keystore_bytes(material).map(Self)
    }
}

impl WrappableKey for AccountKemKey {}

/// One device's own keys: a signing key (authentication, commits) and a KEM key (receives the
/// account key). Generated on the device; the private halves never leave its keystore.
#[derive(Debug)]
pub struct DeviceIdentity {
    signing: SigningKey,
    kem: KemSecretKey,
}

/// Length of [`DeviceIdentity::to_keystore_bytes`].
pub const DEVICE_IDENTITY_LEN: usize = 64;

impl DeviceIdentity {
    /// A new random identity.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        Self {
            signing: SigningKey::generate(rng),
            kem: KemSecretKey::generate(rng),
        }
    }

    /// Signs as this device.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// Unwraps keys sent to this device.
    #[must_use]
    pub const fn kem_secret_key(&self) -> &KemSecretKey {
        &self.kem
    }

    /// The device's public signing key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// The device's public KEM key.
    #[must_use]
    pub fn kem_public_key(&self) -> KemPublicKey {
        self.kem.public_key()
    }

    /// The private keys, for the OS keystore only.
    #[must_use]
    pub fn to_keystore_bytes(&self) -> Zeroizing<[u8; DEVICE_IDENTITY_LEN]> {
        let mut bytes = Zeroizing::new([0; DEVICE_IDENTITY_LEN]);
        bytes[..32].copy_from_slice(&*self.signing.to_keystore_bytes());
        bytes[32..].copy_from_slice(&*self.kem.to_keystore_bytes());
        bytes
    }

    /// Restores an identity from [`DeviceIdentity::to_keystore_bytes`].
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] if the bytes don't hold a valid identity.
    pub fn from_keystore_bytes(bytes: &[u8; DEVICE_IDENTITY_LEN]) -> Result<Self, CryptoError> {
        let mut signing = Zeroizing::new([0; 32]);
        let mut kem = Zeroizing::new([0; 32]);
        signing.copy_from_slice(&bytes[..32]);
        kem.copy_from_slice(&bytes[32..]);
        Ok(Self {
            signing: SigningKey::from_keystore_bytes(&signing),
            kem: KemSecretKey::from_keystore_bytes(&kem)?,
        })
    }
}

/// Length of an envelope's plaintext: type tag, epoch, key material.
const WRAPPED_LEN: usize = 1 + 4 + 32;

/// Encodes a key as an envelope plaintext: type tag ‖ epoch (little endian) ‖ material.
pub(crate) fn encode_wrapped<K: WrappableKey>(key: &K) -> Zeroizing<Vec<u8>> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(WRAPPED_LEN));
    plaintext.push(K::TYPE_TAG);
    plaintext.extend_from_slice(&sealed::Wrappable::epoch(key).to_le_bytes());
    plaintext.extend_from_slice(&*key.material());
    plaintext
}

/// Decodes an envelope plaintext, checking it holds a key of type `K`.
pub(crate) fn decode_wrapped<K: WrappableKey>(plaintext: &[u8]) -> Result<K, CryptoError> {
    let (&tag, rest) = plaintext.split_first().ok_or(CryptoError::Decrypt)?;
    let (epoch, material) = rest.split_first_chunk::<4>().ok_or(CryptoError::Decrypt)?;
    let mut key = Zeroizing::new([0; 32]);
    if tag != K::TYPE_TAG || material.len() != key.len() {
        return Err(CryptoError::Decrypt);
    }
    key.copy_from_slice(material);
    K::from_material(u32::from_le_bytes(*epoch), &key)
}

fn wrap_symmetric<K: WrappableKey, R: CryptoRng>(
    wrapping: &Secret32,
    rng: &mut R,
    aad: &[u8],
    key: &K,
) -> Result<Vec<u8>, CryptoError> {
    aead::seal_with(wrapping, rng, aad, &encode_wrapped(key))
}

fn unwrap_symmetric<K: WrappableKey>(
    wrapping: &Secret32,
    aad: &[u8],
    sealed: &[u8],
) -> Result<K, CryptoError> {
    decode_wrapped(&aead::open_with(wrapping, aad, sealed)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::SignContext;
    use crate::test_util::rng;

    #[test]
    fn derived_keys_are_distinct_and_deterministic() {
        let collection = CollectionKey::generate(&mut rng(1), 0);
        let secrets = [
            *sealed::SymmetricKey::secret(&collection.meta()).expose(),
            *sealed::SymmetricKey::secret(&collection.data()).expose(),
            *sealed::SymmetricKey::secret(&collection.id()).expose(),
            *sealed::SymmetricKey::secret(&collection.chunking()).expose(),
            *sealed::SymmetricKey::secret(&collection.thumb()).expose(),
            *collection.secret.expose(),
        ];
        for (i, a) in secrets.iter().enumerate() {
            for b in &secrets[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(
            sealed::SymmetricKey::secret(&collection.meta()).expose(),
            sealed::SymmetricKey::secret(&collection.meta()).expose()
        );
    }

    #[test]
    fn account_meta_key_is_derived_and_encrypts() {
        let mut rng = rng(7);
        let account = AccountKey::generate(&mut rng, 0);
        let sealed = aead::seal(&account.meta(), &mut rng, b"name", b"laptop").unwrap();
        assert_eq!(
            &*aead::open(&account.meta(), b"name", &sealed).unwrap(),
            b"laptop"
        );
        assert_ne!(
            sealed::SymmetricKey::secret(&account.meta()).expose(),
            account.secret.expose()
        );
        assert_eq!(format!("{:?}", account.meta()), "AccountMetaKey(..)");
    }

    #[test]
    fn debug_never_shows_key_bytes() {
        let mut rng = rng(2);
        let collection = CollectionKey::generate(&mut rng, 7);
        assert_eq!(format!("{collection:?}"), "CollectionKey(epoch 7, ..)");
        assert_eq!(format!("{:?}", collection.meta()), "MetaKey(..)");
        assert_eq!(format!("{:?}", collection.data()), "DataKey(..)");
        assert_eq!(format!("{:?}", collection.id()), "IdKey(..)");
        assert_eq!(format!("{:?}", collection.chunking()), "ChunkingKey(..)");
        assert_eq!(format!("{:?}", collection.thumb()), "ThumbKey(..)");
        let account = AccountKey::generate(&mut rng, 3);
        assert_eq!(format!("{account:?}"), "AccountKey(epoch 3, ..)");
        let identity = DeviceIdentity::generate(&mut rng);
        let text = format!("{identity:?}");
        assert!(text.starts_with("DeviceIdentity"), "{text}");
        assert!(
            text.contains("SigningKey(..)") && text.contains("KemSecretKey(..)"),
            "{text}"
        );
    }

    #[test]
    fn account_key_wraps_every_wrappable_type() {
        let mut rng = rng(3);
        let account = AccountKey::generate(&mut rng, 2);

        let collection = CollectionKey::generate(&mut rng, 5);
        let sealed = account.wrap(&mut rng, b"ck", &collection).unwrap();
        let back: CollectionKey = account.unwrap(b"ck", &sealed).unwrap();
        assert_eq!(back.epoch(), 5);
        assert_eq!(back.secret.expose(), collection.secret.expose());

        let older = AccountKey::generate(&mut rng, 1);
        let sealed = account.wrap(&mut rng, b"ak", &older).unwrap();
        let back: AccountKey = account.unwrap(b"ak", &sealed).unwrap();
        assert_eq!(
            (back.epoch(), back.secret.expose()),
            (1, older.secret.expose())
        );

        let signing = AccountSigningKey::generate(&mut rng);
        let sealed = account.wrap(&mut rng, b"ask", &signing).unwrap();
        let back: AccountSigningKey = account.unwrap(b"ask", &sealed).unwrap();
        assert_eq!(back.verifying_key(), signing.verifying_key());
        let signature = back.signing_key().sign(SignContext::DeviceList, b"list");
        assert!(
            signing
                .verifying_key()
                .verify(SignContext::DeviceList, b"list", &signature)
                .is_ok()
        );

        let kem = AccountKemKey::generate(&mut rng);
        let sealed = account.wrap(&mut rng, b"akk", &kem).unwrap();
        let back: AccountKemKey = account.unwrap(b"akk", &sealed).unwrap();
        assert_eq!(back.public_key(), kem.public_key());
        assert_eq!(back.secret_key().public_key(), kem.public_key());
    }

    #[test]
    fn unwrapping_as_another_type_or_with_another_key_fails() {
        let mut rng = rng(4);
        let account = AccountKey::generate(&mut rng, 0);
        let collection = CollectionKey::generate(&mut rng, 0);
        let sealed = account.wrap(&mut rng, b"aad", &collection).unwrap();
        assert!(matches!(
            account.unwrap::<AccountKey>(b"aad", &sealed),
            Err(CryptoError::Decrypt)
        ));
        assert!(matches!(
            account.unwrap::<CollectionKey>(b"other", &sealed),
            Err(CryptoError::Decrypt)
        ));
        let stranger = AccountKey::generate(&mut rng, 0);
        assert!(matches!(
            stranger.unwrap::<CollectionKey>(b"aad", &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn malformed_envelope_plaintexts_are_rejected() {
        assert!(decode_wrapped::<AccountKey>(&[]).is_err());
        assert!(decode_wrapped::<AccountKey>(&[1, 0, 0]).is_err());
        assert!(decode_wrapped::<AccountKey>(&[1, 0, 0, 0, 0, 9]).is_err());
        let mut long = vec![1, 0, 0, 0, 0];
        long.extend_from_slice(&[0; 33]);
        assert!(decode_wrapped::<AccountKey>(&long).is_err());
        let mut exact = vec![1, 9, 0, 0, 0];
        exact.extend_from_slice(&[5; 32]);
        let key = decode_wrapped::<AccountKey>(&exact).unwrap();
        assert_eq!((key.epoch(), key.secret.expose()), (9, &[5; 32]));
    }

    #[test]
    fn recovery_wrap_key_wraps_the_account_key() {
        let mut rng = rng(5);
        let wrap = RecoveryWrapKey::new(Secret32::random(&mut rng));
        let account = AccountKey::generate(&mut rng, 4);
        let sealed = wrap.wrap_account_key(&mut rng, b"rec", &account).unwrap();
        let back = wrap.unwrap_account_key(b"rec", &sealed).unwrap();
        assert_eq!(
            (back.epoch(), back.secret.expose()),
            (4, account.secret.expose())
        );
        assert!(wrap.unwrap_account_key(b"x", &sealed).is_err());
    }

    #[test]
    fn device_identity_survives_the_keystore() {
        let identity = DeviceIdentity::generate(&mut rng(6));
        let bytes = identity.to_keystore_bytes();
        let back = DeviceIdentity::from_keystore_bytes(&bytes).unwrap();
        assert_eq!(back.verifying_key(), identity.verifying_key());
        assert_eq!(back.kem_public_key(), identity.kem_public_key());
        assert_eq!(
            back.kem_secret_key().public_key(),
            identity.kem_secret_key().public_key()
        );
        let signature = back.signing_key().sign(SignContext::Commit, b"c");
        assert!(
            identity
                .verifying_key()
                .verify(SignContext::Commit, b"c", &signature)
                .is_ok()
        );
    }
}
