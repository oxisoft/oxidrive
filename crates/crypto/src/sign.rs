//! Ed25519 signatures, always bound to a [`SignContext`].
//!
//! The signed bytes are `context ‖ 0x00 ‖ message`, so a signature made for one purpose (say,
//! a commit) can never be passed off as another (say, a device certificate). Verification uses
//! Ed25519's strict mode, which rejects malleable signatures and weak public keys.

use std::fmt;

use ed25519_dalek::{Signer, ed25519::signature::Error as DalekError};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::context;

/// Public key length in bytes.
pub const VERIFYING_KEY_LEN: usize = 32;
/// Signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// What a signature is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignContext {
    /// A device answering the server's authentication challenge.
    AuthChallenge,
    /// The account certifying a device.
    DeviceCertificate,
    /// The account's list of trusted devices.
    DeviceList,
    /// A commit in a collection's change log.
    Commit,
    /// A device attesting the newest head it has seen.
    HeadAttestation,
    /// The account publishing its KEM public key.
    AccountKemKey,
}

impl SignContext {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AuthChallenge => context::SIGN_AUTH_CHALLENGE,
            Self::DeviceCertificate => context::SIGN_DEVICE_CERTIFICATE,
            Self::DeviceList => context::SIGN_DEVICE_LIST,
            Self::Commit => context::SIGN_COMMIT,
            Self::HeadAttestation => context::SIGN_HEAD_ATTESTATION,
            Self::AccountKemKey => context::SIGN_ACCOUNT_KEM_KEY,
        }
    }

    fn frame(self, message: &[u8]) -> Vec<u8> {
        let context = self.as_str().as_bytes();
        let mut framed = Vec::with_capacity(context.len() + 1 + message.len());
        framed.extend_from_slice(context);
        framed.push(0);
        framed.extend_from_slice(message);
        framed
    }
}

/// An Ed25519 private key. Wiped on drop.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    /// A new random key.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        Self(ed25519_dalek::SigningKey::generate(rng))
    }

    /// Signs `message` for the given purpose.
    #[must_use]
    pub fn sign(&self, context: SignContext, message: &[u8]) -> Signature {
        Signature(self.0.sign(&context.frame(message)).to_bytes())
    }

    /// The public half.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    pub(crate) fn to_keystore_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub(crate) fn from_keystore_bytes(bytes: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(bytes))
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Reads a stored public key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] if the bytes are not a valid curve point.
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Result<Self, CryptoError> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// The stored form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Checks that `signature` was made by this key over `message` for this purpose.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidSignature`] if it wasn't.
    pub fn verify(
        &self,
        context: SignContext,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), CryptoError> {
        let signature = ed25519_dalek::Signature::from_bytes(&signature.0);
        self.0
            .verify_strict(&context.frame(message), &signature)
            .map_err(|_: DalekError| CryptoError::InvalidSignature)
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey(")?;
        for byte in self.0.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// An Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Wraps stored bytes. Validity is only known after [`VerifyingKey::verify`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// The stored form.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signature(")?;
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{from_hex, from_hex_array, rng, to_hex};
    use proptest::prelude::*;

    /// RFC 8032 §7.1, tests 1–3: secret key, public key, message, signature.
    const RFC_8032: [(&str, &str, &str, &str); 3] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc4 4449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a 0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a 84877f1eb8e5d974d873e06522490155
             5fb8821590a33bacc61e39701cf9b46b d25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f 5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc 9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540 a2b27b5416503f8fb3762223ebdb69da
             085ac1e43e15996e458f3613d0f11d8c 387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b1 66d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f058 0816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a3 0ce548a284743a445e3680d7db5ac3ac
             18ff9b538d16f290ae67f760984dc659 4a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];

    /// Our keys are plain Ed25519: the RFC's secret keys give the RFC's public keys, and the
    /// underlying signature over the unframed message matches the RFC.
    #[test]
    fn keys_and_raw_signatures_match_rfc_8032() {
        for (secret, public, message, signature) in RFC_8032 {
            let key = SigningKey::from_keystore_bytes(&from_hex_array::<32>(secret));
            assert_eq!(key.verifying_key().to_bytes(), from_hex_array::<32>(public));
            assert_eq!(
                key.0.sign(&from_hex(message)).to_bytes(),
                from_hex_array::<64>(signature)
            );
        }
    }

    #[test]
    fn contexts_separate_signatures() {
        let key = SigningKey::generate(&mut rng(50));
        let public = key.verifying_key();
        let signature = key.sign(SignContext::Commit, b"message");
        assert_eq!(
            public.verify(SignContext::Commit, b"message", &signature),
            Ok(())
        );
        for other in [
            SignContext::AuthChallenge,
            SignContext::DeviceCertificate,
            SignContext::DeviceList,
            SignContext::HeadAttestation,
            SignContext::AccountKemKey,
        ] {
            assert_eq!(
                public.verify(other, b"message", &signature),
                Err(CryptoError::InvalidSignature)
            );
        }
    }

    #[test]
    fn keys_and_signatures_round_trip_through_bytes() {
        let key = SigningKey::generate(&mut rng(51));
        let public = VerifyingKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
        let signature = Signature::from_bytes(key.sign(SignContext::DeviceList, b"x").to_bytes());
        assert!(
            public
                .verify(SignContext::DeviceList, b"x", &signature)
                .is_ok()
        );
        let restored = SigningKey::from_keystore_bytes(&key.to_keystore_bytes());
        assert_eq!(restored.verifying_key(), public);
    }

    #[test]
    fn invalid_public_keys_are_rejected() {
        // Not a valid compressed Edwards point (y = 2 has no x on the curve).
        let mut bytes = [0; 32];
        bytes[0] = 2;
        assert_eq!(
            VerifyingKey::from_bytes(&bytes),
            Err(CryptoError::InvalidKey)
        );
    }

    #[test]
    fn debug_shows_public_data_only() {
        let key = SigningKey::generate(&mut rng(52));
        assert_eq!(format!("{key:?}"), "SigningKey(..)");
        let public = key.verifying_key();
        let hex = to_hex(&public.to_bytes());
        assert_eq!(format!("{public:?}"), format!("VerifyingKey({hex})"));
        let signature = key.sign(SignContext::Commit, b"");
        let prefix = to_hex(&signature.to_bytes()[..8]);
        assert_eq!(format!("{signature:?}"), format!("Signature({prefix}..)"));
    }

    proptest! {
        #[test]
        fn tampering_is_detected(message in prop::collection::vec(any::<u8>(), 0..512),
                                 flip in any::<prop::sample::Index>(),
                                 bit in 0u8..8) {
            let key = SigningKey::generate(&mut rng(53));
            let signature = key.sign(SignContext::Commit, &message);
            let public = key.verifying_key();
            prop_assert!(public.verify(SignContext::Commit, &message, &signature).is_ok());

            let mut bad_signature = signature.to_bytes();
            let i = flip.index(SIGNATURE_LEN);
            bad_signature[i] ^= 1 << bit;
            prop_assert!(public
                .verify(SignContext::Commit, &message, &Signature::from_bytes(bad_signature))
                .is_err());

            if !message.is_empty() {
                let mut bad_message = message.clone();
                let i = flip.index(bad_message.len());
                bad_message[i] ^= 1 << bit;
                prop_assert!(public.verify(SignContext::Commit, &bad_message, &signature).is_err());
            }
        }
    }
}
