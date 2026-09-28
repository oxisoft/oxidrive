//! Signed objects: the exact bytes that were signed, plus the signature.
//!
//! Signing encodes the value once and keeps those bytes. Verification checks the signature
//! over the kept bytes and only then decodes them, so no canonical encoding is needed and a
//! re-encoding can never break a signature.

use std::fmt;
use std::marker::PhantomData;

use minicbor::{Decode, Encode};
use oxisoft_drive_crypto::hash::{self, Digest};
use oxisoft_drive_crypto::sign::{SignContext, Signature, SigningKey, VerifyingKey};

use crate::ProtoError;
use crate::cbor;

/// A type that is signed for one fixed purpose.
pub trait Signable: Encode<()> + for<'b> Decode<'b, ()> {
    /// What the signature is for.
    const CONTEXT: SignContext;
}

/// A `T` as signed bytes.
#[derive(Encode, Decode)]
#[cbor(map)]
pub struct Signed<T> {
    #[cbor(n(0), with = "minicbor::bytes")]
    bytes: Vec<u8>,
    #[cbor(n(1), with = "cbor::signature")]
    signature: Signature,
    #[cbor(skip)]
    kind: PhantomData<fn() -> T>,
}

impl<T: Signable> Signed<T> {
    /// Encodes and signs `value`.
    #[must_use]
    pub fn sign(key: &SigningKey, value: &T) -> Self {
        let bytes = cbor::to_vec(value);
        let signature = key.sign(T::CONTEXT, &bytes);
        Self {
            bytes,
            signature,
            kind: PhantomData,
        }
    }

    /// Checks the signature, then decodes.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Crypto`] if the signature is not `key`'s, [`ProtoError::Decode`] if the
    /// signed bytes don't decode.
    pub fn verify(&self, key: &VerifyingKey) -> Result<T, ProtoError> {
        key.verify(T::CONTEXT, &self.bytes, &self.signature)?;
        Ok(minicbor::decode(&self.bytes)?)
    }

    /// Decodes **without** checking the signature, only to find out who claims to have signed
    /// (for example, which device key to verify a commit with). Never act on the result
    /// before [`Signed::verify`] succeeds.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Decode`] if the bytes don't decode.
    pub fn decode_unverified(&self) -> Result<T, ProtoError> {
        Ok(minicbor::decode(&self.bytes)?)
    }
}

impl<T> Signed<T> {
    /// BLAKE3 of the signed bytes followed by the signature: identifies this exact signed
    /// object (used for commit links and certificate references).
    #[must_use]
    pub fn hash(&self) -> Digest {
        hash::hash(&[self.bytes.as_slice(), &self.signature.to_bytes()].concat())
    }

    /// The signed bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<T> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            signature: self.signature,
            kind: PhantomData,
        }
    }
}

impl<T> PartialEq for Signed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes && self.signature == other.signature
    }
}

impl<T> Eq for Signed<T> {}

impl<T> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signed<{}>({} bytes, {:?})",
            std::any::type_name::<T>()
                .rsplit("::")
                .next()
                .unwrap_or("?"),
            self.bytes.len(),
            self.signature
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::rng;
    use oxisoft_drive_crypto::CryptoError;

    #[derive(Debug, PartialEq, Encode, Decode)]
    #[cbor(map)]
    struct Note {
        #[n(0)]
        text: String,
    }

    impl Signable for Note {
        const CONTEXT: SignContext = SignContext::HeadAttestation;
    }

    fn note(text: &str) -> Note {
        Note { text: text.into() }
    }

    #[test]
    fn verifies_and_decodes() {
        let key = SigningKey::generate(&mut rng(1));
        let signed = Signed::sign(&key, &note("hello"));
        assert_eq!(signed.verify(&key.verifying_key()).unwrap(), note("hello"));
        assert_eq!(signed.decode_unverified().unwrap(), note("hello"));
        let bytes = minicbor::to_vec(&signed).unwrap();
        let back: Signed<Note> = minicbor::decode(&bytes).unwrap();
        assert_eq!(back, signed);
        assert_eq!(back.hash(), signed.hash());
        assert_eq!(back.clone().bytes(), signed.bytes());
        let text = format!("{signed:?}");
        assert!(text.starts_with("Signed<Note>("), "{text}");
    }

    #[test]
    fn any_change_fails() {
        let key = SigningKey::generate(&mut rng(2));
        let signed = Signed::sign(&key, &note("hello"));
        let other = SigningKey::generate(&mut rng(3));
        assert_eq!(
            signed.verify(&other.verifying_key()),
            Err(ProtoError::Crypto(CryptoError::InvalidSignature))
        );
        for i in 0..signed.bytes.len() {
            let mut tampered = signed.clone();
            tampered.bytes[i] ^= 1;
            assert!(tampered.verify(&key.verifying_key()).is_err(), "byte {i}");
            assert_ne!(tampered.hash(), signed.hash());
        }
    }

    #[test]
    fn signed_garbage_is_a_decode_error() {
        let key = SigningKey::generate(&mut rng(4));
        let garbage = Signed::<Note> {
            bytes: vec![0xff, 0x00],
            signature: key.sign(Note::CONTEXT, &[0xff, 0x00]),
            kind: PhantomData,
        };
        assert!(matches!(
            garbage.verify(&key.verifying_key()),
            Err(ProtoError::Decode(_))
        ));
        assert!(matches!(
            garbage.decode_unverified(),
            Err(ProtoError::Decode(_))
        ));
    }
}
