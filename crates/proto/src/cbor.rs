//! CBOR encodings for types from `oxisoft-drive-crypto`, used through
//! `#[cbor(with = "…")]`: each is stored as a CBOR byte string of its fixed or serialised
//! form, and decoding validates it (for example, that a public key is a valid point).

use minicbor::decode::{Decoder, Error as DecodeError};
use minicbor::encode::{Encoder, Error as EncodeError, Write};

/// Reads a byte string of exactly `N` bytes.
pub(crate) fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], DecodeError> {
    <[u8; N]>::try_from(d.bytes()?).map_err(|_| DecodeError::message(format!("expected {N} bytes")))
}

pub(crate) mod verifying_key {
    use super::{DecodeError, Decoder, EncodeError, Encoder, Write, fixed};
    use oxisoft_drive_crypto::sign::VerifyingKey;

    pub(crate) fn encode<C, W: Write>(
        key: &VerifyingKey,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        e.bytes(&key.to_bytes())?;
        Ok(())
    }

    pub(crate) fn decode<C>(d: &mut Decoder<'_>, _: &mut C) -> Result<VerifyingKey, DecodeError> {
        VerifyingKey::from_bytes(&fixed(d)?).map_err(|_| DecodeError::message("invalid key"))
    }
}

pub(crate) mod signature {
    use super::{DecodeError, Decoder, EncodeError, Encoder, Write, fixed};
    use oxisoft_drive_crypto::sign::Signature;

    pub(crate) fn encode<C, W: Write>(
        signature: &Signature,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        e.bytes(&signature.to_bytes())?;
        Ok(())
    }

    pub(crate) fn decode<C>(d: &mut Decoder<'_>, _: &mut C) -> Result<Signature, DecodeError> {
        Ok(Signature::from_bytes(fixed(d)?))
    }
}

pub(crate) mod kem_key {
    use super::{DecodeError, Decoder, EncodeError, Encoder, Write};
    use oxisoft_drive_crypto::kem::KemPublicKey;

    pub(crate) fn encode<C, W: Write>(
        key: &KemPublicKey,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        e.bytes(&key.to_bytes())?;
        Ok(())
    }

    pub(crate) fn decode<C>(d: &mut Decoder<'_>, _: &mut C) -> Result<KemPublicKey, DecodeError> {
        KemPublicKey::from_bytes(d.bytes()?).map_err(|_| DecodeError::message("invalid KEM key"))
    }
}

/// Encodes any `minicbor` value to a vector. Writing to a `Vec` can't fail.
pub(crate) fn to_vec<T: minicbor::Encode<()>>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = minicbor::encode(value, &mut out);
    out
}
