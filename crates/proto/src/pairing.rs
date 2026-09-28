//! Authentication and pairing messages (server API §2, §4.1).

use std::fmt;

use minicbor::decode::{Decoder, Error as DecodeError};
use minicbor::encode::{Encoder, Error as EncodeError, Write};
use minicbor::{Decode, Encode};
use oxisoft_drive_crypto::hash;
use oxisoft_drive_crypto::kem::KemPublicKey;
use oxisoft_drive_crypto::pairing::{PAIRING_SECRET_LEN, PairingSecret};
use oxisoft_drive_crypto::sign::VerifyingKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cbor::{self, fixed};
use crate::{AccountId, DeviceId, KeysHash, PairingId, ProtoError};

/// Pairing code format version written by this code.
pub const PAIRING_FORMAT: u8 = 1;

const AUTH_LABEL: &[u8] = b"oxidrive-auth-v1";
const KEYS_LABEL: &[u8] = b"oxidrive pairing keys v1";
const APPROVAL_LABEL: &[u8] = b"oxidrive pairing approval v1";

/// The bytes a device signs to answer the server's challenge: the label, the server's
/// origin (so the answer can't be replayed to another server), the nonce and the device.
#[must_use]
pub fn auth_message(origin: &str, nonce: &[u8; 32], device: DeviceId) -> Vec<u8> {
    let origin_len = u64::try_from(origin.len()).unwrap_or(u64::MAX);
    [
        AUTH_LABEL,
        &origin_len.to_le_bytes(),
        origin.as_bytes(),
        nonce,
        device.as_bytes(),
    ]
    .concat()
}

/// Hash of a new device's public keys, carried in the pairing code so the approving device
/// can check the server didn't swap them.
#[must_use]
pub fn keys_hash(verifying_key: &VerifyingKey, kem_key: &KemPublicKey) -> KeysHash {
    KeysHash(hash::hash(
        &[KEYS_LABEL, &verifying_key.to_bytes(), &kem_key.to_bytes()].concat(),
    ))
}

/// The data the approving device MACs with the pairing secret: which account the new device
/// is joining, and that account's signing key.
#[must_use]
pub fn approval_mac_data(account: AccountId, account_key: &VerifyingKey) -> Vec<u8> {
    [APPROVAL_LABEL, account.as_bytes(), &account_key.to_bytes()].concat()
}

/// What the new device shows as a QR code (or, on a headless server, as a typed code).
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct PairingCode {
    /// Format version; [`PAIRING_FORMAT`].
    #[n(0)]
    pub format: u8,
    /// The server's base URL.
    #[n(1)]
    pub server: String,
    /// The pending pairing on the server.
    #[n(2)]
    pub pairing: PairingId,
    /// [`keys_hash`] of the new device's public keys.
    #[n(3)]
    pub keys_hash: KeysHash,
    #[n(4)]
    secret: SecretBytes,
}

impl PairingCode {
    /// A code for `pairing`, carrying `secret`.
    #[must_use]
    pub fn new(
        server: String,
        pairing: PairingId,
        keys_hash: KeysHash,
        secret: &PairingSecret,
    ) -> Self {
        Self {
            format: PAIRING_FORMAT,
            server,
            pairing,
            keys_hash,
            secret: SecretBytes(*secret.to_bytes()),
        }
    }

    /// The pairing secret.
    #[must_use]
    pub const fn secret(&self) -> PairingSecret {
        PairingSecret::from_bytes(self.secret.0)
    }

    /// The bytes to put into the QR code.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::to_vec(self)
    }

    /// Reads a scanned code.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Decode`] or [`ProtoError::UnsupportedFormat`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        let code: Self = minicbor::decode(bytes)?;
        if code.format == PAIRING_FORMAT {
            Ok(code)
        } else {
            Err(ProtoError::UnsupportedFormat(code.format))
        }
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCode")
            .field("server", &self.server)
            .field("pairing", &self.pairing)
            .field("keys_hash", &self.keys_hash)
            .finish_non_exhaustive()
    }
}

/// The secret inside a pairing code; wiped on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
struct SecretBytes([u8; PAIRING_SECRET_LEN]);

impl<C> Encode<C> for SecretBytes {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), EncodeError<W::Error>> {
        e.bytes(&self.0)?;
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for SecretBytes {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        fixed(d).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::rng;
    use oxisoft_drive_crypto::keys::{AccountSigningKey, DeviceIdentity};

    #[test]
    fn auth_messages_bind_origin_nonce_and_device() {
        let device = DeviceId::from_bytes([1; 16]);
        let base = auth_message("https://a.example", &[7; 32], device);
        assert_ne!(base, auth_message("https://b.example", &[7; 32], device));
        assert_ne!(base, auth_message("https://a.example", &[8; 32], device));
        assert_ne!(
            base,
            auth_message("https://a.example", &[7; 32], DeviceId::from_bytes([2; 16]))
        );
        // The length prefix keeps origin and nonce apart.
        assert_ne!(
            auth_message("ab", &[0; 32], device),
            auth_message("a", &[0; 32], device)
        );
    }

    #[test]
    fn pairing_codes_round_trip_and_hide_the_secret() {
        let mut rng = rng(1);
        let identity = DeviceIdentity::generate(&mut rng);
        let secret = PairingSecret::generate(&mut rng);
        let keys = keys_hash(&identity.verifying_key(), &identity.kem_public_key());
        let code = PairingCode::new(
            "https://drive.example".into(),
            PairingId::random(&mut rng),
            keys,
            &secret,
        );
        let back = PairingCode::from_bytes(&code.to_bytes()).unwrap();
        assert_eq!(back, code);

        let account = AccountSigningKey::generate(&mut rng);
        let data = approval_mac_data(AccountId::from_bytes([3; 16]), &account.verifying_key());
        let mac = secret.mac(&data);
        assert!(back.secret().verify(&data, &mac).is_ok());

        let text = format!("{code:?}");
        assert!(
            text.contains("drive.example") && !text.contains("secret"),
            "{text}"
        );

        let other = DeviceIdentity::generate(&mut rng);
        assert_ne!(
            keys,
            keys_hash(&other.verifying_key(), &identity.kem_public_key())
        );

        let future = PairingCode { format: 2, ..code };
        assert_eq!(
            PairingCode::from_bytes(&future.to_bytes()),
            Err(ProtoError::UnsupportedFormat(2))
        );
        assert!(matches!(
            PairingCode::from_bytes(&[0xff]),
            Err(ProtoError::Decode(_))
        ));
    }
}
