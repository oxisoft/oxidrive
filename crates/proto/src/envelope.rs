//! Key envelopes: wrapped keys as the server stores them (crypto design §3).
//!
//! The wrapping itself is done by `oxisoft-drive-crypto`; this module fixes the data around
//! it and, importantly, the associated data every wrap and unwrap must use, so an envelope
//! can't be presented as belonging to another account, epoch, device or collection.

use minicbor::{Decode, Encode};

use crate::{AccountId, CollectionId, DeviceId};

const AAD_LABEL: &[u8] = b"oxidrive envelope v1";

/// What an envelope holds and how it's wrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
#[cbor(index_only)]
pub enum EnvelopeKind {
    /// The account key, wrapped to a device's KEM key.
    #[n(0)]
    AccountKeyToDevice,
    /// The account key, wrapped with the recovery key.
    #[n(1)]
    AccountKeyToRecovery,
    /// The previous epoch's account key, wrapped with the current one.
    #[n(2)]
    OlderAccountKey,
    /// A collection key, wrapped with the account key.
    #[n(3)]
    CollectionKey,
    /// The account signing key, wrapped with the account key.
    #[n(4)]
    AccountSigningKey,
    /// The account KEM key, wrapped with the account key.
    #[n(5)]
    AccountKemKey,
}

impl EnvelopeKind {
    const fn code(self) -> u8 {
        match self {
            Self::AccountKeyToDevice => 0,
            Self::AccountKeyToRecovery => 1,
            Self::OlderAccountKey => 2,
            Self::CollectionKey => 3,
            Self::AccountSigningKey => 4,
            Self::AccountKemKey => 5,
        }
    }
}

/// A wrapped key.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct Envelope {
    /// What it holds.
    #[n(0)]
    pub kind: EnvelopeKind,
    /// The epoch of the wrapped key.
    #[n(1)]
    pub epoch: u32,
    /// The recipient device, for [`EnvelopeKind::AccountKeyToDevice`].
    #[n(2)]
    pub device: Option<DeviceId>,
    /// The collection, for [`EnvelopeKind::CollectionKey`].
    #[n(3)]
    pub collection: Option<CollectionId>,
    /// The wrapped key.
    #[cbor(n(4), with = "minicbor::bytes")]
    pub wrapped: Vec<u8>,
}

impl Envelope {
    /// The associated data to wrap and unwrap this envelope with.
    #[must_use]
    pub fn aad(&self, account: AccountId) -> Vec<u8> {
        let mut aad = [AAD_LABEL, account.as_bytes()].concat();
        aad.push(self.kind.code());
        aad.extend_from_slice(&self.epoch.to_le_bytes());
        push_optional(&mut aad, self.device.as_ref().map(DeviceId::as_bytes));
        push_optional(
            &mut aad,
            self.collection.as_ref().map(CollectionId::as_bytes),
        );
        aad
    }
}

fn push_optional(aad: &mut Vec<u8>, id: Option<&[u8; 16]>) {
    match id {
        Some(id) => {
            aad.push(1);
            aad.extend_from_slice(id);
        }
        None => aad.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::rng;
    use oxisoft_drive_crypto::keys::{AccountKey, CollectionKey};

    fn envelope(kind: EnvelopeKind) -> Envelope {
        Envelope {
            kind,
            epoch: 1,
            device: None,
            collection: Some(CollectionId::from_bytes([2; 16])),
            wrapped: vec![1, 2, 3],
        }
    }

    #[test]
    fn aad_binds_every_field() {
        let account = AccountId::from_bytes([1; 16]);
        let base = envelope(EnvelopeKind::CollectionKey);
        let variants = [
            Envelope {
                epoch: 2,
                ..base.clone()
            },
            Envelope {
                collection: None,
                ..base.clone()
            },
            Envelope {
                collection: Some(CollectionId::from_bytes([3; 16])),
                ..base.clone()
            },
            Envelope {
                device: Some(DeviceId::from_bytes([2; 16])),
                collection: None,
                ..base.clone()
            },
            envelope(EnvelopeKind::AccountKeyToDevice),
            envelope(EnvelopeKind::AccountKeyToRecovery),
            envelope(EnvelopeKind::OlderAccountKey),
            envelope(EnvelopeKind::AccountSigningKey),
            envelope(EnvelopeKind::AccountKemKey),
        ];
        let aad = base.aad(account);
        assert_ne!(aad, base.aad(AccountId::from_bytes([9; 16])));
        let mut all = vec![aad];
        for variant in variants {
            let other = variant.aad(account);
            assert!(!all.contains(&other), "{variant:?}");
            all.push(other);
        }
        // The wrapped bytes are not part of the binding.
        assert_eq!(
            Envelope {
                wrapped: vec![],
                ..base.clone()
            }
            .aad(account),
            base.aad(account)
        );
    }

    #[test]
    fn envelopes_round_trip_and_unwrap_with_their_aad() {
        let mut rng = rng(1);
        let account_id = AccountId::from_bytes([1; 16]);
        let account = AccountKey::generate(&mut rng, 0);
        let collection = CollectionKey::generate(&mut rng, 1);
        let mut envelope = envelope(EnvelopeKind::CollectionKey);
        envelope.wrapped = account
            .wrap(&mut rng, &envelope.aad(account_id), &collection)
            .unwrap();
        let bytes = minicbor::to_vec(&envelope).unwrap();
        let back: Envelope = minicbor::decode(&bytes).unwrap();
        assert_eq!(back, envelope);
        let unwrapped: CollectionKey = account
            .unwrap(&back.aad(account_id), &back.wrapped)
            .unwrap();
        assert_eq!(unwrapped.epoch(), 1);
        let moved = Envelope { epoch: 7, ..back };
        assert!(
            account
                .unwrap::<CollectionKey>(&moved.aad(account_id), &moved.wrapped)
                .is_err()
        );
    }
}
