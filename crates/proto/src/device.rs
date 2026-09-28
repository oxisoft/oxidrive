//! Device certificates and lists, the account's KEM key publication, and head attestations
//! (crypto design §5, §8).

use minicbor::{Decode, Encode};
use oxisoft_drive_crypto::CryptoRng;
use oxisoft_drive_crypto::aead;
use oxisoft_drive_crypto::kem::KemPublicKey;
use oxisoft_drive_crypto::keys::AccountMetaKey;
use oxisoft_drive_crypto::sign::{SignContext, VerifyingKey};

use crate::cbor;
use crate::signed::{Signable, Signed};
use crate::{AccountId, CertificateHash, CollectionId, CommitHash, DeviceId, ProtoError, Seq};

/// Format version of device certificates, lists, publications and attestations.
pub const DEVICE_FORMAT: u8 = 1;

const NAME_AAD_LABEL: &[u8] = b"oxidrive device name v1";

/// The account's statement that a device belongs to it. Signed by the account signing key.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct DeviceCertificate {
    /// Format version; [`DEVICE_FORMAT`].
    #[n(0)]
    pub format: u8,
    /// The account.
    #[n(1)]
    pub account: AccountId,
    /// The device; must equal [`DeviceId::from_key`] of `verifying_key`.
    #[n(2)]
    pub device: DeviceId,
    /// The device's public signing key.
    #[cbor(n(3), with = "cbor::verifying_key")]
    pub verifying_key: VerifyingKey,
    /// The device's public KEM key.
    #[cbor(n(4), with = "cbor::kem_key")]
    pub kem_key: KemPublicKey,
    /// When the device was added, milliseconds since the Unix epoch.
    #[n(5)]
    pub created_ms: u64,
    /// The device's display name, sealed with the account meta key (decision P3).
    #[cbor(n(6), with = "minicbor::bytes")]
    pub sealed_name: Vec<u8>,
}

impl Signable for DeviceCertificate {
    const CONTEXT: SignContext = SignContext::DeviceCertificate;
}

impl DeviceCertificate {
    /// A certificate for a device's public keys, with its display name sealed.
    ///
    /// # Errors
    ///
    /// Only if sealing the name fails, which can't happen for names under 256 GiB.
    pub fn new<R: CryptoRng>(
        account: AccountId,
        keys: (VerifyingKey, KemPublicKey),
        name: &str,
        meta: &AccountMetaKey,
        rng: &mut R,
        created_ms: u64,
    ) -> Result<Self, ProtoError> {
        let (verifying_key, kem_key) = keys;
        let device = DeviceId::from_key(&verifying_key);
        let sealed_name = aead::seal(meta, rng, &name_aad(account, device), name.as_bytes())?;
        Ok(Self {
            format: DEVICE_FORMAT,
            account,
            device,
            verifying_key,
            kem_key,
            created_ms,
            sealed_name,
        })
    }

    /// The display name.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Crypto`] with the wrong key or a moved name, [`ProtoError::Decode`] if
    /// the name isn't UTF-8.
    pub fn name(&self, meta: &AccountMetaKey) -> Result<String, ProtoError> {
        let bytes = aead::open(
            meta,
            &name_aad(self.account, self.device),
            &self.sealed_name,
        )?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| ProtoError::Decode("name is not UTF-8".into()))
    }

    /// Verifies a signed certificate against the account signing key and checks it is
    /// consistent: known format, right account, device ID matching its key.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Crypto`] for a bad signature, [`ProtoError::UnsupportedFormat`], or
    /// [`ProtoError::Inconsistent`].
    pub fn verify(
        signed: &Signed<Self>,
        account: AccountId,
        account_key: &VerifyingKey,
    ) -> Result<Self, ProtoError> {
        let certificate = signed.verify(account_key)?;
        if certificate.format != DEVICE_FORMAT {
            return Err(ProtoError::UnsupportedFormat(certificate.format));
        }
        if certificate.account != account {
            return Err(ProtoError::Inconsistent("certificate account"));
        }
        if certificate.device != DeviceId::from_key(&certificate.verifying_key) {
            return Err(ProtoError::Inconsistent("device id"));
        }
        Ok(certificate)
    }
}

fn name_aad(account: AccountId, device: DeviceId) -> Vec<u8> {
    [NAME_AAD_LABEL, account.as_bytes(), device.as_bytes()].concat()
}

/// One trusted device in a [`DeviceList`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct DeviceEntry {
    /// The device.
    #[n(0)]
    pub device: DeviceId,
    /// Hash of its signed certificate.
    #[n(1)]
    pub certificate: CertificateHash,
}

/// The account's list of trusted and revoked devices. Signed by the account signing key.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct DeviceList {
    /// Format version; [`DEVICE_FORMAT`].
    #[n(0)]
    pub format: u8,
    /// The account.
    #[n(1)]
    pub account: AccountId,
    /// Increases with every change.
    #[n(2)]
    pub version: u64,
    /// Trusted devices.
    #[n(3)]
    pub devices: Vec<DeviceEntry>,
    /// Revoked devices; never trusted again.
    #[n(4)]
    pub revoked: Vec<DeviceId>,
}

impl Signable for DeviceList {
    const CONTEXT: SignContext = SignContext::DeviceList;
}

impl DeviceList {
    /// Whether `device` is currently trusted.
    #[must_use]
    pub fn is_trusted(&self, device: &DeviceId) -> bool {
        !self.revoked.contains(device) && self.devices.iter().any(|entry| entry.device == *device)
    }

    /// Checks that this list may replace `previous`: known format, same account, a higher
    /// version, and no revoked device trusted again.
    ///
    /// # Errors
    ///
    /// [`ProtoError::UnsupportedFormat`], [`ProtoError::Inconsistent`] or
    /// [`ProtoError::ListRollback`].
    pub fn check_update(&self, previous: Option<&Self>) -> Result<(), ProtoError> {
        if self.format != DEVICE_FORMAT {
            return Err(ProtoError::UnsupportedFormat(self.format));
        }
        let Some(previous) = previous else {
            return Ok(());
        };
        if self.account != previous.account {
            return Err(ProtoError::Inconsistent("device list account"));
        }
        if self.version <= previous.version {
            return Err(ProtoError::ListRollback);
        }
        let unrevoked = previous
            .revoked
            .iter()
            .any(|device| !self.revoked.contains(device) || self.is_listed(device));
        if unrevoked {
            return Err(ProtoError::Inconsistent("revoked device trusted again"));
        }
        Ok(())
    }

    fn is_listed(&self, device: &DeviceId) -> bool {
        self.devices.iter().any(|entry| entry.device == *device)
    }
}

/// The account publishing its KEM public key. Signed by the account signing key.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct KemKeyPublication {
    /// Format version; [`DEVICE_FORMAT`].
    #[n(0)]
    pub format: u8,
    /// The account.
    #[n(1)]
    pub account: AccountId,
    /// Its KEM public key.
    #[cbor(n(2), with = "cbor::kem_key")]
    pub kem_key: KemPublicKey,
}

impl Signable for KemKeyPublication {
    const CONTEXT: SignContext = SignContext::AccountKemKey;
}

/// A device stating the newest head it has seen of a collection, so forks can be detected
/// (crypto design §8). Signed by the device.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct HeadAttestation {
    /// Format version; [`DEVICE_FORMAT`].
    #[n(0)]
    pub format: u8,
    /// The collection.
    #[n(1)]
    pub collection: CollectionId,
    /// Sequence number of the head seen.
    #[n(2)]
    pub seq: Seq,
    /// Hash of the head seen.
    #[n(3)]
    pub hash: CommitHash,
    /// The attesting device.
    #[n(4)]
    pub device: DeviceId,
    /// When, milliseconds since the Unix epoch.
    #[n(5)]
    pub time_ms: u64,
}

impl Signable for HeadAttestation {
    const CONTEXT: SignContext = SignContext::HeadAttestation;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::rng;
    use oxisoft_drive_crypto::hash;
    use oxisoft_drive_crypto::keys::{AccountKey, AccountSigningKey, DeviceIdentity};

    struct Account {
        id: AccountId,
        key: AccountKey,
        signing: AccountSigningKey,
    }

    fn account(seed: u8) -> Account {
        let mut rng = rng(seed);
        Account {
            id: AccountId::random(&mut rng),
            key: AccountKey::generate(&mut rng, 0),
            signing: AccountSigningKey::generate(&mut rng),
        }
    }

    fn certificate(account: &Account, seed: u8, name: &str) -> DeviceCertificate {
        let identity = DeviceIdentity::generate(&mut rng(seed));
        DeviceCertificate::new(
            account.id,
            (identity.verifying_key(), identity.kem_public_key()),
            name,
            &account.key.meta(),
            &mut rng(seed),
            1000,
        )
        .unwrap()
    }

    #[test]
    fn certificates_verify_and_hide_the_name() {
        let account = account(1);
        let cert = certificate(&account, 2, "Alex's laptop");
        assert_eq!(cert.name(&account.key.meta()).unwrap(), "Alex's laptop");
        let signed = Signed::sign(account.signing.signing_key(), &cert);
        let verifying = account.signing.verifying_key();
        assert_eq!(
            DeviceCertificate::verify(&signed, account.id, &verifying).unwrap(),
            cert
        );
        let bytes = minicbor::to_vec(&signed).unwrap();
        assert!(!bytes.windows(6).any(|window| window == b"laptop"));

        let other = self::account(3);
        assert!(cert.name(&other.key.meta()).is_err());
        assert_eq!(
            DeviceCertificate::verify(&signed, other.id, &verifying),
            Err(ProtoError::Inconsistent("certificate account"))
        );
        assert!(matches!(
            DeviceCertificate::verify(&signed, account.id, &other.signing.verifying_key()),
            Err(ProtoError::Crypto(_))
        ));
    }

    #[test]
    fn inconsistent_certificates_are_rejected() {
        let account = account(4);
        let sign = |cert: &DeviceCertificate| Signed::sign(account.signing.signing_key(), cert);
        let verify = |cert: &DeviceCertificate| {
            DeviceCertificate::verify(&sign(cert), account.id, &account.signing.verifying_key())
        };
        let mut wrong_id = certificate(&account, 5, "a");
        wrong_id.device = DeviceId::from_bytes([0; 16]);
        assert_eq!(
            verify(&wrong_id),
            Err(ProtoError::Inconsistent("device id"))
        );
        let mut future = certificate(&account, 6, "a");
        future.format = 2;
        assert_eq!(verify(&future), Err(ProtoError::UnsupportedFormat(2)));

        let mut garbled = certificate(&account, 7, "a");
        garbled.sealed_name = aead::seal(
            &account.key.meta(),
            &mut rng(8),
            &name_aad(garbled.account, garbled.device),
            &[0xff, 0xfe],
        )
        .unwrap();
        assert!(matches!(
            garbled.name(&account.key.meta()),
            Err(ProtoError::Decode(_))
        ));
    }

    fn list(version: u64, devices: &[u8], revoked: &[u8]) -> DeviceList {
        DeviceList {
            format: DEVICE_FORMAT,
            account: AccountId::from_bytes([1; 16]),
            version,
            devices: devices
                .iter()
                .map(|&d| DeviceEntry {
                    device: DeviceId::from_bytes([d; 16]),
                    certificate: CertificateHash(hash::hash(&[d])),
                })
                .collect(),
            revoked: revoked
                .iter()
                .map(|&d| DeviceId::from_bytes([d; 16]))
                .collect(),
        }
    }

    #[test]
    fn device_lists_only_move_forward() {
        let first = list(1, &[1, 2], &[]);
        assert_eq!(first.check_update(None), Ok(()));
        assert!(first.is_trusted(&DeviceId::from_bytes([2; 16])));
        let revoked = list(2, &[1], &[2]);
        assert_eq!(revoked.check_update(Some(&first)), Ok(()));
        assert!(!revoked.is_trusted(&DeviceId::from_bytes([2; 16])));
        assert_eq!(
            list(1, &[1], &[]).check_update(Some(&first)),
            Err(ProtoError::ListRollback)
        );
        assert_eq!(
            list(3, &[1, 2], &[]).check_update(Some(&revoked)),
            Err(ProtoError::Inconsistent("revoked device trusted again"))
        );
        assert_eq!(
            list(3, &[1, 2], &[2]).check_update(Some(&revoked)),
            Err(ProtoError::Inconsistent("revoked device trusted again"))
        );
        let other_account = DeviceList {
            account: AccountId::from_bytes([9; 16]),
            ..list(3, &[1], &[2])
        };
        assert_eq!(
            other_account.check_update(Some(&revoked)),
            Err(ProtoError::Inconsistent("device list account"))
        );
        let future = DeviceList {
            format: 5,
            ..list(3, &[1], &[2])
        };
        assert_eq!(
            future.check_update(None),
            Err(ProtoError::UnsupportedFormat(5))
        );
    }

    #[test]
    fn publications_and_attestations_round_trip() {
        let account = account(9);
        let kem = oxisoft_drive_crypto::keys::AccountKemKey::generate(&mut rng(10));
        let publication = KemKeyPublication {
            format: DEVICE_FORMAT,
            account: account.id,
            kem_key: kem.public_key(),
        };
        let signed = Signed::sign(account.signing.signing_key(), &publication);
        assert_eq!(
            signed.verify(&account.signing.verifying_key()).unwrap(),
            publication
        );

        let device = DeviceIdentity::generate(&mut rng(11));
        let attestation = HeadAttestation {
            format: DEVICE_FORMAT,
            collection: CollectionId::from_bytes([2; 16]),
            seq: 12,
            hash: CommitHash(hash::hash(b"head")),
            device: DeviceId::from_key(&device.verifying_key()),
            time_ms: 5,
        };
        let signed = Signed::sign(device.signing_key(), &attestation);
        assert_eq!(signed.verify(&device.verifying_key()).unwrap(), attestation);
    }
}
