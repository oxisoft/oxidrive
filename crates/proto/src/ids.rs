//! Identifiers. Each is its own type, so an account ID can't be passed where a node ID is
//! expected.

use std::fmt;

use minicbor::decode::{Decoder, Error as DecodeError};
use minicbor::encode::{Encoder, Error as EncodeError, Write};
use minicbor::{Decode, Encode};
use oxisoft_drive_crypto::CryptoRng;
use oxisoft_drive_crypto::hash::{self, Digest};
use oxisoft_drive_crypto::sign::VerifyingKey;

use crate::cbor::fixed;

/// Length of the random identifiers.
pub const ID_LEN: usize = 16;

fn write_hex(f: &mut fmt::Formatter<'_>, name: &str, bytes: &[u8]) -> fmt::Result {
    write!(f, "{name}(")?;
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    write!(f, ")")
}

macro_rules! random_id {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            /// A new random identifier.
            pub fn random<R: CryptoRng>(rng: &mut R) -> Self {
                let mut bytes = [0; ID_LEN];
                rng.fill_bytes(&mut bytes);
                Self(bytes)
            }

            /// Wraps stored bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            /// The stored form.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_hex(f, stringify!($name), &self.0)
            }
        }

        impl<C> Encode<C> for $name {
            fn encode<W: Write>(
                &self,
                e: &mut Encoder<W>,
                _: &mut C,
            ) -> Result<(), EncodeError<W::Error>> {
                e.bytes(&self.0)?;
                Ok(())
            }
        }

        impl<'b, C> Decode<'b, C> for $name {
            fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
                fixed(d).map(Self)
            }
        }
    };
}

macro_rules! digest_id {
    ($(#[$attr:meta])* $name:ident) => {
        $(#[$attr])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub Digest);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_hex(f, stringify!($name), self.0.as_bytes())
            }
        }

        impl<C> Encode<C> for $name {
            fn encode<W: Write>(
                &self,
                e: &mut Encoder<W>,
                _: &mut C,
            ) -> Result<(), EncodeError<W::Error>> {
                e.bytes(self.0.as_bytes())?;
                Ok(())
            }
        }

        impl<'b, C> Decode<'b, C> for $name {
            fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
                fixed(d).map(|bytes| Self(Digest::from_bytes(bytes)))
            }
        }
    };
}

random_id!(
    /// One user's account.
    AccountId
);
random_id!(
    /// One collection: a synced folder root, or the photo library.
    CollectionId
);
random_id!(
    /// One file or folder, stable across renames and moves.
    NodeId
);
random_id!(
    /// A pending device pairing on the server.
    PairingId
);
random_id!(
    /// A server-side upload lease protecting chunks from garbage collection.
    LeaseId
);
random_id!(
    /// One device. Derived from its signing key (decision P4), so an ID can't be paired with
    /// another key; see [`DeviceId::from_key`].
    DeviceId
);

impl DeviceId {
    /// The ID belonging to a device's verifying key: the first 16 bytes of its BLAKE3 hash.
    #[must_use]
    pub fn from_key(key: &VerifyingKey) -> Self {
        let digest = hash::hash(&key.to_bytes());
        let mut id = [0; ID_LEN];
        id.copy_from_slice(&digest.as_bytes()[..ID_LEN]);
        Self(id)
    }
}

digest_id!(
    /// A chunk's keyed content hash; the name its object is stored under.
    ChunkId
);
digest_id!(
    /// Hash of a commit's signed header and signature; links the chain.
    CommitHash
);
digest_id!(
    /// Keyed hash of a whole file's content.
    ContentHash
);
digest_id!(
    /// Hash of a commit's encoded records, signed in its header.
    RecordsHash
);
digest_id!(
    /// Hash of a signed device certificate, referenced from the device list.
    CertificateHash
);
digest_id!(
    /// Hash of a new device's public keys, carried in the pairing code.
    KeysHash
);

/// A commit's position in its collection's log, starting at 1.
pub type Seq = u64;

/// A version of one node: which device wrote it, and that device's counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode)]
pub struct Version {
    /// The writing device.
    #[n(0)]
    pub device: DeviceId,
    /// That device's counter, increasing with each of its writes.
    #[n(1)]
    pub counter: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::rng;
    use oxisoft_drive_crypto::keys::DeviceIdentity;

    #[test]
    fn random_ids_round_trip_and_print_hex() {
        let mut rng = rng(1);
        let id = NodeId::random(&mut rng);
        assert_ne!(id, NodeId::random(&mut rng));
        let bytes = minicbor::to_vec(id).unwrap();
        assert_eq!(minicbor::decode::<NodeId>(&bytes).unwrap(), id);
        assert_eq!(NodeId::from_bytes(*id.as_bytes()), id);
        assert_eq!(
            format!("{:?}", AccountId::from_bytes([0xab; 16])),
            format!("AccountId({})", "ab".repeat(16))
        );
        for id in [
            CollectionId::random(&mut rng).as_bytes(),
            PairingId::random(&mut rng).as_bytes(),
            LeaseId::random(&mut rng).as_bytes(),
        ] {
            assert_ne!(id, &[0; 16]);
        }
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        let short = minicbor::to_vec(minicbor::bytes::ByteVec::from(vec![1; 15])).unwrap();
        assert!(minicbor::decode::<NodeId>(&short).is_err());
        assert!(minicbor::decode::<ChunkId>(&short).is_err());
    }

    #[test]
    fn device_ids_are_derived_from_keys() {
        let identity = DeviceIdentity::generate(&mut rng(2));
        let id = DeviceId::from_key(&identity.verifying_key());
        assert_eq!(id, DeviceId::from_key(&identity.verifying_key()));
        let expected = hash::hash(&identity.verifying_key().to_bytes());
        assert_eq!(id.as_bytes(), &expected.as_bytes()[..16]);
    }

    #[test]
    fn digest_ids_and_versions_round_trip() {
        let chunk = ChunkId(hash::hash(b"x"));
        let bytes = minicbor::to_vec(chunk).unwrap();
        assert_eq!(minicbor::decode::<ChunkId>(&bytes).unwrap(), chunk);
        assert!(format!("{chunk:?}").starts_with("ChunkId("));
        for text in [
            format!("{:?}", CommitHash(hash::hash(b""))),
            format!("{:?}", ContentHash(hash::hash(b""))),
            format!("{:?}", CertificateHash(hash::hash(b""))),
            format!("{:?}", KeysHash(hash::hash(b""))),
            format!("{:?}", RecordsHash(hash::hash(b""))),
        ] {
            assert!(text.ends_with(')') && text.len() > 64, "{text}");
        }
        let version = Version {
            device: DeviceId::from_bytes([3; 16]),
            counter: 9,
        };
        let bytes = minicbor::to_vec(version).unwrap();
        assert_eq!(minicbor::decode::<Version>(&bytes).unwrap(), version);
    }
}
