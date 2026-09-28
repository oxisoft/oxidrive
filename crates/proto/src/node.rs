//! Node records (crypto design §7): one change to one file or folder.
//!
//! The server sees the node ID, the referenced chunk IDs (decision D4) and the sealed payload.
//! Everything else (parent, name, kind, size, times, versions) is inside the payload, which is
//! CBOR, Padmé-padded, and encrypted with the collection's meta key.

use minicbor::{Decode, Encode};
use oxisoft_drive_chunking::padme;
use oxisoft_drive_crypto::CryptoRng;
use oxisoft_drive_crypto::aead;
use oxisoft_drive_crypto::keys::MetaKey;
use zeroize::Zeroizing;

use crate::cbor;
use crate::{ChunkId, CollectionId, ContentHash, Name, NodeId, ProtoError, Seq, Version};

/// Node payload format version written by this code.
pub const NODE_FORMAT: u8 = 1;

const AAD_LABEL: &[u8] = b"oxidrive node v1";

/// One change to one node, as stored in a commit.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct NodeRecord {
    /// The node that changed.
    #[n(0)]
    pub node: NodeId,
    /// Chunks the new version references, in order; visible so the server can count
    /// references (D4). Must match the encrypted chunk list.
    #[n(1)]
    pub chunks: Vec<ChunkId>,
    /// The encrypted, padded [`NodePayload`].
    #[cbor(n(2), with = "minicbor::bytes")]
    pub sealed: Vec<u8>,
}

/// Where a record sits; bound into its encryption so it can't be moved elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordContext {
    /// The collection.
    pub collection: CollectionId,
    /// The sequence number of the commit carrying the record.
    pub seq: Seq,
    /// The key epoch of the meta key used.
    pub epoch: u32,
}

/// The encrypted part of a node record.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct NodePayload {
    /// Format version; [`NODE_FORMAT`].
    #[n(0)]
    pub format: u8,
    /// The containing folder, or `None` for a node directly in the collection root.
    #[n(1)]
    pub parent: Option<NodeId>,
    /// The node's name inside its parent.
    #[n(2)]
    pub name: Name,
    /// What the node is now.
    #[n(3)]
    pub kind: NodeKind,
    /// This version.
    #[n(4)]
    pub version: Version,
    /// The version the change was made on; `None` for a new node (sync protocol §1).
    #[n(5)]
    pub base: Option<Version>,
}

/// What a node is.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum NodeKind {
    /// A file with content.
    #[n(0)]
    File(#[n(0)] FileInfo),
    /// A folder.
    #[n(1)]
    Folder,
    /// A deleted node (a tombstone, sync protocol §7).
    #[n(2)]
    Deleted,
}

/// Metadata and content of one file version.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct FileInfo {
    /// Size in bytes.
    #[n(0)]
    pub size: u64,
    /// Modification time, milliseconds since the Unix epoch (informational).
    #[n(1)]
    pub mtime_ms: i64,
    /// The Unix executable bit.
    #[n(2)]
    pub executable: bool,
    /// Keyed hash of the whole content.
    #[n(3)]
    pub content_hash: ContentHash,
    /// The chunks, in order, with their plaintext lengths.
    #[n(4)]
    pub chunks: Vec<ChunkRef>,
}

/// One chunk of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct ChunkRef {
    /// The chunk's ID.
    #[n(0)]
    pub id: ChunkId,
    /// Its plaintext length.
    #[n(1)]
    pub len: u32,
}

impl NodePayload {
    /// The chunk IDs this payload references, in order.
    #[must_use]
    pub fn chunk_ids(&self) -> Vec<ChunkId> {
        match &self.kind {
            NodeKind::File(file) => file.chunks.iter().map(|chunk| chunk.id).collect(),
            NodeKind::Folder | NodeKind::Deleted => Vec::new(),
        }
    }
}

impl NodeRecord {
    /// Encrypts `payload` as the record for `node` at `context`.
    ///
    /// # Errors
    ///
    /// [`ProtoError::TooLarge`] for a payload over 4 GiB.
    pub fn seal<R: CryptoRng>(
        node: NodeId,
        payload: &NodePayload,
        key: &MetaKey,
        rng: &mut R,
        context: &RecordContext,
    ) -> Result<Self, ProtoError> {
        let encoded = Zeroizing::new(cbor::to_vec(payload));
        let len = u32::try_from(encoded.len()).map_err(|_| ProtoError::TooLarge)?;
        let padded = padded_len(len).ok_or(ProtoError::TooLarge)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(padded));
        plaintext.extend_from_slice(&len.to_le_bytes());
        plaintext.extend_from_slice(&encoded);
        plaintext.resize(padded, 0);
        let sealed = aead::seal(key, rng, &aad(context, node), &plaintext)?;
        Ok(Self {
            node,
            chunks: payload.chunk_ids(),
            sealed,
        })
    }

    /// Decrypts and checks the payload.
    ///
    /// # Errors
    ///
    /// [`ProtoError::Crypto`] if the record wasn't sealed for this key, node and context;
    /// [`ProtoError::Decode`] or [`ProtoError::UnsupportedFormat`] for a bad payload;
    /// [`ProtoError::Inconsistent`] if the visible chunk list disagrees with the payload.
    pub fn open(&self, key: &MetaKey, context: &RecordContext) -> Result<NodePayload, ProtoError> {
        let plaintext = aead::open(key, &aad(context, self.node), &self.sealed)?;
        let (len, rest) = plaintext
            .split_first_chunk::<4>()
            .ok_or(ProtoError::Inconsistent("payload length"))?;
        let len = u32::from_le_bytes(*len);
        let (encoded, padding) = rest
            .split_at_checked(len as usize)
            .ok_or(ProtoError::Inconsistent("payload length"))?;
        if padded_len(len) != Some(plaintext.len()) || padding.iter().any(|&byte| byte != 0) {
            return Err(ProtoError::Inconsistent("payload padding"));
        }
        let payload: NodePayload = minicbor::decode(encoded)?;
        if payload.format != NODE_FORMAT {
            return Err(ProtoError::UnsupportedFormat(payload.format));
        }
        if payload.chunk_ids() != self.chunks {
            return Err(ProtoError::Inconsistent("chunk references"));
        }
        Ok(payload)
    }
}

/// Padded plaintext length for an encoded payload of `len` bytes (4-byte length prefix
/// included), or `None` if it wouldn't fit in memory.
fn padded_len(len: u32) -> Option<usize> {
    let prefixed = len.checked_add(4)?;
    usize::try_from(padme(prefixed)).ok()
}

fn aad(context: &RecordContext, node: NodeId) -> Vec<u8> {
    [
        AAD_LABEL,
        context.collection.as_bytes(),
        node.as_bytes(),
        &context.seq.to_le_bytes(),
        &context.epoch.to_le_bytes(),
    ]
    .concat()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::DeviceId;
    use crate::test_util::rng;
    use oxisoft_drive_crypto::hash;
    use oxisoft_drive_crypto::keys::CollectionKey;

    pub(crate) fn file_payload(name: &str, chunks: &[&[u8]]) -> NodePayload {
        NodePayload {
            format: NODE_FORMAT,
            parent: Some(NodeId::from_bytes([1; 16])),
            name: Name::new(name).unwrap(),
            kind: NodeKind::File(FileInfo {
                size: 42,
                mtime_ms: 1_790_000_000_000,
                executable: false,
                content_hash: ContentHash(hash::hash(b"content")),
                chunks: chunks
                    .iter()
                    .map(|chunk| ChunkRef {
                        id: ChunkId(hash::hash(chunk)),
                        len: 21,
                    })
                    .collect(),
            }),
            version: Version {
                device: DeviceId::from_bytes([2; 16]),
                counter: 3,
            },
            base: None,
        }
    }

    pub(crate) fn context() -> RecordContext {
        RecordContext {
            collection: CollectionId::from_bytes([5; 16]),
            seq: 7,
            epoch: 1,
        }
    }

    #[test]
    fn records_round_trip_and_expose_only_chunk_ids() {
        let key = CollectionKey::generate(&mut rng(1), 1).meta();
        let node = NodeId::from_bytes([9; 16]);
        for payload in [
            file_payload("a.txt", &[b"one", b"two"]),
            NodePayload {
                kind: NodeKind::Folder,
                ..file_payload("dir", &[])
            },
            NodePayload {
                kind: NodeKind::Deleted,
                base: Some(Version {
                    device: DeviceId::from_bytes([4; 16]),
                    counter: 1,
                }),
                ..file_payload("gone", &[])
            },
        ] {
            let record = NodeRecord::seal(node, &payload, &key, &mut rng(2), &context()).unwrap();
            assert_eq!(record.chunks, payload.chunk_ids());
            assert_eq!(record.open(&key, &context()).unwrap(), payload);
            let bytes = minicbor::to_vec(&record).unwrap();
            assert_eq!(minicbor::decode::<NodeRecord>(&bytes).unwrap(), record);
            // The name never appears in the clear.
            let name = payload.name.as_str().as_bytes();
            assert!(!bytes.windows(name.len()).any(|window| window == name));
        }
    }

    #[test]
    fn records_are_bound_to_node_and_context() {
        let key = CollectionKey::generate(&mut rng(3), 1).meta();
        let payload = file_payload("a", &[b"x"]);
        let record = NodeRecord::seal(
            NodeId::from_bytes([1; 16]),
            &payload,
            &key,
            &mut rng(4),
            &context(),
        )
        .unwrap();
        let moved = NodeRecord {
            node: NodeId::from_bytes([2; 16]),
            ..record.clone()
        };
        assert!(matches!(
            moved.open(&key, &context()),
            Err(ProtoError::Crypto(_))
        ));
        for other in [
            RecordContext {
                seq: 8,
                ..context()
            },
            RecordContext {
                epoch: 2,
                ..context()
            },
            RecordContext {
                collection: CollectionId::from_bytes([6; 16]),
                ..context()
            },
        ] {
            assert!(matches!(
                record.open(&key, &other),
                Err(ProtoError::Crypto(_))
            ));
        }
        let hidden_chunk = NodeRecord {
            chunks: Vec::new(),
            ..record
        };
        assert_eq!(
            hidden_chunk.open(&key, &context()),
            Err(ProtoError::Inconsistent("chunk references"))
        );
    }

    /// Seals an arbitrary plaintext, to test what `open` rejects.
    fn forge(key: &MetaKey, plaintext: &[u8]) -> NodeRecord {
        let node = NodeId::from_bytes([1; 16]);
        NodeRecord {
            node,
            chunks: Vec::new(),
            sealed: aead::seal(key, &mut rng(5), &aad(&context(), node), plaintext).unwrap(),
        }
    }

    fn framed(encoded: &[u8], extra: usize) -> Vec<u8> {
        let len = u32::try_from(encoded.len()).unwrap();
        let mut plaintext = len.to_le_bytes().to_vec();
        plaintext.extend_from_slice(encoded);
        plaintext.resize(padded_len(len).unwrap() + extra, 0);
        plaintext
    }

    #[test]
    fn forged_payloads_are_rejected() {
        let key = CollectionKey::generate(&mut rng(6), 1).meta();
        let folder = NodePayload {
            kind: NodeKind::Folder,
            ..file_payload("f", &[])
        };
        let good = cbor::to_vec(&folder);
        assert_eq!(
            forge(&key, &framed(&good, 0))
                .open(&key, &context())
                .unwrap(),
            folder
        );

        let inconsistent = |text| Err(ProtoError::Inconsistent(text));
        assert_eq!(
            forge(&key, &[1, 0]).open(&key, &context()),
            inconsistent("payload length")
        );
        assert_eq!(
            forge(&key, &[200, 0, 0, 0, 1]).open(&key, &context()),
            inconsistent("payload length")
        );
        assert_eq!(
            forge(&key, &framed(&good, 64)).open(&key, &context()),
            inconsistent("payload padding")
        );
        // A payload whose padded plaintext has padding bytes, to corrupt one of them.
        let padded = (1..40)
            .map(|len| {
                cbor::to_vec(&NodePayload {
                    kind: NodeKind::Folder,
                    ..file_payload(&"p".repeat(len), &[])
                })
            })
            .find(|encoded| framed(encoded, 0).len() > 4 + encoded.len())
            .unwrap();
        let mut dirty = framed(&padded, 0);
        *dirty.last_mut().unwrap() = 1;
        assert_eq!(
            forge(&key, &dirty).open(&key, &context()),
            inconsistent("payload padding")
        );
        assert!(matches!(
            forge(&key, &framed(&[0xff], 0)).open(&key, &context()),
            Err(ProtoError::Decode(_))
        ));
        let future = cbor::to_vec(&NodePayload {
            format: 9,
            ..folder
        });
        assert_eq!(
            forge(&key, &framed(&future, 0)).open(&key, &context()),
            Err(ProtoError::UnsupportedFormat(9))
        );
        assert_eq!(padded_len(u32::MAX), None);
    }
}
