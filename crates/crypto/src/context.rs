//! Every domain-separation string, in one place.
//!
//! BLAKE3 recommends contexts of the form "application, date, purpose". Changing any of these
//! strings changes every key derived with it, so they are frozen: the format vectors in the
//! tests fail if one is edited.

pub(crate) const COLLECTION_META: &str = "oxidrive 2026-09-28 collection meta key";
pub(crate) const COLLECTION_DATA: &str = "oxidrive 2026-09-28 collection data key";
pub(crate) const COLLECTION_ID: &str = "oxidrive 2026-09-28 collection id key";
pub(crate) const COLLECTION_CHUNKING: &str = "oxidrive 2026-09-28 collection chunking key";
pub(crate) const COLLECTION_THUMB: &str = "oxidrive 2026-09-28 collection thumbnail key";
pub(crate) const RECOVERY_WRAP: &str = "oxidrive 2026-09-28 recovery wrap key";

/// Input to the keyed XOF that expands a chunking key into the gear table.
pub(crate) const GEAR_TABLE: &[u8] = b"oxidrive 2026-09-28 gear table";

pub(crate) const SIGN_AUTH_CHALLENGE: &str = "oxidrive 2026-09-28 sign auth challenge";
pub(crate) const SIGN_DEVICE_CERTIFICATE: &str = "oxidrive 2026-09-28 sign device certificate";
pub(crate) const SIGN_DEVICE_LIST: &str = "oxidrive 2026-09-28 sign device list";
pub(crate) const SIGN_COMMIT: &str = "oxidrive 2026-09-28 sign commit";
pub(crate) const SIGN_HEAD_ATTESTATION: &str = "oxidrive 2026-09-28 sign head attestation";
pub(crate) const SIGN_ACCOUNT_KEM_KEY: &str = "oxidrive 2026-09-28 sign account kem key";

pub(crate) const WRAP_ACCOUNT_KEY_TO_DEVICE: &[u8] =
    b"oxidrive 2026-09-28 wrap account key to device";
pub(crate) const WRAP_COLLECTION_KEY_TO_ACCOUNT: &[u8] =
    b"oxidrive 2026-09-28 wrap collection key to account";

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn contexts_are_distinct_and_contain_no_nul() {
        let all: [&[u8]; 16] = [
            COLLECTION_META.as_bytes(),
            COLLECTION_DATA.as_bytes(),
            COLLECTION_ID.as_bytes(),
            COLLECTION_CHUNKING.as_bytes(),
            COLLECTION_THUMB.as_bytes(),
            RECOVERY_WRAP.as_bytes(),
            GEAR_TABLE,
            SIGN_AUTH_CHALLENGE.as_bytes(),
            SIGN_DEVICE_CERTIFICATE.as_bytes(),
            SIGN_DEVICE_LIST.as_bytes(),
            SIGN_COMMIT.as_bytes(),
            SIGN_HEAD_ATTESTATION.as_bytes(),
            SIGN_ACCOUNT_KEM_KEY.as_bytes(),
            WRAP_ACCOUNT_KEY_TO_DEVICE,
            WRAP_COLLECTION_KEY_TO_ACCOUNT,
            b"oxidrive 2026-09-28 ",
        ];
        let unique: HashSet<&[u8]> = all.iter().copied().collect();
        assert_eq!(unique.len(), all.len());
        // Signatures frame messages as context ‖ 0x00 ‖ message, so a NUL inside a context
        // would make framing ambiguous.
        assert!(all.iter().all(|context| !context.contains(&0)));
    }
}
