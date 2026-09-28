//! Frozen format vectors (engineering standards §2, requirement N4).
//!
//! Every output below comes from a seeded RNG, so it is fully deterministic. Its BLAKE3 hash is
//! frozen here. If a test fails, a stored format or a derivation changed: that breaks existing
//! data and needs a new suite, not an updated constant.

use oxisoft_drive_crypto::hash::{self, KeyedHasher};
use oxisoft_drive_crypto::kem::{self, WrapContext};
use oxisoft_drive_crypto::keys::{AccountKey, CollectionKey, DeviceIdentity};
use oxisoft_drive_crypto::recovery::RecoveryKey;
use oxisoft_drive_crypto::sign::SignContext;
use oxisoft_drive_crypto::{CryptoError, aead};
use std::fmt::Write as _;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn fingerprint(bytes: &[u8]) -> String {
    hash::hash(bytes)
        .as_bytes()
        .iter()
        .fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Name and fingerprint of every frozen output.
fn outputs() -> Result<Vec<(&'static str, String)>, CryptoError> {
    let mut rng = rng(0x0d);
    let collection = CollectionKey::generate(&mut rng, 3);
    let account = AccountKey::generate(&mut rng, 2);
    let device = DeviceIdentity::generate(&mut rng);
    let recovery = RecoveryKey::generate(&mut rng);

    let sealed_meta = aead::seal(&collection.meta(), &mut rng, b"aad", b"node record")?;
    let sealed_data = aead::seal(&collection.data(), &mut rng, b"aad", b"chunk")?;
    let sealed_thumb = aead::seal(&collection.thumb(), &mut rng, b"aad", b"thumb")?;
    let chunk_id = hash::keyed_hash(&collection.id(), b"chunk");
    let mut streaming = KeyedHasher::new(&collection.id());
    streaming.update(b"whole ").update(b"file");
    let gear: Vec<u8> = hash::gear_table(&collection.chunking())
        .iter()
        .flat_map(|entry| entry.to_le_bytes())
        .collect();
    let wrapped_collection = account.wrap(&mut rng, b"ck", &collection)?;
    let wrapped_to_device = kem::wrap_to(
        &mut rng,
        &device.kem_public_key(),
        WrapContext::AccountKeyToDevice,
        b"device",
        &account,
    )?;
    let wrapped_recovery = recovery
        .wrap_key()
        .wrap_account_key(&mut rng, b"recovery", &account)?;
    let signature = device.signing_key().sign(SignContext::Commit, b"commit");

    Ok(vec![
        ("sealed meta", fingerprint(&sealed_meta)),
        ("sealed data", fingerprint(&sealed_data)),
        ("sealed thumb", fingerprint(&sealed_thumb)),
        ("chunk id", fingerprint(chunk_id.as_bytes())),
        ("streaming id", fingerprint(streaming.finalize().as_bytes())),
        ("gear table", fingerprint(&gear)),
        ("wrapped collection key", fingerprint(&wrapped_collection)),
        ("wrapped to device", fingerprint(&wrapped_to_device)),
        ("wrapped for recovery", fingerprint(&wrapped_recovery)),
        ("device keystore", fingerprint(&*device.to_keystore_bytes())),
        (
            "device verifying key",
            fingerprint(&device.verifying_key().to_bytes()),
        ),
        (
            "device kem public key",
            fingerprint(&device.kem_public_key().to_bytes()),
        ),
        ("signature", fingerprint(&signature.to_bytes())),
        (
            "recovery words",
            fingerprint(recovery.to_words()?.as_bytes()),
        ),
    ])
}

const FROZEN: [(&str, &str); 14] = [
    (
        "sealed meta",
        "10cce71dfec84bad9fab870fd82a67f925abbbc101fd8937c83739f8a9a2915a",
    ),
    (
        "sealed data",
        "5907e0121ba08349ab87f3b6d7eec6f72301cfc72574ede0f55f7f3e1925c863",
    ),
    (
        "sealed thumb",
        "0523807bae3fccd34634573d9520bf54a2cee67ee1edf0c65df4ec6483747f10",
    ),
    (
        "chunk id",
        "3957978616bd0555a3a62f1671aa4dc514802eedb0204bf73f1bc3cc1863ec77",
    ),
    (
        "streaming id",
        "6d9b82e921151d050a96efa404c68abc3bb32f080728b3b78fd7471cd44393b0",
    ),
    (
        "gear table",
        "9cde8f4b3ede52f4c552278a7f661fc19eb023c3d0e69509094449265e8b298e",
    ),
    (
        "wrapped collection key",
        "04f4a2da2ffc8761fd4083f3d6d0aa97cfeeaf20f1293484281539f5296235d4",
    ),
    (
        "wrapped to device",
        "07c6a4f72a0d8cd2d62f6194435774299fa8cbed9f0a908bb45e75ffc2f8d97a",
    ),
    (
        "wrapped for recovery",
        "2b2ea3533489aa231a32710f7b643e3c0493b1a117a69acd7259f2adf9e2ca8e",
    ),
    (
        "device keystore",
        "17d28e6cd857550ae1482d9c4075cf44e5c1d8991c087c0a4c6ca921d7d0b123",
    ),
    (
        "device verifying key",
        "952226081c7c3864ca5dfb6187b8ab3a3f05fd346ae67becc05399847e97bc30",
    ),
    (
        "device kem public key",
        "6f72eed0e7543ae5ae16de71f3c10d02d7685f17d0a309e1ba916490f2870423",
    ),
    (
        "signature",
        "b0ef127dfc79175837a327dc042297b52b8294d7792eb18b8bd086ab14ba4574",
    ),
    (
        "recovery words",
        "45d5270bcd2b020e258abbc1fc16251f49f63c2b019dd1c5d5a063af1deafaf3",
    ),
];

#[test]
fn formats_are_frozen() {
    let actual = outputs().unwrap();
    let expected: Vec<(&str, String)> = FROZEN
        .iter()
        .map(|(name, digest)| (*name, (*digest).to_owned()))
        .collect();
    assert_eq!(actual, expected);
}

/// The frozen outputs also still decrypt and verify, so the vectors describe working data.
#[test]
fn frozen_outputs_are_valid() {
    let mut rng = rng(0x0d);
    let collection = CollectionKey::generate(&mut rng, 3);
    let account = AccountKey::generate(&mut rng, 2);
    let device = DeviceIdentity::generate(&mut rng);
    let _recovery = RecoveryKey::generate(&mut rng);
    let sealed_meta = aead::seal(&collection.meta(), &mut rng, b"aad", b"node record").unwrap();
    assert_eq!(
        &*aead::open(&collection.meta(), b"aad", &sealed_meta).unwrap(),
        b"node record"
    );
    let wrapped = account.wrap(&mut rng, b"ck", &collection).unwrap();
    assert_eq!(
        account
            .unwrap::<CollectionKey>(b"ck", &wrapped)
            .unwrap()
            .epoch(),
        3
    );
    let signature = device.signing_key().sign(SignContext::Commit, b"commit");
    assert!(
        device
            .verifying_key()
            .verify(SignContext::Commit, b"commit", &signature)
            .is_ok()
    );
}
