//! The recovery key: 256 random bits, shown once to the user as 24 BIP-39 English words.
//!
//! It has full key strength, so no password hashing is needed: the wrapping key is derived
//! from it directly (crypto design §5).

use std::fmt;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::context;
use crate::hash;
use crate::keys::RecoveryWrapKey;
use crate::secret::Secret32;
use crate::{CryptoError, RecoveryPhraseError};

/// Number of words in a recovery phrase.
pub const WORDS: usize = 24;

/// The recovery key. Wiped on drop, never printed.
pub struct RecoveryKey(Secret32);

impl RecoveryKey {
    /// A new random recovery key.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        Self(Secret32::random(rng))
    }

    /// The 24 words to show the user, separated by single spaces.
    ///
    /// # Errors
    ///
    /// Only if the word encoder rejects 32 bytes of entropy, which it never does.
    pub fn to_words(&self) -> Result<Zeroizing<String>, CryptoError> {
        let mnemonic =
            bip39::Mnemonic::from_entropy(self.0.expose()).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Zeroizing::new(mnemonic.to_string()))
    }

    /// Reads the words back, forgiving upper case and extra whitespace.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidRecoveryPhrase`] saying whether the word count, a word, or the
    /// checksum is wrong. The words themselves never appear in the error.
    pub fn from_words(words: &str) -> Result<Self, CryptoError> {
        let mut normalized = Zeroizing::new(String::with_capacity(words.len()));
        for word in words.split_whitespace() {
            if !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.extend(word.chars().flat_map(char::to_lowercase));
        }
        let invalid = |reason| CryptoError::InvalidRecoveryPhrase(reason);
        let mnemonic = bip39::Mnemonic::parse_normalized(&normalized).map_err(|error| {
            invalid(match error {
                bip39::Error::InvalidChecksum => RecoveryPhraseError::Checksum,
                bip39::Error::UnknownWord(_) | bip39::Error::AmbiguousLanguages(_) => {
                    RecoveryPhraseError::UnknownWord
                }
                _ => RecoveryPhraseError::WordCount,
            })
        })?;
        let (mut entropy, len) = mnemonic.to_entropy_array();
        let key = <[u8; 32]>::try_from(&entropy[..len])
            .map(|bytes| Self(Secret32::from_bytes(bytes)))
            .map_err(|_| invalid(RecoveryPhraseError::WordCount));
        zeroize::Zeroize::zeroize(&mut entropy);
        key
    }

    /// The key that wraps the account key for recovery.
    #[must_use]
    pub fn wrap_key(&self) -> RecoveryWrapKey {
        RecoveryWrapKey::new(hash::derive_key(context::RECOVERY_WRAP, self.0.expose()))
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AccountKey;
    use crate::test_util::{from_hex_array, rng};
    use proptest::prelude::*;

    /// The 256-bit English vectors of the BIP-39 reference implementation
    /// (trezor/python-mnemonic `vectors.json`): entropy, words.
    const BIP39: [(&str, &str); 8] = [
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        ),
        (
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        ),
        (
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        ),
        (
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        ),
        (
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        ),
    ];

    fn single_spaced(words: &str) -> String {
        words.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn matches_the_bip39_vectors() {
        for (hex, words) in BIP39 {
            let key = RecoveryKey(Secret32::from_bytes(from_hex_array::<32>(hex)));
            assert_eq!(*key.to_words().unwrap(), single_spaced(words));
            let back = RecoveryKey::from_words(words).unwrap();
            assert_eq!(back.0.expose(), &from_hex_array::<32>(hex));
        }
    }

    #[test]
    fn forgives_case_and_whitespace() {
        let key = RecoveryKey::generate(&mut rng(70));
        let words = key.to_words().unwrap();
        let messy = format!("  {}\n", words.to_uppercase().replace(' ', " \t "));
        assert_eq!(
            RecoveryKey::from_words(&messy).unwrap().0.expose(),
            key.0.expose()
        );
    }

    #[test]
    fn explains_what_is_wrong() {
        let words = RecoveryKey::generate(&mut rng(71)).to_words().unwrap();
        let list: Vec<&str> = words.split(' ').collect();
        let err = |text: &str| match RecoveryKey::from_words(text) {
            Err(CryptoError::InvalidRecoveryPhrase(reason)) => reason,
            other => panic!("expected a phrase error, got {other:?}"),
        };
        assert_eq!(err(&list[..23].join(" ")), RecoveryPhraseError::WordCount);
        assert_eq!(err(""), RecoveryPhraseError::WordCount);
        let mut unknown = list.clone();
        unknown[5] = "oxidrive";
        assert_eq!(err(&unknown.join(" ")), RecoveryPhraseError::UnknownWord);
        let mut swapped = list.clone();
        let (a, b) = (0..WORDS)
            .flat_map(|i| (i + 1..WORDS).map(move |j| (i, j)))
            .find(|&(i, j)| list[i] != list[j])
            .unwrap();
        swapped.swap(a, b);
        assert_eq!(err(&swapped.join(" ")), RecoveryPhraseError::Checksum);
        // A valid 12-word phrase is still the wrong length for a recovery key.
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
        assert_eq!(err(twelve), RecoveryPhraseError::WordCount);
    }

    #[test]
    fn wrap_key_is_deterministic_and_debug_is_silent() {
        let mut rng = rng(72);
        let key = RecoveryKey::generate(&mut rng);
        assert_eq!(format!("{key:?}"), "RecoveryKey(..)");
        let account = AccountKey::generate(&mut rng, 1);
        let sealed = key
            .wrap_key()
            .wrap_account_key(&mut rng, b"r", &account)
            .unwrap();
        let again = RecoveryKey::from_words(&key.to_words().unwrap()).unwrap();
        assert_eq!(
            again
                .wrap_key()
                .unwrap_account_key(b"r", &sealed)
                .unwrap()
                .epoch(),
            1
        );
    }

    proptest! {
        #[test]
        fn words_round_trip(seed in any::<u8>()) {
            let key = RecoveryKey::generate(&mut rng(seed));
            let words = key.to_words().unwrap();
            prop_assert_eq!(words.split(' ').count(), WORDS);
            let back = RecoveryKey::from_words(&words).unwrap();
            prop_assert_eq!(back.0.expose(), key.0.expose());
        }
    }
}
