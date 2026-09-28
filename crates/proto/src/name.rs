//! File and folder names (sync protocol §8).

use std::fmt;

use minicbor::decode::{Decoder, Error as DecodeError};
use minicbor::encode::{Encoder, Error as EncodeError, Write};
use minicbor::{Decode, Encode};
use unicode_normalization::UnicodeNormalization;

use crate::{NameError, ProtoError};

/// Longest name in bytes (after normalisation).
pub const MAX_NAME_LEN: usize = 255;

/// A valid name: UTF-8, normalised to NFC, 1–255 bytes, no `/` or NUL, not `.` or `..`.
///
/// Names are stored exactly like this on every device. Clashes that only some file systems
/// see (case-insensitive ones) are found with [`Name::fold_case`]; the stored name is never
/// changed for them.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    /// Validates and normalises a name.
    ///
    /// # Errors
    ///
    /// [`ProtoError::InvalidName`] with the reason.
    pub fn new(name: &str) -> Result<Self, ProtoError> {
        let normalized: String = name.nfc().collect();
        let invalid = |reason| Err(ProtoError::InvalidName(reason));
        if normalized.is_empty() {
            invalid(NameError::Empty)
        } else if normalized.len() > MAX_NAME_LEN {
            invalid(NameError::TooLong)
        } else if normalized.contains(['/', '\0']) {
            invalid(NameError::ForbiddenCharacter)
        } else if normalized == "." || normalized == ".." {
            invalid(NameError::Reserved)
        } else {
            Ok(Self(normalized))
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A key under which names that a case-insensitive file system would treat as the same
    /// compare equal: lower case, then NFC. An approximation of the file systems' own rules,
    /// used only to detect clashes.
    #[must_use]
    pub fn fold_case(&self) -> String {
        self.0.chars().flat_map(char::to_lowercase).nfc().collect()
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({:?})", self.0)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<C> Encode<C> for Name {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), EncodeError<W::Error>> {
        e.str(&self.0)?;
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for Name {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        let text = d.str()?;
        let name = Self::new(text).map_err(|_| DecodeError::message("invalid name"))?;
        // Only the stored, already-normalised form is accepted.
        if name.0 == text {
            Ok(name)
        } else {
            Err(DecodeError::message("name not in NFC"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn reason(name: &str) -> NameError {
        match Name::new(name) {
            Err(ProtoError::InvalidName(reason)) => reason,
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn normalises_to_nfc() {
        let decomposed = "Cafe\u{301}.txt";
        let name = Name::new(decomposed).unwrap();
        assert_eq!(name.as_str(), "Caf\u{e9}.txt");
        assert_eq!(name, Name::new("Caf\u{e9}.txt").unwrap());
        assert_eq!(name.to_string(), "Caf\u{e9}.txt");
        assert_eq!(format!("{name:?}"), "Name(\"Caf\u{e9}.txt\")");
    }

    #[test]
    fn rejects_bad_names() {
        assert_eq!(reason(""), NameError::Empty);
        assert_eq!(reason(&"a".repeat(256)), NameError::TooLong);
        assert!(Name::new(&"a".repeat(255)).is_ok());
        assert_eq!(reason("a/b"), NameError::ForbiddenCharacter);
        assert_eq!(reason("a\0b"), NameError::ForbiddenCharacter);
        assert_eq!(reason("."), NameError::Reserved);
        assert_eq!(reason(".."), NameError::Reserved);
        assert!(Name::new("...").is_ok());
        assert!(Name::new(".hidden").is_ok());
    }

    #[test]
    fn case_folding_finds_clashes() {
        let a = Name::new("Report.TXT").unwrap();
        let b = Name::new("report.txt").unwrap();
        assert_ne!(a, b);
        assert_eq!(a.fold_case(), b.fold_case());
        let umlaut = Name::new("\u{c4}pfel").unwrap();
        assert_eq!(
            umlaut.fold_case(),
            Name::new("A\u{308}pfel").unwrap().fold_case()
        );
        assert_eq!(umlaut.fold_case(), "\u{e4}pfel");
    }

    #[test]
    fn decoding_accepts_only_stored_form() {
        let name = Name::new("notes.md").unwrap();
        let bytes = minicbor::to_vec(&name).unwrap();
        assert_eq!(minicbor::decode::<Name>(&bytes).unwrap(), name);
        let decomposed = minicbor::to_vec("Cafe\u{301}").unwrap();
        assert!(minicbor::decode::<Name>(&decomposed).is_err());
        let invalid = minicbor::to_vec("a/b").unwrap();
        assert!(minicbor::decode::<Name>(&invalid).is_err());
    }

    proptest! {
        #[test]
        fn valid_names_round_trip(name in "[^/\u{0}]{1,60}") {
            if let Ok(valid) = Name::new(&name) {
                let bytes = minicbor::to_vec(&valid).unwrap();
                prop_assert_eq!(minicbor::decode::<Name>(&bytes).unwrap(), valid.clone());
                prop_assert_eq!(Name::new(valid.as_str()).unwrap(), valid);
            }
        }
    }
}
