//! Helpers shared by the unit tests.

use std::fmt::Write as _;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// A deterministic RNG, so every test run sees the same keys.
pub(crate) fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

/// Lower-case hex.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Parses hex, ignoring whitespace (test vectors are often wrapped).
pub(crate) fn from_hex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Parses hex into a fixed-size array.
pub(crate) fn from_hex_array<const N: usize>(text: &str) -> [u8; N] {
    from_hex(text).try_into().unwrap()
}
