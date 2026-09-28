//! oxidrive cryptography: keys, envelopes, suites, AEAD, signatures, hybrid post-quantum key
//! wrapping.
//!
//! This crate is the only place in oxidrive that touches cryptographic primitives. Everything
//! else goes through the small, typed API here:
//!
//! - [`aead`]: XChaCha20-Poly1305 encryption with random nonces.
//! - [`hash`]: BLAKE3 hashing, keyed hashing (content IDs) and the chunking gear table.
//! - [`sign`]: Ed25519 signatures, always bound to a [`sign::SignContext`].
//! - [`kem`]: wrapping keys to a public key with HPKE and the X-Wing hybrid KEM
//!   (X25519 + ML-KEM-768).
//! - [`keys`]: the key hierarchy, one type per key, so keys can't be mixed up.
//! - [`recovery`]: the 24-word recovery key.
//! - [`suite`]: the suite identifier stored with every encrypted object.
//!
//! The crate performs no I/O and never gathers randomness on its own: every function that
//! needs randomness takes a [`CryptoRng`] from the caller. Secret types wipe themselves on
//! drop and never reveal their bytes through `Debug`.

pub mod aead;
pub mod hash;
pub mod kem;
pub mod keys;
pub mod recovery;
pub mod sign;
pub mod suite;

mod context;
mod error;
mod secret;
#[cfg(test)]
mod test_util;

pub use error::{CryptoError, RecoveryPhraseError};
pub use rand_core::CryptoRng;
