use std::fmt;

use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32 secret bytes that are wiped on drop and never printed.
///
/// Nominally `pub` so the sealed key traits may return it; the `secret` module is private, so
/// no other crate can name it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    pub(crate) fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut secret = Self([0; 32]);
        rng.fill_bytes(&mut secret.0);
        secret
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::rng;

    #[test]
    fn random_secrets_differ_and_debug_hides_bytes() {
        let mut rng = rng(1);
        let a = Secret32::random(&mut rng);
        let b = Secret32::random(&mut rng);
        assert_ne!(a.expose(), b.expose());
        assert_ne!(a.expose(), &[0; 32]);
        assert_eq!(format!("{a:?}"), "Secret32(..)");
        assert_eq!(Secret32::from_bytes([7; 32]).expose(), &[7; 32]);
    }
}
