//! Padmé padding (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and
//! Communication with PURBs", PETS 2019).
//!
//! A padded length reveals only O(log log n) bits about the true length, and never adds more
//! than about 12 %.

/// The padded length for `len` bytes.
///
/// With `E = ⌊log2 len⌋` and `S = ⌊log2 E⌋ + 1`, the lowest `E − S` bits of the result are
/// zero. Lengths below 2 are returned unchanged.
#[must_use]
pub const fn padme(len: u32) -> u64 {
    let len = len as u64;
    if len < 2 {
        return len;
    }
    let exponent = len.ilog2();
    let significant = exponent.ilog2() + 1;
    let mask = (1u64 << (exponent - significant)) - 1;
    (len + mask) & !mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_lengths() {
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(2), 2);
        assert_eq!(padme(3), 3);
        assert_eq!(padme(9), 10);
        assert_eq!(padme(129), 144);
    }

    #[test]
    fn a_one_megabyte_chunk() {
        // E = 19, S = 5: the lowest 14 bits are cleared.
        assert_eq!(padme(1_000_000), 1_015_808);
        assert_eq!(padme(1_048_576), 1_048_576);
    }

    #[test]
    fn bounded_monotonic_and_idempotent() {
        let mut previous = 0;
        for len in (0..200_000).chain((200_000..u32::MAX).step_by(9_999_991)) {
            let padded = padme(len);
            let len = u64::from(len);
            assert!(padded >= len, "{len}");
            // At most 12 % overhead.
            assert!(padded * 100 <= len * 112, "{len} → {padded}");
            assert!(padded >= previous, "{len}");
            previous = padded;
            if let Ok(padded32) = u32::try_from(padded) {
                assert_eq!(padme(padded32), padded, "{len}");
            }
        }
        assert!(padme(u32::MAX) >= u64::from(u32::MAX));
    }
}
