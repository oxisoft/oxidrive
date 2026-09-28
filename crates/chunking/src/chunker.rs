//! Keyed content-defined chunking.
//!
//! The cut-point search is the `fastcdc` crate's `FastCDC` 2020 (`v2020::cut_gear`, normalisation
//! level 1), called with a gear table derived from the collection's chunking key instead of
//! the public one. Boundaries therefore follow the content (an insertion moves only nearby
//! boundaries) but can't be predicted without the key (chunking design §3).

use std::fmt;

use fastcdc::v2020::{self, Normalization};
use oxisoft_drive_crypto::hash::{GEAR_TABLE_LEN, gear_table};
use oxisoft_drive_crypto::keys::ChunkingKey;

use crate::ChunkError;

/// Minimum, average and maximum chunk size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkParams {
    min: u32,
    avg: u32,
    max: u32,
}

impl ChunkParams {
    /// 256 KiB / 1 MiB / 4 MiB (decision K1).
    pub const DEFAULT: Self = Self {
        min: 256 * 1024,
        avg: 1024 * 1024,
        max: 4 * 1024 * 1024,
    };

    /// Custom parameters: even numbers, `min < avg < max`, each within the supported
    /// range (min 64 B–1 MiB, average 256 B–4 MiB, max 1 KiB–16 MiB).
    ///
    /// # Errors
    ///
    /// [`ChunkError::InvalidParams`] otherwise.
    pub const fn new(min: u32, avg: u32, max: u32) -> Result<Self, ChunkError> {
        let even = min.is_multiple_of(2) && avg.is_multiple_of(2) && max.is_multiple_of(2);
        let ordered = min < avg && avg < max;
        let in_range = min >= 64
            && min <= 1024 * 1024
            && avg >= 256
            && avg <= 4 * 1024 * 1024
            && max >= 1024
            && max <= 16 * 1024 * 1024;
        if even && ordered && in_range {
            Ok(Self { min, avg, max })
        } else {
            Err(ChunkError::InvalidParams)
        }
    }

    /// Minimum chunk size (the last chunk of a file may be smaller).
    #[must_use]
    pub const fn min(&self) -> u32 {
        self.min
    }

    /// Target average chunk size.
    #[must_use]
    pub const fn avg(&self) -> u32 {
        self.avg
    }

    /// Maximum chunk size.
    #[must_use]
    pub const fn max(&self) -> u32 {
        self.max
    }
}

impl Default for ChunkParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Finds chunk boundaries for one collection and key epoch.
pub struct Chunker {
    gear: Box<[u64; GEAR_TABLE_LEN]>,
    gear_ls: Box<[u64; GEAR_TABLE_LEN]>,
    params: ChunkParams,
    mask_s: u64,
    mask_l: u64,
}

impl Chunker {
    /// A chunker whose boundaries are keyed by `key`.
    #[must_use]
    pub fn new(key: &ChunkingKey, params: ChunkParams) -> Self {
        Self::with_gear(gear_table(key), params)
    }

    /// A chunker with an explicit gear table. `gear_ls[i] = gear[i] << 1` is the relation
    /// `fastcdc` uses for its own tables; it makes the two-bytes-per-step scan equal to the
    /// byte-by-byte gear hash.
    pub(crate) fn with_gear(gear: Box<[u64; GEAR_TABLE_LEN]>, params: ChunkParams) -> Self {
        let gear_ls = Box::new(gear.map(|entry| entry << 1));
        let (mask_s, mask_l) = v2020::select_masks(params.avg as usize, Normalization::Level1);
        Self {
            gear,
            gear_ls,
            params,
            mask_s,
            mask_l,
        }
    }

    /// The parameters in use.
    #[must_use]
    pub const fn params(&self) -> ChunkParams {
        self.params
    }

    /// The length of the next chunk of `window`, which must start at a chunk boundary.
    ///
    /// Returns `None` when the cut can't be decided yet, because `window` holds fewer than
    /// `max` bytes and more data may follow (`at_eof` false), or when `window` is empty. A
    /// streaming caller keeps at least `max` bytes buffered (or the rest of the file), asks,
    /// emits that many bytes, and refills. The results are identical to [`Chunker::chunks`]
    /// over the whole data.
    #[must_use]
    pub fn next_cut(&self, window: &[u8], at_eof: bool) -> Option<usize> {
        let max = self.params.max as usize;
        if window.is_empty() || (!at_eof && window.len() < max) {
            return None;
        }
        let (_, length) = v2020::cut_gear(
            window,
            self.params.min as usize,
            self.params.avg as usize,
            max,
            self.mask_s,
            self.mask_l,
            self.mask_s << 1,
            self.mask_l << 1,
            self.gear.as_slice(),
            self.gear_ls.as_slice(),
        );
        Some(length)
    }

    /// The chunks of data already in memory.
    #[must_use]
    pub const fn chunks<'a>(&'a self, data: &'a [u8]) -> Chunks<'a> {
        Chunks {
            chunker: self,
            rest: data,
        }
    }
}

impl fmt::Debug for Chunker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunker")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

/// Iterator over the chunks of in-memory data; see [`Chunker::chunks`].
#[derive(Debug)]
pub struct Chunks<'a> {
    chunker: &'a Chunker,
    rest: &'a [u8],
}

impl<'a> Iterator for Chunks<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let length = self.chunker.next_cut(self.rest, true)?;
        let (chunk, rest) = self.rest.split_at(length);
        self.rest = rest;
        Some(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxisoft_drive_crypto::keys::CollectionKey;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{Rng, SeedableRng};

    const SMALL: ChunkParams = ChunkParams {
        min: 64,
        avg: 256,
        max: 1024,
    };

    fn random_bytes(seed: u8, len: usize) -> Vec<u8> {
        let mut data = vec![0; len];
        ChaCha20Rng::from_seed([seed; 32]).fill_bytes(&mut data);
        data
    }

    fn fastcdc_tables() -> Box<[u64; GEAR_TABLE_LEN]> {
        let (gear, _) = v2020::get_gear_with_seed(0);
        Box::new(<[u64; GEAR_TABLE_LEN]>::try_from(&*gear).unwrap())
    }

    fn keyed(seed: u8, params: ChunkParams) -> Chunker {
        let key = CollectionKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]), 0);
        Chunker::new(&key.chunking(), params)
    }

    fn lengths(chunker: &Chunker, data: &[u8]) -> Vec<usize> {
        chunker.chunks(data).map(<[u8]>::len).collect()
    }

    #[test]
    fn fastcdc_derives_its_shifted_table_the_same_way() {
        let (gear, gear_ls) = v2020::get_gear_with_seed(0);
        for (plain, shifted) in gear.iter().zip(gear_ls.iter()) {
            assert_eq!(plain << 1, *shifted);
        }
    }

    /// With fastcdc's own public tables, our chunker must cut exactly where fastcdc does.
    #[test]
    fn matches_fastcdc_with_its_own_tables() {
        for (params, len) in [(SMALL, 200_000), (ChunkParams::DEFAULT, 12 * 1024 * 1024)] {
            let data = random_bytes(1, len);
            let ours = lengths(&Chunker::with_gear(fastcdc_tables(), params), &data);
            let reference: Vec<usize> = v2020::FastCDC::with_level(
                &data,
                params.min as usize,
                params.avg as usize,
                params.max as usize,
                Normalization::Level1,
            )
            .map(|chunk| chunk.length)
            .collect();
            assert!(ours.len() > 3, "{params:?}");
            assert_eq!(ours, reference, "{params:?}");
        }
    }

    #[test]
    fn keys_change_the_boundaries() {
        let data = random_bytes(2, 100_000);
        let a = lengths(&keyed(10, SMALL), &data);
        assert_eq!(a, lengths(&keyed(10, SMALL), &data));
        assert_ne!(a, lengths(&keyed(11, SMALL), &data));
        assert_ne!(
            a,
            lengths(&Chunker::with_gear(fastcdc_tables(), SMALL), &data)
        );
    }

    #[test]
    fn undecidable_windows_ask_for_more() {
        let chunker = keyed(3, SMALL);
        assert_eq!(chunker.next_cut(&[], true), None);
        assert_eq!(chunker.next_cut(&[], false), None);
        assert_eq!(chunker.next_cut(&[0; 1023], false), None);
        assert!(chunker.next_cut(&[0; 1024], false).is_some());
        assert_eq!(chunker.next_cut(&[7; 10], true), Some(10));
        // Constant data has no content boundaries: chunks are cut at `max`.
        assert_eq!(chunker.next_cut(&[0; 5000], true), Some(1024));
        assert_eq!(chunker.params(), SMALL);
        assert_eq!(chunker.chunks(&[]).count(), 0);
    }

    #[test]
    fn params_are_validated() {
        let defaults = ChunkParams::default();
        assert_eq!(
            (defaults.min(), defaults.avg(), defaults.max()),
            (262_144, 1_048_576, 4_194_304)
        );
        assert_eq!(ChunkParams::new(64, 256, 1024), Ok(SMALL));
        for (min, avg, max) in [
            (65, 256, 1024),
            (64, 257, 1024),
            (64, 256, 1025),
            (256, 256, 1024),
            (64, 1024, 1024),
            (62, 256, 1024),
            (2 * 1024 * 1024, 3 * 1024 * 1024, 8 * 1024 * 1024),
            (64, 128, 1024),
            (64, 8 * 1024 * 1024, 16 * 1024 * 1024),
            (64, 256, 512),
            (64, 256, 32 * 1024 * 1024),
        ] {
            assert_eq!(
                ChunkParams::new(min, avg, max),
                Err(ChunkError::InvalidParams),
                "{min} {avg} {max}"
            );
        }
        let text = format!("{:?}", keyed(4, SMALL));
        assert!(text.starts_with("Chunker { params:"), "{text}");
        assert!(!text.contains("gear"), "{text}");
    }

    /// Boundaries after an insertion line up again, and from there on every chunk is
    /// identical: what keeps delta sync cheap. How soon this happens is probabilistic, so it is
    /// checked on fixed inputs (including the case that exposed the old, flaky bound).
    #[test]
    fn boundaries_resynchronise_after_an_insertion() {
        for (seed, at, insert) in [
            (16, 16_933, 135),
            (1, 0, 1),
            (2, 50_000, 199),
            (3, 99_000, 10),
            (4, 1_234, 64),
            (5, 70_001, 1),
        ] {
            let data = random_bytes(seed, 100_000);
            let mut edited = data.clone();
            edited.splice(at..at, random_bytes(seed.wrapping_add(1), insert));
            let chunker = keyed(seed, SMALL);
            let offsets = |bytes: &[u8]| -> Vec<usize> {
                chunker
                    .chunks(bytes)
                    .scan(0, |end, chunk| {
                        *end += chunk.len();
                        Some(*end)
                    })
                    .collect()
            };
            let before = offsets(&data);
            // Boundaries after the insertion, moved back into the original's coordinates.
            let after: Vec<usize> = offsets(&edited)
                .into_iter()
                .filter(|&end| end >= at + insert)
                .map(|end| end - insert)
                .collect();
            let resync = after
                .iter()
                .find(|end| before.contains(end))
                .copied()
                .unwrap();
            assert!(resync <= at + 4 * 1024, "seed {seed}: resync at {resync}");
            let tail = |ends: &[usize]| -> Vec<usize> {
                ends.iter().copied().filter(|&end| end >= resync).collect()
            };
            assert_eq!(tail(&before), tail(&after), "seed {seed}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn chunks_rejoin_and_respect_the_size_limits(seed in any::<u8>(), len in 0usize..60_000) {
            let data = random_bytes(seed, len);
            let chunker = keyed(seed, SMALL);
            let chunks: Vec<&[u8]> = chunker.chunks(&data).collect();
            prop_assert_eq!(&chunks.concat(), &data);
            if let Some((_, all_but_last)) = chunks.split_last() {
                for chunk in all_but_last {
                    prop_assert!((64..=1024).contains(&chunk.len()));
                }
            }
            for chunk in &chunks {
                prop_assert!(!chunk.is_empty() && chunk.len() <= 1024);
            }
        }

        #[test]
        fn streaming_matches_in_memory(seed in any::<u8>(), len in 0usize..40_000, refill in 1usize..3000) {
            let data = random_bytes(seed, len);
            let chunker = keyed(seed, SMALL);
            let expected = lengths(&chunker, &data);

            // Feed the data in pieces of `refill` bytes, cutting whenever a cut is decidable.
            let mut buffer = Vec::new();
            let mut fed = 0;
            let mut streamed = Vec::new();
            loop {
                let at_eof = fed == data.len();
                match chunker.next_cut(&buffer, at_eof) {
                    Some(length) => {
                        streamed.push(length);
                        buffer.drain(..length);
                    }
                    None if at_eof => break,
                    None => {
                        let end = (fed + refill).min(data.len());
                        buffer.extend_from_slice(&data[fed..end]);
                        fed = end;
                    }
                }
            }
            prop_assert_eq!(streamed, expected);
        }

        /// A cut depends only on the bytes of its own window (at most `max` bytes) and, near
        /// the end of the data, on how much remains. So every chunk that starts at least `max`
        /// bytes before an insertion is guaranteed unchanged.
        #[test]
        fn chunks_well_before_an_insertion_are_unchanged(seed in any::<u8>(), at in 0usize..100_000, insert in 1usize..200) {
            let data = random_bytes(seed, 100_000);
            let mut edited = data.clone();
            edited.splice(at..at, random_bytes(seed.wrapping_add(1), insert));
            let chunker = keyed(seed, SMALL);
            let after: Vec<&[u8]> = chunker.chunks(&edited).collect();
            let mut start = 0;
            for (i, chunk) in chunker.chunks(&data).enumerate() {
                if start + 1024 > at {
                    break;
                }
                prop_assert_eq!(after[i], chunk);
                start += chunk.len();
            }
        }
    }
}
