//! Block ID / Event ID generation.
//!
//! 80 bits = 42 bits of Unix time in ms + 10 bits from a hash of
//! `strata_node_id` + 28 bits of sequence, encoded as 16 Crockford base32
//! characters: `STR-XXXX-XXXX-XXXX-XXXX` (block) or `EVT-…` (shadow/error).
//!
//! The 28 bits are monotonic within a millisecond (ULID style): each new
//! millisecond starts at a random value below 2^27, then every id of that
//! millisecond takes the next value, so one thread never repeats an id even
//! in a burst. When a millisecond runs out of values, the next one is
//! borrowed. Workers of one node only collide if two of them generate ids
//! in the same millisecond from overlapping random starts.
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Formatted id length without the trailing NUL.
pub const ID_LEN: usize = 23;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Block,
    Event,
}

/// 10-bit FNV-1a hash of the node name.
pub fn node_hash(node_id: &[u8]) -> u16 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in node_id {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    ((h ^ (h >> 10) ^ (h >> 20)) & 0x3ff) as u16
}

/// Packs the 80-bit id: time(42) | node(10) | random(28).
pub fn pack(ms: u64, node: u16, rand: u32) -> u128 {
    (u128::from(ms & ((1 << 42) - 1)) << 38)
        | (u128::from(node & 0x3ff) << 28)
        | u128::from(rand & 0x0fff_ffff)
}

/// Formats an 80-bit value as `PFX-XXXX-XXXX-XXXX-XXXX`.
pub fn format(kind: Kind, bits: u128) -> [u8; ID_LEN] {
    let mut out = [b'-'; ID_LEN];
    out[..3].copy_from_slice(match kind {
        Kind::Block => b"STR",
        Kind::Event => b"EVT",
    });
    for i in 0..16 {
        let shift = 75 - 5 * i;
        let sym = ((bits >> shift) & 0x1f) as usize;
        out[4 + i + i / 4] = CROCKFORD[sym];
    }
    out
}

/// Decodes the 80-bit value back from a formatted id (used by tests and tools).
pub fn parse(id: &[u8]) -> Option<(Kind, u128)> {
    if id.len() != ID_LEN {
        return None;
    }
    let kind = match &id[..4] {
        b"STR-" => Kind::Block,
        b"EVT-" => Kind::Event,
        _ => return None,
    };
    let mut bits: u128 = 0;
    for (i, &c) in id[4..].iter().enumerate() {
        if i % 5 == 4 {
            if c != b'-' {
                return None;
            }
            continue;
        }
        let v = CROCKFORD.iter().position(|&s| s == c)?;
        bits = (bits << 5) | v as u128;
    }
    Some((kind, bits))
}

const SEQ_MAX: u32 = (1 << 28) - 1;
const SEQ_START_MASK: u32 = (1 << 27) - 1;

thread_local! {
    static RNG: Cell<u64> = Cell::new(seed());
    /// (millisecond, last sequence) of the last id made by this thread.
    static LAST: Cell<(u64, u32)> = const { Cell::new((0, 0)) };
}

fn seed() -> u64 {
    // RandomState is keyed from the OS RNG once per thread; no I/O afterwards.
    let mut h = RandomState::new().build_hasher();
    h.write_u128(now_ms().into());
    h.finish() | 1
}

pub(crate) fn next_rand() -> u32 {
    RNG.with(|s| {
        // SplitMix64: uniqueness, not secrecy, is what matters here.
        let mut z = s.get().wrapping_add(0x9e37_79b9_7f4a_7c15);
        s.set(z);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        ((z ^ (z >> 31)) >> 32) as u32
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Next (millisecond, sequence) after `last` at time `now`. Never goes back,
/// even if the clock does.
fn advance(last: (u64, u32), now: u64, rand: u32) -> (u64, u32) {
    let (ms, seq) = last;
    if now > ms {
        (now, rand & SEQ_START_MASK)
    } else if seq < SEQ_MAX {
        (ms, seq + 1)
    } else {
        (ms + 1, rand & SEQ_START_MASK)
    }
}

/// Generates a fresh id for the given node hash.
pub fn generate(kind: Kind, node: u16) -> [u8; ID_LEN] {
    let (ms, seq) = LAST.with(|l| {
        let next = advance(l.get(), now_ms(), next_rand());
        l.set(next);
        next
    });
    format(kind, pack(ms, node, seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn well_formed(id: &[u8]) -> bool {
        id.len() == ID_LEN
            && id.iter().enumerate().all(|(i, &c)| match i {
                3 | 8 | 13 | 18 => c == b'-',
                0..=2 => c.is_ascii_uppercase(),
                _ => CROCKFORD.contains(&c),
            })
    }

    #[test]
    fn format_matches_spec() {
        let id = generate(Kind::Block, node_hash(b"web-01"));
        assert!(well_formed(&id), "{}", String::from_utf8_lossy(&id));
        assert_eq!(&id[..4], b"STR-");
        assert_eq!(&generate(Kind::Event, 0)[..4], b"EVT-");
    }

    #[test]
    fn round_trip_fields() {
        let bits = pack(0x2ab_cdef_0123, 0x155, 0x0abc_def1);
        let id = format(Kind::Block, bits);
        let (kind, back) = parse(&id).unwrap();
        assert_eq!(kind, Kind::Block);
        assert_eq!(back, bits);
        assert_eq!((back >> 38) as u64, 0x2ab_cdef_0123);
        assert_eq!(((back >> 28) & 0x3ff) as u16, 0x155);
        assert_eq!((back & 0x0fff_ffff) as u32, 0x0abc_def1);
    }

    #[test]
    fn node_hash_is_10_bits_and_embedded() {
        let n = node_hash(b"api.example.test");
        assert!(n < 1024);
        let (_, bits) = parse(&generate(Kind::Block, n)).unwrap();
        assert_eq!(((bits >> 28) & 0x3ff) as u16, n);
    }

    fn well_formed_all(ids: &[[u8; ID_LEN]]) {
        for id in ids {
            assert!(well_formed(id), "{}", String::from_utf8_lossy(id));
        }
    }

    #[test]
    fn ids_are_unique_in_a_burst() {
        let ids: Vec<_> = (0..200_000).map(|_| generate(Kind::Block, 7)).collect();
        well_formed_all(&ids);
        let mut bits: Vec<u128> = ids.iter().map(|id| parse(id).unwrap().1).collect();
        // monotonic within a thread
        assert!(bits.windows(2).all(|w| w[0] < w[1]));
        bits.dedup();
        assert_eq!(bits.len(), 200_000);
    }

    /// Per-thread state: threads of different nodes never collide. (Threads
    /// or workers of the *same* node only collide when two of them pick
    /// overlapping random starts in the same millisecond; see module docs.)
    #[test]
    fn ids_are_unique_across_threads() {
        let all: Vec<u128> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8u16)
                .map(|node| {
                    s.spawn(move || {
                        (0..100_000)
                            .map(|_| parse(&generate(Kind::Block, node)).unwrap().1)
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len());
    }

    /// W03-R-02: 10 million ids, unique and well formed. Slow unoptimized:
    /// `cargo test --release -p libstrata -- --ignored ten_million`.
    #[test]
    #[ignore]
    fn ten_million_ids_unique_and_well_formed() {
        const N: usize = 10_000_000;
        let mut bits = Vec::with_capacity(N);
        for _ in 0..N {
            let id = generate(Kind::Block, node_hash(b"web-01"));
            assert!(well_formed(&id), "{}", String::from_utf8_lossy(&id));
            bits.push(parse(&id).unwrap().1);
        }
        bits.sort_unstable();
        bits.dedup();
        assert_eq!(bits.len(), N);
    }

    #[test]
    fn sequence_rolls_into_the_next_millisecond() {
        assert_eq!(advance((5, 10), 5, 0), (5, 11));
        assert_eq!(advance((5, SEQ_MAX), 5, 3), (6, 3));
        // clock going backwards does not reuse an id
        assert_eq!(advance((9, 1), 4, 0), (9, 2));
        // a new millisecond starts low enough to leave room for a burst
        assert!(advance((1, 0), 2, u32::MAX).1 <= SEQ_START_MASK);
    }

    #[test]
    fn excludes_ambiguous_letters() {
        for c in b"ILOU" {
            assert!(!CROCKFORD.contains(c));
        }
    }
}
