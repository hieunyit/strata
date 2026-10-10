//! Block ID / Event ID generation.
//!
//! 80 bits = 42 bits of Unix time in ms + 10 bits from a hash of
//! `strata_node_id` + 28 random bits, encoded as 16 Crockford base32
//! characters: `STR-XXXX-XXXX-XXXX-XXXX` (block) or `EVT-…` (shadow/error).
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

thread_local! {
    static RNG: Cell<u64> = Cell::new(seed());
}

fn seed() -> u64 {
    // RandomState is keyed from the OS RNG once per thread; no I/O afterwards.
    let mut h = RandomState::new().build_hasher();
    h.write_u128(now_ms().into());
    h.finish() | 1
}

fn next_rand() -> u32 {
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

/// Generates a fresh id for the given node hash.
pub fn generate(kind: Kind, node: u16) -> [u8; ID_LEN] {
    format(kind, pack(now_ms(), node, next_rand()))
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

    #[test]
    fn ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(generate(Kind::Block, 7)));
        }
    }

    #[test]
    fn excludes_ambiguous_letters() {
        for c in b"ILOU" {
            assert!(!CROCKFORD.contains(c));
        }
    }
}
