//! Enforce canary (nginx-module.md › Bật enforce theo canary): which
//! requests of an enforce policy with a canary share are enforced.
//!
//! A client falls into a bucket in `0..10000` from a stable hash of its key
//! (identity, or the client address when there is none) and the policy name;
//! it is in the canary group when its bucket is below the share in basis
//! points. The same client always gets the same bucket for a policy, on every
//! node and every engine version, so raising the share from 1% to 5% keeps
//! the first 1% inside, and a client never flips between block and shadow.
//! Policies hash apart, so the canary groups of two policies are unrelated.
//!
//! The hash is FNV-1a 64 over `policy || 0xff || key`, finished with the
//! splitmix64 mixer, modulo 10000. It is part of the design (the control
//! plane recomputes it to split canary and shadow metrics), so it must not
//! change. It is not keyed: a client that picks its own identity can pick
//! the shadow side, which only delays its block until the policy is fully
//! enforced; the canary limits the damage of a bad policy, it is not a
//! protection layer.
#![forbid(unsafe_code)]

/// Buckets per policy: canary shares are in basis points.
pub const BUCKETS: u16 = 10_000;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The bucket (`0..BUCKETS`) of a client key for a policy.
pub fn bucket(policy: &[u8], key: &[u8]) -> u16 {
    let h = fnv1a(fnv1a(fnv1a(FNV_OFFSET, policy), &[0xff]), key);
    (mix(h) % u64::from(BUCKETS)) as u16
}

/// The key of a client: its identity when the connector has one, else its
/// address.
pub fn key<'a>(identity: &'a [u8], client_addr: &'a [u8]) -> &'a [u8] {
    if identity.is_empty() {
        client_addr
    } else {
        identity
    }
}

/// Whether the client is in the canary group of a policy whose enforce
/// share is `share` basis points (0 = no canary: everyone is enforced).
pub fn enforced(policy: &[u8], key: &[u8], share: u16) -> bool {
    share == 0 || bucket(policy, key) < share
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values_never_change() {
        // Pinned: the control plane recomputes these (W12-G2-01).
        assert_eq!(bucket(b"example-api", b"192.0.2.1"), 893);
        assert_eq!(bucket(b"example-api", b"user-1"), 3845);
        assert_eq!(bucket(b"example-web", b"192.0.2.1"), 7473);
        assert_eq!(bucket(b"", b""), 4141);
    }

    #[test]
    fn same_client_same_group() {
        for i in 0..1000u32 {
            let k = format!("198.51.100.{}", i % 256);
            let k = format!("{k}-{i}");
            assert_eq!(
                bucket(b"example-api", k.as_bytes()),
                bucket(b"example-api", k.as_bytes())
            );
        }
    }

    #[test]
    fn share_matches_the_rate_and_groups_nest() {
        let n = 200_000u32;
        let mut in_1 = 0u32;
        let mut in_5 = 0u32;
        for i in 0..n {
            let k = format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255);
            let one = enforced(b"example-api", k.as_bytes(), 100);
            let five = enforced(b"example-api", k.as_bytes(), 500);
            assert!(!one || five, "{k}: in the 1% group but not in the 5% one");
            in_1 += u32::from(one);
            in_5 += u32::from(five);
        }
        // 1% of 200k = 2000 (sigma ~ 44), 5% = 10000 (sigma ~ 97)
        assert!((1800..2200).contains(&in_1), "1%: {in_1}");
        assert!((9600..10400).contains(&in_5), "5%: {in_5}");
    }

    #[test]
    fn policies_hash_apart() {
        let both = (0..10_000u32)
            .map(|i| format!("user-{i}"))
            .filter(|k| {
                enforced(b"example-api", k.as_bytes(), 1000)
                    && enforced(b"example-web", k.as_bytes(), 1000)
            })
            .count();
        // independent 10% groups overlap on ~1%
        assert!((50..150).contains(&both), "{both}");
    }

    #[test]
    fn no_share_enforces_everyone_and_identity_wins() {
        assert!(enforced(b"example-api", b"anything", 0));
        assert_eq!(key(b"", b"192.0.2.1"), b"192.0.2.1");
        assert_eq!(key(b"user-1", b"192.0.2.1"), b"user-1");
    }
}
