//! CRS paranoia levels of a policy (W17-S-01): rules with a paranoia level
//! (record byte `paranoia`, the CRS rules) up to `enforce` run as usual;
//! those above it up to `shadow` run and are reported, but their score is
//! kept apart and they never block, like the signature pack in shadow;
//! those above `shadow` do not run. Rules without a level (0) always run.
//! A policy without an entry is (1, 1): CRS paranoia level 1.
//!
//! Section PARANOIA, codec `SPL1` (little-endian): magic, `u32` count, then
//! `(policy_index u32, enforce u8, shadow u8, 0 u16)` by increasing
//! policy, `1 <= enforce <= shadow <= 4`, not (1, 1). The policies with an
//! entry are exactly those with bit 6 of byte 62; engines from before it
//! refuse that bit.
#![forbid(unsafe_code)]

use crate::bundle::{Error, MAX_POLICIES};
use std::collections::BTreeSet;

const MAGIC: &[u8; 4] = b"SPL1";
pub const MAX_LEVEL: u8 = 4;

/// Paranoia levels of one policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Levels {
    pub enforce: u8,
    pub shadow: u8,
}

impl Default for Levels {
    fn default() -> Self {
        Levels {
            enforce: 1,
            shadow: 1,
        }
    }
}

impl Levels {
    pub fn valid(self) -> bool {
        (1..=MAX_LEVEL).contains(&self.enforce) && (self.enforce..=MAX_LEVEL).contains(&self.shadow)
    }
}

/// What a rule of `paranoia` level does for a policy of these levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Enforce,
    Shadow,
    Skip,
}

impl Levels {
    pub fn role(self, paranoia: u8) -> Role {
        if paranoia <= self.enforce {
            Role::Enforce
        } else if paranoia <= self.shadow {
            Role::Shadow
        } else {
            Role::Skip
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub policy_index: u32,
    pub levels: Levels,
}

fn bad() -> Error {
    Error::BadLayout("invalid paranoia section")
}

fn validate(entries: &[Entry], policies: u32) -> Result<(), Error> {
    if policies > MAX_POLICIES || entries.len() > policies as usize {
        return Err(bad());
    }
    let mut seen = BTreeSet::new();
    for e in entries {
        if e.policy_index >= policies
            || !e.levels.valid()
            || e.levels == Levels::default()
            || !seen.insert(e.policy_index)
        {
            return Err(bad());
        }
    }
    Ok(())
}

/// Section bytes; empty when every policy is at (1, 1).
pub fn encode(entries: &[Entry], policies: u32) -> Result<Vec<u8>, Error> {
    validate(entries, policies)?;
    if entries.is_empty() {
        return Ok(vec![]);
    }
    let mut ordered = entries.to_vec();
    ordered.sort_unstable();
    let mut out = Vec::with_capacity(8 + ordered.len() * 8);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(ordered.len() as u32).to_le_bytes());
    for e in ordered {
        out.extend_from_slice(&e.policy_index.to_le_bytes());
        out.extend_from_slice(&[e.levels.enforce, e.levels.shadow, 0, 0]);
    }
    Ok(out)
}

/// Levels per policy index; `flagged` are the policies with bit 6, which
/// must be exactly those of the section.
pub fn parse(bytes: &[u8], policies: u32, flagged: &[u32]) -> Result<Vec<Levels>, Error> {
    if policies > MAX_POLICIES || flagged.len() > policies as usize {
        return Err(bad());
    }
    let mut out = vec![Levels::default(); policies as usize];
    if bytes.is_empty() {
        return if flagged.is_empty() {
            Ok(out)
        } else {
            Err(bad())
        };
    }
    if bytes.len() < 8 || &bytes[..4] != MAGIC {
        return Err(bad());
    }
    let n = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| bad())?) as usize;
    if n == 0 || n > policies as usize || bytes.len() != 8 + n * 8 {
        return Err(bad());
    }
    let mut entries = Vec::with_capacity(n);
    for c in bytes[8..].as_chunks::<8>().0 {
        if c[6] != 0 || c[7] != 0 {
            return Err(bad());
        }
        entries.push(Entry {
            policy_index: u32::from_le_bytes(c[..4].try_into().map_err(|_| bad())?),
            levels: Levels {
                enforce: c[4],
                shadow: c[5],
            },
        });
    }
    validate(&entries, policies)?;
    if entries
        .windows(2)
        .any(|w| w[0].policy_index >= w[1].policy_index)
    {
        return Err(bad());
    }
    let actual: BTreeSet<_> = entries.iter().map(|e| e.policy_index).collect();
    let expected: BTreeSet<_> = flagged.iter().copied().collect();
    if expected.len() != flagged.len() || expected != actual {
        return Err(bad());
    }
    for e in entries {
        out[e.policy_index as usize] = e.levels;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(policy_index: u32, enforce: u8, shadow: u8) -> Entry {
        Entry {
            policy_index,
            levels: Levels { enforce, shadow },
        }
    }

    #[test]
    fn roles() {
        let l = Levels {
            enforce: 1,
            shadow: 2,
        };
        assert_eq!(l.role(0), Role::Enforce); // not a CRS rule
        assert_eq!(l.role(1), Role::Enforce);
        assert_eq!(l.role(2), Role::Shadow);
        assert_eq!(l.role(3), Role::Skip);
        assert_eq!(Levels::default().role(2), Role::Skip);
    }

    #[test]
    fn roundtrip_and_checks() {
        let b = encode(&[e(2, 2, 3), e(0, 1, 2)], 3).unwrap();
        let got = parse(&b, 3, &[0, 2]).unwrap();
        assert_eq!(
            got,
            vec![
                Levels {
                    enforce: 1,
                    shadow: 2
                },
                Levels::default(),
                Levels {
                    enforce: 2,
                    shadow: 3
                }
            ]
        );
        assert_eq!(encode(&[], 3).unwrap(), Vec::<u8>::new());
        assert_eq!(parse(&[], 2, &[]).unwrap(), vec![Levels::default(); 2]);
        // flags must match the section exactly
        assert!(parse(&b, 3, &[0]).is_err());
        assert!(parse(&b, 3, &[0, 1, 2]).is_err());
        assert!(parse(&[], 3, &[1]).is_err());
        // invalid levels, defaults, duplicates, out of range
        for bad in [
            vec![e(0, 0, 1)],
            vec![e(0, 2, 1)],
            vec![e(0, 1, 5)],
            vec![e(0, 1, 1)],
            vec![e(0, 1, 2), e(0, 2, 2)],
            vec![e(3, 1, 2)],
        ] {
            assert!(encode(&bad, 3).is_err(), "{bad:?}");
        }
        for cut in 0..b.len() {
            assert!(parse(&b[..cut], 3, &[0, 2]).is_err(), "cut {cut}");
        }
        let mut reserved = b.clone();
        reserved[14] = 1;
        assert!(parse(&reserved, 3, &[0, 2]).is_err());
        let mut order = b.clone();
        order.swap(8, 16); // policy indexes out of order
        assert!(parse(&order, 3, &[0, 2]).is_err());
    }
}
