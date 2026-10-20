//! Policy-scoped rules (W19-G2-01): a rule record with flag bit 4 runs only
//! for the policies section SCOPE lists it for, each in a mode: enforce
//! (as any rule) or log (reported with an Event ID, kept apart, never
//! blocks, like a CRS rule in paranoia shadow). The compiler makes them
//! from a policy's own rules (`geo_rules`).
//!
//! Section SCOPE, codec `SSC1` (little-endian): magic, `u32` count, then
//! `(policy_index u32, rule_id u32, mode u8, 0 u8, 0 u16)` by increasing
//! (policy, rule); mode 0 enforce, 1 log. The rule IDs of the section are
//! exactly those of the records with bit 4; anything else refuses the
//! bundle.
#![forbid(unsafe_code)]

use crate::bundle::{Error, MAX_POLICIES};
use std::collections::BTreeSet;

const MAGIC: &[u8; 4] = b"SSC1";
pub const MAX_ENTRIES: usize = 65_536;
const REC: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    Enforce = 0,
    Log = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub policy_index: u32,
    pub rule_id: u32,
    pub mode: Mode,
}

fn bad() -> Error {
    Error::BadLayout("invalid rule scope section")
}

/// Section bytes; empty without scoped rules.
pub fn encode(entries: &[Entry], policies: u32) -> Result<Vec<u8>, Error> {
    if entries.is_empty() {
        return Ok(vec![]);
    }
    let mut e = entries.to_vec();
    e.sort_unstable();
    if e.len() > MAX_ENTRIES
        || policies > MAX_POLICIES
        || e.iter().any(|x| x.policy_index >= policies)
        || e.windows(2)
            .any(|w| (w[0].policy_index, w[0].rule_id) == (w[1].policy_index, w[1].rule_id))
    {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(8 + e.len() * REC);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(e.len() as u32).to_le_bytes());
    for x in e {
        out.extend_from_slice(&x.policy_index.to_le_bytes());
        out.extend_from_slice(&x.rule_id.to_le_bytes());
        out.extend_from_slice(&[x.mode as u8, 0, 0, 0]);
    }
    Ok(out)
}

/// Per policy index: its scoped rules, as (rule_id, mode) by increasing
/// rule_id. `flagged` are the IDs of the records with bit 4.
pub fn parse(bytes: &[u8], policies: u32, flagged: &[u32]) -> Result<Vec<Vec<(u32, Mode)>>, Error> {
    if policies > MAX_POLICIES {
        return Err(bad());
    }
    let mut out = vec![vec![]; policies as usize];
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
    let n = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if n == 0 || n > MAX_ENTRIES || bytes.len() != 8 + n * REC {
        return Err(bad());
    }
    let mut ids = BTreeSet::new();
    let mut prev: Option<(u32, u32)> = None;
    for c in bytes[8..].as_chunks::<REC>().0 {
        let p = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        let r = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        let mode = match c[8] {
            0 => Mode::Enforce,
            1 => Mode::Log,
            _ => return Err(bad()),
        };
        if c[9..] != [0, 0, 0] || p >= policies || prev.is_some_and(|q| q >= (p, r)) {
            return Err(bad());
        }
        prev = Some((p, r));
        ids.insert(r);
        out[p as usize].push((r, mode));
    }
    let expected: BTreeSet<u32> = flagged.iter().copied().collect();
    if expected.len() != flagged.len() || ids != expected {
        return Err(bad());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(p: u32, r: u32, mode: Mode) -> Entry {
        Entry {
            policy_index: p,
            rule_id: r,
            mode,
        }
    }

    #[test]
    fn roundtrip_and_checks() {
        let b = encode(
            &[
                e(1, 190001, Mode::Log),
                e(0, 190001, Mode::Enforce),
                e(0, 190000, Mode::Enforce),
            ],
            2,
        )
        .unwrap();
        let s = parse(&b, 2, &[190000, 190001]).unwrap();
        assert_eq!(s[0], vec![(190000, Mode::Enforce), (190001, Mode::Enforce)]);
        assert_eq!(s[1], vec![(190001, Mode::Log)]);
        assert!(parse(&b, 2, &[190000]).is_err());
        assert!(parse(&b, 2, &[190000, 190001, 190002]).is_err());
        assert!(parse(&b, 1, &[190000, 190001]).is_err());
        assert!(parse(&[], 2, &[190000]).is_err());
        assert_eq!(parse(&[], 2, &[]).unwrap(), vec![vec![], vec![]]);
        for cut in 1..b.len() {
            assert!(parse(&b[..cut], 2, &[190000, 190001]).is_err(), "cut {cut}");
        }
        let mut mode = b.clone();
        mode[8 + 8] = 2;
        assert!(parse(&mode, 2, &[190000, 190001]).is_err());
        let mut reserved = b.clone();
        reserved[8 + 9] = 1;
        assert!(parse(&reserved, 2, &[190000, 190001]).is_err());
        assert!(encode(&[e(0, 1, Mode::Log), e(0, 1, Mode::Enforce)], 1).is_err());
        assert!(encode(&[e(1, 1, Mode::Log)], 1).is_err());
    }
}
