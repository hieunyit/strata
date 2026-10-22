//! Per-policy rule actions (RS-1, docs/plan/rule-sets.md): what a policy's
//! rule sets and rule overrides make of a rule, where it differs from the
//! rule's own behaviour. `off`: the rule does not run for the policy;
//! `log`: it runs and is reported with an Event ID, never blocks (like a
//! CRS rule in paranoia shadow); `block`: a match blocks alone, even a
//! rule that only scores (bot lists score 0), and even a rule of the
//! signature pack while the pack is in shadow or off. Rules the engine
//! builds in (100001-100023: protocol checks, bodies it cannot read) are
//! not in the rule table, so no override reaches them.
//!
//! Section OVERRIDE, codec `SOV1` (little-endian): magic, `u32` count, then
//! `(policy_index u32, rule_id u32, action u8, 0 u8, 0 u16)` by increasing
//! (policy, rule); action 0 off, 1 log, 2 block. Every rule ID names a rule
//! of the bundle; the header byte `REQUIRES_OVERRIDE` is set exactly when
//! the section is there.
#![forbid(unsafe_code)]

use crate::bundle::{Error, MAX_POLICIES};

const MAGIC: &[u8; 4] = b"SOV1";
pub const MAX_ENTRIES: usize = 65_536;
const REC: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    Off = 0,
    Log = 1,
    Block = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub policy_index: u32,
    pub rule_id: u32,
    pub action: Action,
}

fn bad() -> Error {
    Error::BadLayout("invalid rule override section")
}

/// Section bytes; empty without overrides.
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
        out.extend_from_slice(&[x.action as u8, 0, 0, 0]);
    }
    Ok(out)
}

/// Per policy index: its overrides as (rule_id, action) by increasing
/// rule_id. `known(rule_id)` tells whether the bundle has that rule.
pub fn parse(
    bytes: &[u8],
    policies: u32,
    known: impl Fn(u32) -> bool,
) -> Result<Vec<Vec<(u32, Action)>>, Error> {
    if policies > MAX_POLICIES {
        return Err(bad());
    }
    let mut out = vec![vec![]; policies as usize];
    if bytes.is_empty() {
        return Ok(out);
    }
    if bytes.len() < 8 || &bytes[..4] != MAGIC {
        return Err(bad());
    }
    let n = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if n == 0 || n > MAX_ENTRIES || bytes.len() != 8 + n * REC {
        return Err(bad());
    }
    let mut prev: Option<(u32, u32)> = None;
    for c in bytes[8..].as_chunks::<REC>().0 {
        let p = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        let r = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        let action = match c[8] {
            0 => Action::Off,
            1 => Action::Log,
            2 => Action::Block,
            _ => return Err(bad()),
        };
        if c[9..] != [0, 0, 0] || p >= policies || prev.is_some_and(|q| q >= (p, r)) || !known(r) {
            return Err(bad());
        }
        prev = Some((p, r));
        out[p as usize].push((r, action));
    }
    Ok(out)
}

/// The action of `rule` in a policy's sorted overrides, if any.
pub fn lookup(overrides: &[(u32, Action)], rule: u32) -> Option<Action> {
    overrides
        .binary_search_by_key(&rule, |&(id, _)| id)
        .ok()
        .map(|k| overrides[k].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(p: u32, r: u32, action: Action) -> Entry {
        Entry {
            policy_index: p,
            rule_id: r,
            action,
        }
    }
    fn known(r: u32) -> bool {
        (942100..=942200).contains(&r) || r == 500200
    }

    #[test]
    fn roundtrip_and_checks() {
        let b = encode(
            &[
                e(1, 942100, Action::Off),
                e(0, 500200, Action::Block),
                e(0, 942100, Action::Log),
            ],
            2,
        )
        .unwrap();
        let s = parse(&b, 2, known).unwrap();
        assert_eq!(s[0], vec![(500200, Action::Block), (942100, Action::Log)]);
        assert_eq!(s[1], vec![(942100, Action::Off)]);
        assert_eq!(lookup(&s[0], 942100), Some(Action::Log));
        assert_eq!(lookup(&s[0], 942101), None);
        assert_eq!(lookup(&s[1], 942100), Some(Action::Off));
        // a rule the bundle does not have
        assert!(parse(&b, 2, |r| r == 942100).is_err());
        // a policy the bundle does not have
        assert!(parse(&b, 1, known).is_err());
        assert_eq!(parse(&[], 2, known).unwrap(), vec![vec![], vec![]]);
        for cut in 1..b.len() {
            assert!(parse(&b[..cut], 2, known).is_err(), "cut {cut}");
        }
        let mut action = b.clone();
        action[8 + 8] = 3;
        assert!(parse(&action, 2, known).is_err());
        for at in 9..12 {
            let mut reserved = b.clone();
            reserved[8 + at] = 1;
            assert!(parse(&reserved, 2, known).is_err());
        }
        let mut magic = b.clone();
        magic[0] = b'X';
        assert!(parse(&magic, 2, known).is_err());
        // out of order
        let mut swapped = b.clone();
        let (a, z) = (8..20, 20..32);
        let first = swapped[a.clone()].to_vec();
        let second = swapped[z.clone()].to_vec();
        swapped[a].copy_from_slice(&second);
        swapped[z].copy_from_slice(&first);
        assert!(parse(&swapped, 2, known).is_err());
        // duplicates and policies out of range refused when encoding
        assert!(encode(&[e(0, 1, Action::Log), e(0, 1, Action::Off)], 1).is_err());
        assert!(encode(&[e(1, 1, Action::Log)], 1).is_err());
        assert_eq!(encode(&[], 1).unwrap(), Vec::<u8>::new());
    }
}
