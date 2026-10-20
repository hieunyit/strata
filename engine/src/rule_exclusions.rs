//! Rule exclusions (W17-S-01: the CRS plugins for WordPress, Drupal…, as
//! ModSecurity's `ctl:ruleRemoveById` / `ctl:ruleRemoveTargetById`).
//!
//! An exclusion rule is a rule record with flag bit 3: its conditions are
//! evaluated, at its stage, before the other rules of that stage; when they
//! match, its removals apply to the rest of the transaction (that stage and
//! the later ones). A removal names a range of rule IDs and either the
//! whole rule (the rules do not run) or one target, a variable and
//! optionally a key (the rules do not see those values). An exclusion rule
//! never scores, never reports. A policy runs only the exclusion rules
//! enabled for it.
//!
//! Section EXCLUSIONS, codec `SXC1` (little-endian):
//!
//! ```text
//! magic "SXC1" | n_rules u32 | n_removals u32 | n_enable u32 | keys_len u32
//! n_rules    x (rule_id u32, removal_first u32, removal_count u32)
//!              by increasing rule_id, removals contiguous from 0, count >= 1
//! n_removals x (lo u32, hi u32, var u8, key_mode u8, 0 u16, key_off u32,
//!              key_len u32); lo <= hi; var 255 = the whole rule (key_mode
//!              0), else a target code; key_mode 0 any key, 1 exact,
//!              2 exact ignoring ASCII case; key 1..=256 bytes iff mode != 0
//! n_enable   x (policy_index u32, rule_id u32) by increasing pair
//! keys       keys_len bytes
//! ```
//!
//! The rule IDs of the section are exactly those of the records with bit
//! 3; anything else refuses the bundle.
#![forbid(unsafe_code)]

use crate::bundle::{Error, MAX_POLICIES};
use std::collections::BTreeSet;

const MAGIC: &[u8; 4] = b"SXC1";
pub const MAX_RULES: usize = 65_536;
pub const MAX_REMOVALS: usize = 1 << 20;
pub const MAX_ENABLE: usize = 1 << 20;
pub const MAX_KEY: usize = 256;
/// `var` of a removal of the whole rule.
pub const WHOLE_RULE: u8 = u8::MAX;
const HEAD: usize = 20;
const RULE_REC: usize = 12;
const REMOVAL_REC: usize = 20;
const ENABLE_REC: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyMode {
    Any = 0,
    Exact = 1,
    Caseless = 2,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Removal {
    pub lo: u32,
    pub hi: u32,
    pub var: u8,
    pub key_mode: KeyMode,
    pub key: Vec<u8>,
}

impl Removal {
    pub fn covers(&self, rule_id: u32) -> bool {
        (self.lo..=self.hi).contains(&rule_id)
    }

    /// The rule `rule_id` does not run.
    pub fn removes_rule(&self, rule_id: u32) -> bool {
        self.var == WHOLE_RULE && self.covers(rule_id)
    }

    /// The rule `rule_id` does not see the value of `var` named `name`
    /// (`None`: a value without a name, e.g. the body).
    pub fn removes_value(&self, rule_id: u32, var: u8, name: Option<&[u8]>) -> bool {
        self.var == var
            && self.covers(rule_id)
            && match self.key_mode {
                KeyMode::Any => true,
                KeyMode::Exact => name == Some(&self.key[..]),
                KeyMode::Caseless => name.is_some_and(|n| n.eq_ignore_ascii_case(&self.key)),
            }
    }

    fn valid(&self, n_vars: usize) -> bool {
        self.lo <= self.hi
            && if self.var == WHOLE_RULE {
                self.key_mode == KeyMode::Any && self.key.is_empty()
            } else {
                (self.var as usize) < n_vars
                    && (self.key_mode == KeyMode::Any) == self.key.is_empty()
                    && self.key.len() <= MAX_KEY
            }
    }
}

/// What makes a rule an exclusion rule, as the compiler reads it from the
/// IR (`exclude`, `metadata.plugin`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleExclusion {
    /// the plugin it comes from (e.g. `wordpress`): a policy runs it when
    /// it lists the plugin in `crs_plugins`
    pub plugin: String,
    pub removals: Vec<Removal>,
}

/// One exclusion rule as the compiler writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Def {
    pub rule_id: u32,
    pub removals: Vec<Removal>,
    /// indexes of the policies that run it
    pub policies: Vec<u32>,
}

/// The section, decoded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exclusions {
    /// (rule_id, removals) by increasing rule_id
    rules: Vec<(u32, Vec<Removal>)>,
    /// per policy index: the rule IDs it runs, increasing
    enabled: Vec<Vec<u32>>,
}

impl Exclusions {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The exclusion rules the policy at `index` runs.
    pub fn enabled(&self, index: u32) -> &[u32] {
        self.enabled.get(index as usize).map_or(&[], |v| &v[..])
    }

    pub fn removals(&self, rule_id: u32) -> &[Removal] {
        self.rules
            .binary_search_by_key(&rule_id, |(id, _)| *id)
            .map_or(&[], |i| &self.rules[i].1[..])
    }
}

/// What a transaction gives one evaluation (`eval::evaluate_with_budget`):
/// the exclusion rules its policy runs, as (rule ID, rule index), and the
/// IDs of those matched so far, which the evaluation extends.
pub struct Pass<'a> {
    pub table: &'a Exclusions,
    pub rules: &'a [(u32, u32)],
    pub active: &'a mut Vec<u32>,
}

fn bad() -> Error {
    Error::BadLayout("invalid rule exclusion section")
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Section bytes; empty without exclusion rules.
pub fn encode(defs: &[Def], n_policies: u32, n_vars: usize) -> Result<Vec<u8>, Error> {
    if defs.is_empty() {
        return Ok(vec![]);
    }
    let mut defs = defs.to_vec();
    defs.sort_by_key(|d| d.rule_id);
    let n_removals: usize = defs.iter().map(|d| d.removals.len()).sum();
    let n_enable: usize = defs.iter().map(|d| d.policies.len()).sum();
    if defs.len() > MAX_RULES
        || n_removals > MAX_REMOVALS
        || n_enable > MAX_ENABLE
        || n_policies > MAX_POLICIES
        || defs.windows(2).any(|w| w[0].rule_id == w[1].rule_id)
    {
        return Err(bad());
    }
    let mut enable = BTreeSet::new();
    for d in &defs {
        if d.removals.is_empty() || d.removals.iter().any(|r| !r.valid(n_vars)) {
            return Err(bad());
        }
        for &p in &d.policies {
            if p >= n_policies || !enable.insert((p, d.rule_id)) {
                return Err(bad());
            }
        }
    }
    let mut keys = vec![];
    let mut out = Vec::with_capacity(
        HEAD + defs.len() * RULE_REC + n_removals * REMOVAL_REC + n_enable * ENABLE_REC,
    );
    out.extend_from_slice(MAGIC);
    for n in [defs.len(), n_removals, n_enable] {
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    let keys_len_at = out.len();
    out.extend_from_slice(&[0; 4]);
    let mut first = 0u32;
    for d in &defs {
        for v in [d.rule_id, first, d.removals.len() as u32] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        first += d.removals.len() as u32;
    }
    for d in &defs {
        for r in &d.removals {
            out.extend_from_slice(&r.lo.to_le_bytes());
            out.extend_from_slice(&r.hi.to_le_bytes());
            out.extend_from_slice(&[r.var, r.key_mode as u8, 0, 0]);
            let off = keys.len() as u32;
            keys.extend_from_slice(&r.key);
            out.extend_from_slice(&off.to_le_bytes());
            out.extend_from_slice(&(r.key.len() as u32).to_le_bytes());
        }
    }
    for (p, id) in enable {
        out.extend_from_slice(&p.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
    }
    let keys_len = u32::try_from(keys.len()).map_err(|_| bad())?;
    out[keys_len_at..keys_len_at + 4].copy_from_slice(&keys_len.to_le_bytes());
    out.extend_from_slice(&keys);
    Ok(out)
}

/// Decodes the section; `flagged` are the IDs of the rule records with bit
/// 3, which must be exactly the section's rules.
pub fn parse(
    bytes: &[u8],
    n_policies: u32,
    flagged: &[u32],
    n_vars: usize,
) -> Result<Exclusions, Error> {
    if n_policies > MAX_POLICIES {
        return Err(bad());
    }
    if bytes.is_empty() {
        return if flagged.is_empty() {
            Ok(Exclusions::default())
        } else {
            Err(bad())
        };
    }
    if bytes.len() < HEAD || &bytes[..4] != MAGIC {
        return Err(bad());
    }
    let (n_rules, n_removals, n_enable, keys_len) = (
        u32_at(bytes, 4) as usize,
        u32_at(bytes, 8) as usize,
        u32_at(bytes, 12) as usize,
        u32_at(bytes, 16) as usize,
    );
    if n_rules == 0 || n_rules > MAX_RULES || n_removals > MAX_REMOVALS || n_enable > MAX_ENABLE {
        return Err(bad());
    }
    let rules_at = HEAD;
    let removals_at = rules_at + n_rules * RULE_REC;
    let enable_at = removals_at + n_removals * REMOVAL_REC;
    let keys_at = enable_at + n_enable * ENABLE_REC;
    if bytes.len() != keys_at + keys_len {
        return Err(bad());
    }
    let keys = &bytes[keys_at..];
    let mut removals = Vec::with_capacity(n_removals);
    for c in bytes[removals_at..enable_at].as_chunks::<REMOVAL_REC>().0 {
        let key_mode = match c[9] {
            0 => KeyMode::Any,
            1 => KeyMode::Exact,
            2 => KeyMode::Caseless,
            _ => return Err(bad()),
        };
        let (off, len) = (u32_at(c, 12) as usize, u32_at(c, 16) as usize);
        if c[10] != 0 || c[11] != 0 || off.checked_add(len).is_none_or(|end| end > keys.len()) {
            return Err(bad());
        }
        let r = Removal {
            lo: u32_at(c, 0),
            hi: u32_at(c, 4),
            var: c[8],
            key_mode,
            key: keys[off..off + len].to_vec(),
        };
        if !r.valid(n_vars) {
            return Err(bad());
        }
        removals.push(r);
    }
    let mut rules: Vec<(u32, Vec<Removal>)> = Vec::with_capacity(n_rules);
    let mut next = 0usize;
    for c in bytes[rules_at..removals_at].as_chunks::<RULE_REC>().0 {
        let (id, first, count) = (u32_at(c, 0), u32_at(c, 4) as usize, u32_at(c, 8) as usize);
        if first != next || count == 0 || rules.last().is_some_and(|(prev, _)| *prev >= id) {
            return Err(bad());
        }
        next = first.checked_add(count).ok_or_else(bad)?;
        if next > n_removals {
            return Err(bad());
        }
        rules.push((id, removals[first..next].to_vec()));
    }
    if next != n_removals {
        return Err(bad());
    }
    let ids: BTreeSet<u32> = rules.iter().map(|(id, _)| *id).collect();
    let expected: BTreeSet<u32> = flagged.iter().copied().collect();
    if expected.len() != flagged.len() || ids != expected {
        return Err(bad());
    }
    let mut enabled = vec![vec![]; n_policies as usize];
    let mut prev = None;
    for c in bytes[enable_at..keys_at].as_chunks::<ENABLE_REC>().0 {
        let pair = (u32_at(c, 0), u32_at(c, 4));
        if pair.0 >= n_policies || !ids.contains(&pair.1) || prev.is_some_and(|p| p >= pair) {
            return Err(bad());
        }
        prev = Some(pair);
        enabled[pair.0 as usize].push(pair.1);
    }
    Ok(Exclusions { rules, enabled })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rm(lo: u32, hi: u32, var: u8, mode: KeyMode, key: &[u8]) -> Removal {
        Removal {
            lo,
            hi,
            var,
            key_mode: mode,
            key: key.to_vec(),
        }
    }

    fn defs() -> Vec<Def> {
        vec![
            Def {
                rule_id: 9_507_100,
                removals: vec![
                    rm(942_100, 942_100, 4, KeyMode::Exact, b"redirect_to"),
                    rm(921_180, 921_180, WHOLE_RULE, KeyMode::Any, b""),
                ],
                policies: vec![1, 0],
            },
            Def {
                rule_id: 9_506_100,
                removals: vec![rm(900_000, 999_999, 8, KeyMode::Caseless, b"X-Token")],
                policies: vec![1],
            },
        ]
    }

    #[test]
    fn roundtrip_and_semantics() {
        let b = encode(&defs(), 2, 31).unwrap();
        let x = parse(&b, 2, &[9_507_100, 9_506_100], 31).unwrap();
        assert_eq!(x.enabled(0), &[9_507_100]);
        assert_eq!(x.enabled(1), &[9_506_100, 9_507_100]);
        assert_eq!(x.enabled(7), &[] as &[u32]);
        let r = x.removals(9_507_100);
        assert_eq!(r.len(), 2);
        assert!(r[0].removes_value(942_100, 4, Some(b"redirect_to")));
        assert!(!r[0].removes_value(942_100, 4, Some(b"Redirect_to")));
        assert!(!r[0].removes_value(942_101, 4, Some(b"redirect_to")));
        assert!(!r[0].removes_value(942_100, 5, Some(b"redirect_to")));
        assert!(!r[0].removes_rule(942_100));
        assert!(r[1].removes_rule(921_180) && !r[1].removes_rule(921_181));
        let h = &x.removals(9_506_100)[0];
        assert!(h.removes_value(942_999, 8, Some(b"x-token")));
        assert!(!h.removes_value(942_999, 8, None));
        assert!(x.removals(1).is_empty());
        assert_eq!(encode(&[], 2, 31).unwrap(), Vec::<u8>::new());
        assert!(parse(&[], 2, &[], 31).unwrap().is_empty());
    }

    #[test]
    fn refuses_bad_sections() {
        let b = encode(&defs(), 2, 31).unwrap();
        // the flagged rules must be exactly the section's
        assert!(parse(&b, 2, &[9_507_100], 31).is_err());
        assert!(parse(&b, 2, &[9_507_100, 9_506_100, 9_506_101], 31).is_err());
        assert!(parse(&[], 2, &[9_507_100], 31).is_err());
        // a policy out of range, a var the engine does not know
        assert!(parse(&b, 1, &[9_507_100, 9_506_100], 31).is_err());
        assert!(parse(&b, 2, &[9_507_100, 9_506_100], 8).is_err());
        for cut in 0..b.len() {
            assert!(
                parse(&b[..cut], 2, &[9_507_100, 9_506_100], 31).is_err(),
                "cut {cut}"
            );
        }
        let mut reserved = b.clone();
        reserved[HEAD + 2 * RULE_REC + 10] = 1;
        assert!(parse(&reserved, 2, &[9_507_100, 9_506_100], 31).is_err());
        let mut mode = b.clone();
        mode[HEAD + 2 * RULE_REC + 9] = 3;
        assert!(parse(&mode, 2, &[9_507_100, 9_506_100], 31).is_err());
        for bad in [
            rm(2, 1, 4, KeyMode::Any, b""),
            rm(1, 2, WHOLE_RULE, KeyMode::Exact, b"a"),
            rm(1, 2, 4, KeyMode::Exact, b""),
            rm(1, 2, 4, KeyMode::Any, b"a"),
            rm(1, 2, 4, KeyMode::Exact, &[b'a'; MAX_KEY + 1]),
        ] {
            let d = Def {
                rule_id: 9_500_000,
                removals: vec![bad.clone()],
                policies: vec![0],
            };
            assert!(encode(&[d], 1, 31).is_err(), "{bad:?}");
        }
        let dup = Def {
            rule_id: 9_500_000,
            removals: vec![rm(1, 1, 4, KeyMode::Any, b"")],
            policies: vec![0, 0],
        };
        assert!(encode(&[dup], 1, 31).is_err());
        let none = Def {
            rule_id: 9_500_000,
            removals: vec![],
            policies: vec![0],
        };
        assert!(encode(&[none], 1, 31).is_err());
    }
}
