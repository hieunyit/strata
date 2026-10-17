//! Bounded codec for a signed policy/rule log-only overlay. This module alone
//! does not enable runtime staging or authorize automatic policy changes.
#![forbid(unsafe_code)]

use crate::bundle::{Error, MAX_POLICIES};
use std::collections::BTreeSet;

pub const MAX_ENTRIES: usize = 4096;
pub const MAX_PER_POLICY: usize = 16;
const MAGIC: &[u8; 4] = b"SSG1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    pub policy_index: u32,
    pub rule_id: u32,
}

fn bad() -> Error {
    Error::BadLayout("invalid policy staging section")
}

fn validate(entries: &[Entry], policies: u32) -> Result<(), Error> {
    if policies > MAX_POLICIES || entries.len() > MAX_ENTRIES {
        return Err(bad());
    }
    let mut seen = BTreeSet::new();
    let mut counts = vec![0; policies as usize];
    for e in entries {
        if e.policy_index >= policies || e.rule_id == 0 || !seen.insert(*e) {
            return Err(bad());
        }
        counts[e.policy_index as usize] += 1;
        if counts[e.policy_index as usize] > MAX_PER_POLICY {
            return Err(bad());
        }
    }
    Ok(())
}

// Empty overlays emit no section. Records have canonical policy/rule order.
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
        out.extend_from_slice(&e.rule_id.to_le_bytes());
    }
    Ok(out)
}

// The flag list must exactly match policies represented in the section.
// Managed request-rule membership must be checked by compiler/engine callers.
pub fn parse(bytes: &[u8], policies: u32, flagged: &[u32]) -> Result<Vec<Entry>, Error> {
    if policies > MAX_POLICIES || flagged.len() > policies as usize {
        return Err(bad());
    }
    if bytes.is_empty() {
        return if flagged.is_empty() {
            Ok(vec![])
        } else {
            Err(bad())
        };
    }
    if bytes.len() < 8 || &bytes[..4] != MAGIC {
        return Err(bad());
    }
    let n = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| bad())?) as usize;
    if n == 0 || n > MAX_ENTRIES || bytes.len() != 8 + n * 8 {
        return Err(bad());
    }
    let mut entries = Vec::with_capacity(n);
    for c in bytes[8..].as_chunks::<8>().0 {
        entries.push(Entry {
            policy_index: u32::from_le_bytes(c[..4].try_into().map_err(|_| bad())?),
            rule_id: u32::from_le_bytes(c[4..].try_into().map_err(|_| bad())?),
        });
    }
    validate(&entries, policies)?;
    if entries.windows(2).any(|w| w[0] >= w[1]) {
        return Err(bad());
    }
    let actual: BTreeSet<_> = entries.iter().map(|e| e.policy_index).collect();
    let expected: BTreeSet<_> = flagged.iter().copied().collect();
    if expected.len() != flagged.len() || expected != actual {
        return Err(bad());
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(policy_index: u32, rule_id: u32) -> Entry {
        Entry {
            policy_index,
            rule_id,
        }
    }

    #[test]
    fn canonical_roundtrip_and_absent_default() {
        let entries = [e(1, u32::MAX), e(0, 42), e(0, 7)];
        let mut sorted = entries;
        sorted.sort_unstable();
        let bytes = encode(&entries, 2).unwrap();
        assert_eq!(bytes, encode(&sorted, 2).unwrap());
        assert_eq!(parse(&bytes, 2, &[0, 1]).unwrap(), sorted);
        assert!(encode(&[], 2).unwrap().is_empty());
        assert!(parse(&[], 2, &[]).unwrap().is_empty());
        assert!(parse(&[], 2, &[0]).is_err());
    }

    #[test]
    fn rejects_malformed_counts_records_and_flags() {
        let bytes = encode(&[e(0, 7), e(1, 42)], 2).unwrap();
        for len in 0..bytes.len() {
            assert!(parse(&bytes[..len], 2, &[0, 1]).is_err());
        }
        for flags in [&[][..], &[0][..], &[0, 0][..], &[0, 2][..]] {
            assert!(parse(&bytes, 2, flags).is_err());
        }
        for (offset, value) in [(0, 0), (4, 0), (4, 255), (8, 2), (12, 0)] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(parse(&bad, 2, &[0, 1]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(parse(&extra, 2, &[0, 1]).is_err());
        let mut reversed = bytes.clone();
        reversed[8..16].copy_from_slice(&bytes[16..24]);
        reversed[16..24].copy_from_slice(&bytes[8..16]);
        assert!(parse(&reversed, 2, &[0, 1]).is_err());
        let mut duplicate = bytes.clone();
        duplicate[16..24].copy_from_slice(&bytes[8..16]);
        assert!(parse(&duplicate, 2, &[0, 1]).is_err());
        assert!(encode(&[e(0, 0)], 1).is_err());
        assert!(encode(&[e(1, 7)], 1).is_err());
        assert!(encode(&[e(0, 7), e(0, 7)], 1).is_err());
        assert!(encode(&[], MAX_POLICIES + 1).is_err());
    }

    #[test]
    fn bounded_before_allocation_and_per_policy_limit() {
        let entries: Vec<_> = (1..=MAX_PER_POLICY as u32).map(|id| e(0, id)).collect();
        let bytes = encode(&entries, MAX_POLICIES).unwrap();
        assert_eq!(parse(&bytes, MAX_POLICIES, &[0]).unwrap(), entries);
        let mut too_many = entries;
        too_many.push(e(0, 100));
        assert!(encode(&too_many, 1).is_err());
        // Simulate a signed-but-invalid producer: parsing must enforce the
        // per-policy bound independently of the encoder.
        let mut allowed = too_many.clone();
        allowed.last_mut().unwrap().policy_index = 1;
        let mut oversized_policy = encode(&allowed, 2).unwrap();
        let pos = oversized_policy.len() - 8;
        oversized_policy[pos..pos + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse(&oversized_policy, 2, &[0]).is_err());
        let oversized = vec![e(0, 7); MAX_ENTRIES + 1];
        assert!(encode(&oversized, 1).is_err());
        let mut header = Vec::from(*MAGIC);
        header.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&header, 1, &[0]).is_err());
    }
}
