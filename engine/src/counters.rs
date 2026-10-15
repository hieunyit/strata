//! Requests and inspection gaps per policy (RV-N-01): the denominator of the
//! share of requests a route did not get fully inspected, which events alone
//! cannot give (clean requests send none).
//!
//! Each engine keeps one slot per policy of its bundle, plus one for
//! requests whose `strata_policy` the bundle does not have. A transaction
//! counts once, when it is dropped. About once a second the connector's
//! `strata_tx_sample` call carries the counts since the last time
//! (COUNTERS_MAGIC + event.proto `PolicyCounters`) instead of a replay
//! sample, on the event socket the connector already writes: no connector
//! code knows about it. Each NGINX worker has its own copy (fork), so each
//! sends its own counts. Counts of an engine replaced by a new bundle that
//! were not sent yet are lost (at most about a second's worth).
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Counters of one policy: requests, and of them the ones not fully
/// inspected, by why.
pub const REQUESTS: usize = 0;
/// the CPU budget ran out (fail mode)
pub const PARTIAL: usize = 1;
/// the body, or part of it, was not inspected (over the limit, spooled)
pub const BODY_SKIPPED: usize = 2;
/// another engine error (fail mode)
pub const ERROR: usize = 3;
/// the worker's circuit breaker ran the request degraded (W11-N-01)
pub const DEGRADED: usize = 4;
pub const N: usize = 5;

/// Least time between two sends of one engine, in milliseconds.
pub const FLUSH_MS: u64 = 1000;

/// Why a request was not fully inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gap {
    None,
    Partial,
    BodySkipped,
    Error,
}

/// The counters of one engine.
#[derive(Debug)]
pub struct PolicyCounters {
    /// one per policy index, then one for unknown policies
    slots: Vec<[AtomicU64; N]>,
    last_flush_ms: AtomicU64,
}

impl PolicyCounters {
    pub fn new(n_policies: usize) -> Self {
        PolicyCounters {
            slots: (0..=n_policies).map(|_| Default::default()).collect(),
            last_flush_ms: AtomicU64::new(0),
        }
    }

    fn slot(&self, index: Option<u32>) -> &[AtomicU64; N] {
        let last = self.slots.len() - 1;
        &self.slots[index.map_or(last, |i| (i as usize).min(last))]
    }

    /// Counts one request of the policy at `index` (None: not in the
    /// bundle).
    pub fn count(&self, index: Option<u32>, gap: Gap, degraded: bool) {
        let s = self.slot(index);
        s[REQUESTS].fetch_add(1, Relaxed);
        match gap {
            Gap::None => {}
            Gap::Partial => {
                s[PARTIAL].fetch_add(1, Relaxed);
            }
            Gap::BodySkipped => {
                s[BODY_SKIPPED].fetch_add(1, Relaxed);
            }
            Gap::Error => {
                s[ERROR].fetch_add(1, Relaxed);
            }
        }
        if degraded {
            s[DEGRADED].fetch_add(1, Relaxed);
        }
    }

    /// When FLUSH_MS passed since the last time (or never), takes the counts
    /// of every slot with requests, by slot (the last one is the unknown
    /// policies), and starts counting again. One caller wins a given turn.
    pub fn take_due(&self, now_ms: u64) -> Option<Vec<(usize, [u64; N])>> {
        let last = self.last_flush_ms.load(Relaxed);
        // nothing counted: the turn stays for the first request
        if now_ms < last.saturating_add(FLUSH_MS)
            || self.slots.iter().all(|s| s[REQUESTS].load(Relaxed) == 0)
            || self
                .last_flush_ms
                .compare_exchange(last, now_ms, Relaxed, Relaxed)
                .is_err()
        {
            return None;
        }
        let mut out = vec![];
        for (i, s) in self.slots.iter().enumerate() {
            if s[REQUESTS].load(Relaxed) == 0 {
                continue;
            }
            let mut v = [0u64; N];
            for (k, c) in s.iter().enumerate() {
                v[k] = c.swap(0, Relaxed);
            }
            out.push((i, v));
        }
        Some(out)
    }

    /// Puts counts that could not be sent back for the next time.
    pub fn give_back(&self, slot: usize, v: [u64; N]) {
        if let Some(s) = self.slots.get(slot) {
            for (k, c) in s.iter().enumerate() {
                c.fetch_add(v[k], Relaxed);
            }
        }
    }

    /// Index of the slot of the unknown policies.
    pub fn unknown_slot(&self) -> usize {
        self.slots.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_by_policy_and_gap_then_takes_once_a_second() {
        let c = PolicyCounters::new(2);
        c.count(Some(0), Gap::None, false);
        c.count(Some(0), Gap::Partial, false);
        c.count(Some(1), Gap::BodySkipped, true);
        c.count(None, Gap::Error, false);
        c.count(Some(9), Gap::None, false); // out of range: unknown
        let t = c.take_due(10_000).unwrap();
        assert_eq!(
            t,
            vec![
                (0, [2, 1, 0, 0, 0]),
                (1, [1, 0, 1, 0, 1]),
                (2, [2, 0, 0, 1, 0]),
            ]
        );
        // not again within the second, and reset
        c.count(Some(0), Gap::None, false);
        assert!(c.take_due(10_999).is_none());
        assert_eq!(c.take_due(11_000).unwrap(), vec![(0, [1, 0, 0, 0, 0])]);
        // given back: sent next time
        c.give_back(1, [3, 1, 0, 0, 0]);
        assert_eq!(c.take_due(12_000).unwrap(), vec![(1, [3, 1, 0, 0, 0])]);
        // nothing counted: no datagram, and the turn is not used up
        assert!(c.take_due(13_000).is_none());
        c.count(Some(0), Gap::None, false);
        assert_eq!(c.take_due(13_001).unwrap(), vec![(0, [1, 0, 0, 0, 0])]);
        assert_eq!(c.unknown_slot(), 2);
    }
}
