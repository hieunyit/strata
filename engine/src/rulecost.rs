//! What each rule costs (W13-R-02): engine time by Rule ID, sampled.
//!
//! One transaction in `sample_every()` (100 by default: 1%) is timed: the
//! scans of the prefilter (shared by every rule, so not split among them:
//! RULE_SCAN), and each rule the evaluator visits. Each engine adds the
//! samples up per rule; about once a second they go out with the per-policy
//! counts (`crate::counters`, event.proto `PolicyCounters.rule_costs`), and
//! the event of a sampled transaction carries its most expensive rules
//! (`Event.rule_costs`). Without a sample nothing is timed: the cost of
//! the measure is a counter per transaction and a branch per rule.
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Slot and Rule ID 0: the scans of the prefilter.
pub const RULE_SCAN: u32 = 0;
/// Rules in the event of a sampled transaction, most expensive first.
pub const EVENT_RULES: usize = 8;

static SAMPLE_EVERY: AtomicU64 = AtomicU64::new(100);

/// One transaction in `n` is sampled (0: none). For tests and benchmarks;
/// connectors keep the default.
pub fn set_sample_every(n: u64) {
    SAMPLE_EVERY.store(n, Relaxed);
}

pub fn sample_every() -> u64 {
    SAMPLE_EVERY.load(Relaxed)
}

thread_local! {
    static TICK: Cell<u64> = const { Cell::new(0) };
}

/// Whether the next transaction of this thread is sampled: a counter per
/// thread, no lock and no shared cache line on the request path.
pub fn should_sample() -> bool {
    let every = sample_every();
    if every == 0 {
        return false;
    }
    TICK.with(|t| {
        let n = t.get().wrapping_add(1);
        t.set(n);
        due(n, every)
    })
}

/// The `n`-th transaction of a thread is sampled.
fn due(n: u64, every: u64) -> bool {
    every != 0 && n.is_multiple_of(every)
}

const SAMPLES: usize = 0;
const TOTAL_NS: usize = 1;
const MAX_NS: usize = 2;

/// One transaction's timed evaluations: (rule index, None for the
/// prefilter's scans; ns).
pub type Samples = std::cell::RefCell<Vec<(Option<u32>, u64)>>;

/// One rule's samples, as sent: (Rule ID, samples, total ns, max ns).
pub type Cost = (u32, u64, u64, u64);

/// The samples of one engine: one slot per rule index, then the scans.
#[derive(Debug)]
pub struct RuleCosts {
    slots: Vec<[AtomicU64; 3]>,
    requests: AtomicU64,
    request_ns: AtomicU64,
}

impl RuleCosts {
    pub fn new(n_rules: usize) -> RuleCosts {
        RuleCosts {
            slots: (0..=n_rules).map(|_| Default::default()).collect(),
            requests: AtomicU64::new(0),
            request_ns: AtomicU64::new(0),
        }
    }

    fn scan_slot(&self) -> usize {
        self.slots.len() - 1
    }

    /// Adds one sample of a rule (by index in the bundle) or, with None, of
    /// the prefilter's scans.
    pub fn add(&self, rule_index: Option<u32>, ns: u64) {
        let i = rule_index.map_or(self.scan_slot(), |i| (i as usize).min(self.scan_slot()));
        let s = &self.slots[i];
        s[SAMPLES].fetch_add(1, Relaxed);
        s[TOTAL_NS].fetch_add(ns, Relaxed);
        s[MAX_NS].fetch_max(ns, Relaxed);
    }

    /// Adds a sampled transaction and its engine time.
    pub fn add_request(&self, ns: u64) {
        self.requests.fetch_add(1, Relaxed);
        self.request_ns.fetch_add(ns, Relaxed);
    }

    /// Takes every sample since the last time: (rule index or None for the
    /// scans, samples, total ns, max ns), most expensive first, and the
    /// sampled transactions with their engine time.
    #[allow(clippy::type_complexity)]
    pub fn take(&self) -> (Vec<(Option<u32>, u64, u64, u64)>, u64, u64) {
        let scan = self.scan_slot();
        let mut out = vec![];
        for (i, s) in self.slots.iter().enumerate() {
            if s[SAMPLES].load(Relaxed) == 0 {
                continue;
            }
            let (n, total, max) = (
                s[SAMPLES].swap(0, Relaxed),
                s[TOTAL_NS].swap(0, Relaxed),
                s[MAX_NS].swap(0, Relaxed),
            );
            let index = (i != scan).then_some(i as u32);
            out.push((index, n, total, max));
        }
        out.sort_by_key(|c| std::cmp::Reverse(c.2));
        (
            out,
            self.requests.swap(0, Relaxed),
            self.request_ns.swap(0, Relaxed),
        )
    }

    /// Puts samples that could not be sent back for the next time.
    pub fn give_back(&self, rule_index: Option<u32>, n: u64, total: u64, max: u64) {
        let i = rule_index.map_or(self.scan_slot(), |i| (i as usize).min(self.scan_slot()));
        let s = &self.slots[i];
        s[SAMPLES].fetch_add(n, Relaxed);
        s[TOTAL_NS].fetch_add(total, Relaxed);
        s[MAX_NS].fetch_max(max, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_takes_and_gives_back() {
        let c = RuleCosts::new(3);
        c.add(Some(1), 500);
        c.add(Some(1), 300);
        c.add(None, 2_000);
        c.add(Some(9), 7); // out of range: the last slot
        c.add_request(4_000);
        let (costs, reqs, ns) = c.take();
        assert_eq!(costs, vec![(None, 2, 2_007, 2_000), (Some(1), 2, 800, 500)]);
        assert_eq!((reqs, ns), (1, 4_000));
        assert_eq!(c.take(), (vec![], 0, 0), "taken once");
        c.give_back(Some(1), 2, 800, 500);
        assert_eq!(c.take().0, vec![(Some(1), 2, 800, 500)]);
    }

    /// The rate itself is process-wide and other tests of this binary run
    /// at the same time: the counter logic is tested here, the rate in
    /// engine/compiler/tests/rule_cost.rs (its own process).
    #[test]
    fn one_in_n() {
        assert_eq!((1..=400).filter(|&n| due(n, 4)).count(), 100);
        assert_eq!((1..=400).filter(|&n| due(n, 100)).count(), 4);
        assert!(!(1..=400).any(|n| due(n, 0)));
        assert_eq!(sample_every(), 100, "1% by default");
    }
}
