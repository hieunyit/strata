//! Cooperative CPU budget tracking (W07-R-01).
//!
//! Tracks cumulative engine time per transaction across FFI calls.
//! Provides cooperative checkpoints (`check()`) every ~50 µs / 8 KB.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetExceeded;

#[derive(Debug)]
pub struct TxBudget {
    /// Total budget configured for the transaction in nanoseconds. 0 means unlimited.
    budget_ns: u64,
    /// Cumulative engine time in previous FFI calls, nanoseconds.
    prior_elapsed_ns: u64,
    /// Start of current FFI call, if active.
    call_start: Option<Instant>,
    /// Precalculated instant when this call's remaining budget expires.
    call_deadline: Option<Instant>,
    /// Sticky flag: once exceeded, always returns BudgetExceeded.
    exceeded: bool,
    /// Whether an external timer (e.g. FFI CallTimer) manages this call's entry/exit.
    external_timer: bool,
    /// calls of `check_cheap` since the budget was made
    ticks: u32,
    /// time of the current call that does not count: one-time work of the
    /// bundle (a fallback regex compiled on first use), not of this request
    credit_ns: u64,
}

impl TxBudget {
    pub fn new(budget_us: u64) -> Self {
        Self {
            budget_ns: budget_us.saturating_mul(1000),
            prior_elapsed_ns: 0,
            call_start: None,
            call_deadline: None,
            exceeded: false,
            external_timer: false,
            ticks: 0,
            credit_ns: 0,
        }
    }

    #[inline]
    pub fn is_external_timer(&self) -> bool {
        self.external_timer
    }

    /// Called at the entry of each call with eager timestamping.
    pub fn enter(&mut self) -> Result<(), BudgetExceeded> {
        let now = Instant::now();
        self.enter_at(now)
    }

    /// Called at the entry of FFI calls when an external timer (e.g. TSC) is used.
    /// Does not query `Instant::now()` eagerly unless a loop inside invokes `check()`.
    pub fn enter_lazy(&mut self) -> Result<(), BudgetExceeded> {
        self.external_timer = true;
        if self.exceeded {
            return Err(BudgetExceeded);
        }
        self.call_start = None;
        self.call_deadline = None;
        if self.budget_ns == 0 {
            return Ok(());
        }
        if self.prior_elapsed_ns >= self.budget_ns {
            self.exceeded = true;
            return Err(BudgetExceeded);
        }
        Ok(())
    }

    /// Called at the entry of each FFI call with a pre-recorded timestamp.
    pub fn enter_at(&mut self, now: Instant) -> Result<(), BudgetExceeded> {
        if self.exceeded {
            return Err(BudgetExceeded);
        }
        self.call_start = Some(now);
        self.call_deadline = None;
        if self.budget_ns == 0 {
            return Ok(());
        }
        if self.prior_elapsed_ns >= self.budget_ns {
            self.exceeded = true;
            return Err(BudgetExceeded);
        }
        let remaining_ns = self.budget_ns.saturating_sub(self.prior_elapsed_ns);
        self.call_deadline = Some(now + Duration::from_nanos(remaining_ns));
        Ok(())
    }

    /// Cooperative checkpoint. Called every ~50 µs / 8 KB in loops.
    #[inline]
    pub fn check(&mut self) -> Result<(), BudgetExceeded> {
        if self.exceeded {
            return Err(BudgetExceeded);
        }
        if self.budget_ns == 0 {
            return Ok(());
        }
        let deadline = match self.call_deadline {
            Some(d) => d,
            None => {
                let start = *self.call_start.get_or_insert_with(Instant::now);
                let remaining_ns = self.budget_ns.saturating_sub(self.prior_elapsed_ns);
                let d = start + Duration::from_nanos(remaining_ns.saturating_add(self.credit_ns));
                self.call_deadline = Some(d);
                d
            }
        };
        if Instant::now() >= deadline {
            self.exceeded = true;
            return Err(BudgetExceeded);
        }
        Ok(())
    }

    /// Checkpoint for tight loops of cheap steps (one per rule): reads the
    /// clock once every 64 calls, so a check costs a counter, not a clock
    /// read (W09-R-01). Loops whose steps are expensive use `check`.
    #[inline]
    pub fn check_cheap(&mut self) -> Result<(), BudgetExceeded> {
        if self.exceeded {
            return Err(BudgetExceeded);
        }
        self.ticks = self.ticks.wrapping_add(1);
        if !self.ticks.is_multiple_of(64) {
            return Ok(());
        }
        self.check()
    }

    /// Excludes `spent` from the current call: work done once per bundle
    /// and worker (a regex compiled on first use) that happened to fall in
    /// this request. Without it the first requests after every bundle load
    /// exceed the budget and take the fail mode (W09 review).
    pub fn credit(&mut self, spent: Duration) {
        let ns = spent.as_nanos().min(u64::MAX as u128) as u64;
        self.credit_ns = self.credit_ns.saturating_add(ns);
        if let Some(d) = self.call_deadline {
            self.call_deadline = Some(d + spent);
        }
    }

    /// Called at exit of FFI call to record actual elapsed time.
    pub fn exit(&mut self) {
        if let Some(start) = self.call_start.take() {
            self.exit_with(start.elapsed());
        }
    }

    /// Records elapsed time for the call in nanoseconds.
    #[inline]
    pub fn exit_with_ns(&mut self, nanos: u64) {
        self.external_timer = false;
        self.call_start = None;
        let nanos = nanos.saturating_sub(std::mem::take(&mut self.credit_ns));
        self.prior_elapsed_ns = self.prior_elapsed_ns.saturating_add(nanos);
        self.call_deadline = None;
        if self.budget_ns > 0 && self.prior_elapsed_ns >= self.budget_ns {
            self.exceeded = true;
        }
    }

    /// Records elapsed time for the call.
    #[inline]
    pub fn exit_with(&mut self, elapsed: Duration) {
        self.exit_with_ns(elapsed.as_nanos().min(u64::MAX as u128) as u64);
    }

    /// Total engine time spent so far in nanoseconds.
    pub fn elapsed_ns(&self) -> u64 {
        let current = self.call_start.map_or(0, |s| s.elapsed().as_nanos() as u64);
        self.prior_elapsed_ns
            .saturating_add(current.saturating_sub(self.credit_ns))
    }

    pub fn elapsed_us(&self) -> u64 {
        self.elapsed_ns() / 1000
    }

    pub fn budget_ns(&self) -> u64 {
        self.budget_ns
    }

    pub fn is_exceeded(&self) -> bool {
        self.exceeded
    }

    pub fn mark_exceeded(&mut self) {
        self.exceeded = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn budget_zero_is_unlimited() {
        let mut b = TxBudget::new(0);
        assert!(b.enter().is_ok());
        assert!(b.check().is_ok());
        b.exit();
        assert!(!b.is_exceeded());
    }

    #[test]
    fn budget_exceeded_triggers_and_sticks() {
        let mut b = TxBudget::new(5_000); // 5 ms
        assert!(b.enter().is_ok());
        sleep(Duration::from_millis(10));
        assert_eq!(b.check(), Err(BudgetExceeded));
        assert!(b.is_exceeded());
        b.exit();

        // Next enter immediately returns error
        assert_eq!(b.enter(), Err(BudgetExceeded));
    }

    #[test]
    fn credited_time_does_not_count() {
        // a 5 s call with 4 s of one-time work fits a 2 s budget. The call
        // started 5 s ago (enter_at) instead of sleeping, and the margins are
        // seconds: a loaded machine cannot push check() past them (#44)
        let Some(start) = Instant::now().checked_sub(Duration::from_secs(5)) else {
            return; // a clock younger than 5 s
        };
        let mut b = TxBudget::new(2_000_000);
        assert!(b.enter_at(start).is_ok());
        b.credit(Duration::from_secs(4));
        assert!(b.check().is_ok(), "the deadline moves by the credit");
        b.exit_with(Duration::from_secs(5));
        assert!(!b.is_exceeded());
        assert!(b.enter().is_ok(), "the credit is not counted later either");
        b.exit_with(Duration::from_millis(500));
        assert!(!b.is_exceeded());
    }

    #[test]
    fn credit_is_per_call_and_only_what_was_spent() {
        // negative: the same 5 ms call with only 1 ms credited is over
        let mut b = TxBudget::new(2_000);
        assert!(b.enter().is_ok());
        sleep(Duration::from_millis(5));
        b.credit(Duration::from_millis(1));
        assert_eq!(b.check(), Err(BudgetExceeded));
        // and a credit does not carry over into the next call
        let mut b = TxBudget::new(2_000);
        assert!(b.enter().is_ok());
        b.credit(Duration::from_millis(4));
        b.exit_with(Duration::from_millis(4));
        assert!(b.enter().is_ok());
        b.exit_with(Duration::from_millis(3));
        assert!(b.is_exceeded());
    }

    #[test]
    fn credit_with_a_lazy_deadline() {
        // the FFI enters lazily (external timer): the deadline is made at
        // the first check, credit included
        let mut b = TxBudget::new(2_000);
        assert!(b.enter_lazy().is_ok());
        b.credit(Duration::from_millis(50));
        let _ = b.check();
        sleep(Duration::from_millis(1));
        assert!(b.check().is_ok());
        b.exit_with_ns(51_000_000);
        assert!(!b.is_exceeded());
    }

    #[test]
    fn budget_accumulates_across_calls() {
        let mut b = TxBudget::new(30_000); // 30 ms
        assert!(b.enter().is_ok());
        b.exit_with(Duration::from_millis(10));
        assert!(!b.is_exceeded());

        // Second call: 20 ms remaining, 25 ms exhausts it
        assert!(b.enter().is_ok());
        b.exit_with(Duration::from_millis(25));
        assert!(b.is_exceeded());
        assert_eq!(b.enter(), Err(BudgetExceeded));
    }
}
