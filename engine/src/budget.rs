//! Cooperative CPU budget tracking (W07-R-01).
//!
//! Tracks cumulative engine time per transaction across FFI calls.
//! Provides cooperative checkpoints (`check()`) every ~50 µs / 8 KB.
//!
//! The budget counts the time a request uses the CPU (22/10/2026). The wall
//! clock also counts the time other processes ran on the worker's CPU: on
//! a loaded host the same request passed or failed open depending on the
//! load, and an attacker could add load to make large requests fail open.
//! Reading the thread's CPU clock is a system call (about 2 µs on a
//! virtual machine), so short calls keep the wall clock; a call that runs
//! past `CPU_MARK_AFTER` takes a mark (wall instant and CPU time) at its
//! next checkpoint, and from there on its time is the CPU time since the
//! mark: when the wall-clock deadline comes, the deadline moves by the time
//! the thread did not run, and at exit the call counts its CPU time.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetExceeded;

/// Wall time of a call after which its CPU time is measured (see the
/// module docs); before it, the call counts wall time.
pub const CPU_MARK_AFTER: Duration = Duration::from_micros(500);

/// Wall time a call counts at most where it has no CPU reading: a call that
/// took no mark, and the part of a marked call before its mark. Loops of
/// the engine reach a checkpoint every ~50 µs of work, so such a part did
/// less than CPU_MARK_AFTER of work; the rest of its wall time is the time
/// other processes ran (a worker preempted in a short call counted 20-40 ms
/// and its request was refused on a loaded host). Counting less here only
/// lets a request do more work, it never leaves one uninspected.
pub const UNMEASURED_MAX: Duration = Duration::from_millis(1);
const UNMEASURED_MAX_NS: u64 = 1_000_000;

/// Once the budget has grown this much over its base (a request of some
/// KB, see `extend`), every call of the transaction counts CPU time from
/// its start: a large body comes in many short calls, each of which would
/// otherwise count wall time, the time other processes ran included. Two
/// clock reads per call (about 4 µs) against tens of milliseconds of work.
pub const EXACT_AFTER_NS: u64 = 20_000_000;

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
    /// `grace` was given (once per transaction)
    graced: bool,
    /// the current call's mark: wall instant and thread CPU time
    cpu_mark: Option<(Instant, u64)>,
    /// the budget set at the start, before `extend`
    base_ns: u64,
    /// every call counts CPU time from its start (`EXACT_AFTER_NS`)
    exact: bool,
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
            graced: false,
            cpu_mark: None,
            base_ns: budget_us.saturating_mul(1000),
            exact: false,
        }
    }

    /// An exact call starts with its mark: CPU time from the first instant.
    fn mark_start(&mut self) {
        if self.exact {
            let now = Instant::now();
            if let Some(cpu) = strata_clock::thread_cpu_ns() {
                self.call_start = Some(now);
                self.cpu_mark = Some((now, cpu));
            }
        }
    }

    /// Once per transaction, an exceeded budget gets `ns` more (#28): time
    /// to confirm what the prefilter found on the values it scanned before
    /// the budget ran out. Returns whether it was given. The transaction
    /// still counts as out of budget (the evaluator says so).
    pub fn grace(&mut self, ns: u64) -> bool {
        if self.graced || !self.exceeded || self.budget_ns == 0 {
            return false;
        }
        self.graced = true;
        self.exceeded = false;
        let now = Instant::now();
        self.call_deadline = Some(now + Duration::from_nanos(ns));
        self.call_start.get_or_insert(now);
        true
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
        self.cpu_mark = None;
        if self.budget_ns == 0 {
            return Ok(());
        }
        if self.prior_elapsed_ns >= self.budget_ns {
            self.exceeded = true;
            return Err(BudgetExceeded);
        }
        self.mark_start();
        Ok(())
    }

    /// Called at the entry of each FFI call with a pre-recorded timestamp.
    pub fn enter_at(&mut self, now: Instant) -> Result<(), BudgetExceeded> {
        if self.exceeded {
            return Err(BudgetExceeded);
        }
        self.call_start = Some(now);
        self.call_deadline = None;
        self.cpu_mark = None;
        if self.budget_ns == 0 {
            return Ok(());
        }
        if self.prior_elapsed_ns >= self.budget_ns {
            self.exceeded = true;
            return Err(BudgetExceeded);
        }
        let remaining_ns = self.budget_ns.saturating_sub(self.prior_elapsed_ns);
        self.call_deadline = Some(now + Duration::from_nanos(remaining_ns));
        if self.exact
            && let Some(cpu) = strata_clock::thread_cpu_ns()
        {
            self.cpu_mark = Some((now, cpu));
        }
        Ok(())
    }

    /// Adds `ns` to the budget, up to `cap_ns` in all; a budget at or over
    /// the cap, or unlimited (0), stays as it is (#28: the budget grows
    /// with the body inspected). The deadline of a call under way moves
    /// with it. Not once exceeded: an exceeded budget stays so.
    pub fn extend(&mut self, ns: u64, cap_ns: u64) {
        if self.exceeded || self.budget_ns == 0 || self.budget_ns >= cap_ns {
            return;
        }
        let grown = self.budget_ns.saturating_add(ns).min(cap_ns);
        let added = grown - self.budget_ns;
        self.budget_ns = grown;
        self.exact |= grown.saturating_sub(self.base_ns) >= EXACT_AFTER_NS;
        if let Some(d) = self.call_deadline.as_mut() {
            *d += Duration::from_nanos(added);
        }
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
        let now = Instant::now();
        let start = self.call_start.unwrap_or(now);
        if self.cpu_mark.is_none()
            && now >= start + CPU_MARK_AFTER
            && let Some(cpu) = strata_clock::thread_cpu_ns()
        {
            self.cpu_mark = Some((now, cpu));
        }
        if now >= deadline {
            // the wall clock says the budget ran out: what did the call
            // use of the CPU? (wall time before the mark, CPU time since)
            if let Some((mark, cpu0)) = self.cpu_mark
                && let Some(cpu) = strata_clock::thread_cpu_ns()
            {
                let call = (mark - start).min(UNMEASURED_MAX).as_nanos() as u64;
                let used = self
                    .prior_elapsed_ns
                    .saturating_add(call)
                    .saturating_add(cpu.saturating_sub(cpu0))
                    .saturating_sub(self.credit_ns);
                if used < self.budget_ns {
                    self.call_deadline = Some(now + Duration::from_nanos(self.budget_ns - used));
                    return Ok(());
                }
            }
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
        // a marked call counts its CPU time from the mark on
        let nanos = match self.cpu_mark.take() {
            Some((mark, cpu0)) => match strata_clock::thread_cpu_ns() {
                Some(cpu) => {
                    let wall_after = mark.elapsed().as_nanos().min(u64::MAX as u128) as u64;
                    nanos
                        .saturating_sub(wall_after)
                        .min(UNMEASURED_MAX_NS)
                        .saturating_add(cpu.saturating_sub(cpu0))
                }
                None => nanos,
            },
            // no mark: under CPU_MARK_AFTER of work (see UNMEASURED_MAX),
            // where the CPU clock can be read
            None if strata_clock::available() => nanos.min(UNMEASURED_MAX_NS),
            None => nanos,
        };
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

    /// Burns CPU for `d` with checkpoints as the engine has them (the
    /// budget counts CPU time, not sleep); stops at the first exceeded one.
    fn work(b: &mut TxBudget, d: Duration) -> Result<(), BudgetExceeded> {
        // CPU time, not wall time: tests run in parallel and share CPUs
        let t0 = strata_clock::thread_cpu_ns().expect("clock");
        let end = t0 + d.as_nanos() as u64;
        let mut x = 0u64;
        while strata_clock::thread_cpu_ns().expect("clock") < end {
            for _ in 0..10_000 {
                x = std::hint::black_box(x.wrapping_add(1));
            }
            b.check()?;
        }
        Ok(())
    }

    #[test]
    fn budget_exceeded_triggers_and_sticks() {
        let mut b = TxBudget::new(5_000); // 5 ms
        assert!(b.enter().is_ok());
        assert_eq!(
            work(&mut b, Duration::from_millis(200)),
            Err(BudgetExceeded)
        );
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
        b.credit(Duration::from_millis(1));
        assert_eq!(
            work(&mut b, Duration::from_millis(200)),
            Err(BudgetExceeded)
        );
        // and a credit does not carry over into the next call
        let mut b = TxBudget::new(2_000);
        assert!(b.enter().is_ok());
        b.credit(Duration::from_millis(4));
        work(&mut b, Duration::from_millis(3)).unwrap();
        b.exit();
        assert!(!b.is_exceeded(), "3 ms of work, 4 ms credited");
        assert!(b.enter().is_ok());
        assert_eq!(
            work(&mut b, Duration::from_millis(200)),
            Err(BudgetExceeded)
        );
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
        work(&mut b, Duration::from_millis(10)).unwrap();
        b.exit();
        assert!(!b.is_exceeded());
        assert!(
            b.prior_elapsed_ns >= 5_000_000,
            "the first call counts its work"
        );

        // Second call: the rest runs out
        assert!(b.enter().is_ok());
        assert_eq!(
            work(&mut b, Duration::from_millis(500)),
            Err(BudgetExceeded)
        );
        b.exit();
        assert_eq!(b.enter(), Err(BudgetExceeded));
    }
}

#[cfg(test)]
mod cpu_time_tests {
    use super::*;

    /// Burns CPU for `d` of wall time, with checkpoints as the engine does.
    fn work(b: &mut TxBudget, d: Duration) -> Result<(), BudgetExceeded> {
        // CPU time, not wall time: tests run in parallel and share CPUs
        let t0 = strata_clock::thread_cpu_ns().expect("clock");
        let end = t0 + d.as_nanos() as u64;
        let mut x = 0u64;
        while strata_clock::thread_cpu_ns().expect("clock") < end {
            for _ in 0..10_000 {
                x = std::hint::black_box(x.wrapping_add(1));
            }
            b.check()?;
        }
        Ok(())
    }

    #[test]
    fn time_the_thread_did_not_run_does_not_count() {
        // 2 ms of work (the call is marked), then 30 ms off the CPU (a
        // sleep stands for other processes on the worker's CPU): over a
        // 10 ms budget by the wall clock, not by the CPU
        let mut b = TxBudget::new(10_000);
        b.enter().unwrap();
        work(&mut b, Duration::from_millis(2)).unwrap();
        assert!(b.cpu_mark.is_some(), "a call past CPU_MARK_AFTER is marked");
        std::thread::sleep(Duration::from_millis(30));
        assert!(b.check().is_ok(), "30 ms off the CPU do not count");
        b.exit();
        assert!(!b.is_exceeded());
        assert!(
            b.prior_elapsed_ns < 10_000_000,
            "the call counts its CPU time: {} ns",
            b.prior_elapsed_ns
        );
    }

    #[test]
    fn work_still_runs_the_budget_out() {
        let mut b = TxBudget::new(10_000);
        b.enter().unwrap();
        assert_eq!(
            work(&mut b, Duration::from_millis(200)),
            Err(BudgetExceeded)
        );
        assert!(b.is_exceeded());
        // across calls too, lazily entered as the FFI does
        let mut b = TxBudget::new(10_000);
        b.enter_lazy().unwrap();
        work(&mut b, Duration::from_millis(6)).unwrap();
        b.exit_with_ns(6_000_000);
        b.enter_lazy().unwrap();
        assert_eq!(
            work(&mut b, Duration::from_millis(200)),
            Err(BudgetExceeded)
        );
    }

    #[test]
    fn a_large_request_counts_cpu_time_in_short_calls_too() {
        // a large body comes in many short calls (one per buffer), each
        // under CPU_MARK_AFTER: 60 of them, 5 ms off the CPU each, are
        // 300 ms of wall time and almost no CPU time
        let mut b = TxBudget::new(10_000);
        b.extend(100_000_000, 2_500_000_000);
        assert!(b.exact, "grown by 100 ms: exact");
        for _ in 0..60 {
            b.enter_lazy().unwrap();
            let t = Instant::now();
            std::thread::sleep(Duration::from_millis(5));
            b.exit_with_ns(t.elapsed().as_nanos() as u64);
        }
        assert!(!b.is_exceeded());
        assert!(
            b.prior_elapsed_ns < 20_000_000,
            "{} ns counted",
            b.prior_elapsed_ns
        );
        // a small request keeps the wall clock: no clock read per call
        let mut b = TxBudget::new(10_000);
        b.extend(1_000_000, 2_500_000_000);
        assert!(!b.exact);
        b.enter_lazy().unwrap();
        assert!(b.cpu_mark.is_none());
        b.exit_with_ns(1_000);
    }

    #[test]
    fn short_calls_never_read_the_cpu_clock() {
        let mut b = TxBudget::new(10_000);
        b.enter().unwrap();
        for _ in 0..10 {
            b.check().unwrap();
        }
        assert!(b.cpu_mark.is_none());
        b.exit();
    }
}

#[cfg(test)]
mod extend_tests {
    use super::*;

    #[test]
    fn grows_up_to_the_cap_and_moves_the_deadline() {
        let mut b = TxBudget::new(10_000); // 10 ms
        let now = Instant::now();
        b.enter_at(now).unwrap();
        let d0 = b.call_deadline.unwrap();
        b.extend(32_000_000, 100_000_000); // + 32 ms
        assert_eq!(b.budget_ns(), 42_000_000);
        assert_eq!(b.call_deadline.unwrap() - d0, Duration::from_millis(32));
        b.extend(500_000_000, 100_000_000);
        assert_eq!(b.budget_ns(), 100_000_000, "capped");
        // a budget over the cap, unlimited, or exceeded does not change
        let mut big = TxBudget::new(1_000_000);
        big.extend(5_000_000, 100_000_000);
        assert_eq!(big.budget_ns(), 1_000_000_000);
        let mut none = TxBudget::new(0);
        none.extend(5_000_000, 100_000_000);
        assert_eq!(none.budget_ns(), 0);
        let mut gone = TxBudget::new(1);
        gone.exceeded = true;
        gone.extend(5_000_000, 100_000_000);
        assert_eq!(gone.budget_ns(), 1_000);
    }

    #[test]
    fn grace_once_after_the_budget_ran_out() {
        let mut b = TxBudget::new(1);
        assert!(!b.grace(1_000_000), "not exceeded yet");
        b.enter().unwrap_or(());
        std::thread::sleep(Duration::from_millis(1));
        assert!(b.check().is_err());
        assert!(b.grace(50_000_000));
        assert!(b.check().is_ok(), "50 ms more");
        b.exceeded = true;
        assert!(!b.grace(50_000_000), "once");
        assert!(b.check().is_err());
    }
}
