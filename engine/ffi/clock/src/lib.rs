//! strata-clock — the CPU time the calling thread has used (22/10/2026).
//!
//! Lives under `engine/ffi/` because it needs `unsafe` (one libc call).
//! The engine's budget counts the time a request uses the CPU, not the time
//! the worker waited for it: on a loaded host the wall clock also counts
//! the time other processes ran, and the same request would pass or fail
//! open depending on the load (`engine/src/budget.rs`).
//!
//! Reading this clock is a system call (about 2 µs on a virtual machine,
//! against 25 ns for the monotonic clock), so the budget reads it only in
//! long calls.

/// CPU time used by the calling thread, nanoseconds; None where the clock is
/// not available (then the budget keeps the wall clock).
#[cfg(target_os = "linux")]
pub fn thread_cpu_ns() -> Option<u64> {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clk: i32, tp: *mut Timespec) -> i32;
    }
    /// <time.h>, Linux: CLOCK_THREAD_CPUTIME_ID
    const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
    let mut t = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: t is a valid, writable timespec for the duration of the call.
    let rc = unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut t) };
    if rc != 0 || t.tv_sec < 0 || t.tv_nsec < 0 {
        return None;
    }
    (t.tv_sec as u64)
        .checked_mul(1_000_000_000)?
        .checked_add(t.tv_nsec as u64)
}

#[cfg(not(target_os = "linux"))]
pub fn thread_cpu_ns() -> Option<u64> {
    None
}

/// Whether `thread_cpu_ns` works here, checked once per process.
pub fn available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| thread_cpu_ns().is_some())
}

#[cfg(test)]
mod tests {
    use super::thread_cpu_ns;
    use std::time::{Duration, Instant};

    #[test]
    fn counts_work_not_sleep() {
        let a = thread_cpu_ns().expect("clock");
        std::thread::sleep(Duration::from_millis(30));
        let b = thread_cpu_ns().expect("clock");
        assert!(b - a < 10_000_000, "sleeping used {} ns of CPU", b - a);
        let t = Instant::now();
        let mut x = 0u64;
        while t.elapsed() < Duration::from_millis(30) {
            x = std::hint::black_box(x.wrapping_add(1));
        }
        let c = thread_cpu_ns().expect("clock");
        assert!(c - b >= 10_000_000, "30 ms of work counted {} ns", c - b);
        assert!(c >= b && b >= a, "monotonic");
    }
}
