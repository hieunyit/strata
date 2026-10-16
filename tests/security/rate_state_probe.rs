//! Measures the pinned, unmodified rate prototype; does not enable enforcement.
#[path = "../../build/m3-rate-measurement/prototype.rs"]
mod prototype;
use prototype::{RateLimitVerdict, RateLimiter, compute_key_hash, resolve_client_ip};
use std::collections::{HashMap, HashSet};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Barrier};
use std::time::Instant;

fn parts(v: RateLimitVerdict) -> (bool, u64) {
    match v {
        RateLimitVerdict::Allow { count, limit } => {
            black_box(limit);
            (true, count)
        }
        RateLimitVerdict::Exceeded {
            count,
            limit,
            retry_after_secs,
        } => {
            black_box((limit, retry_after_secs));
            (false, count)
        }
    }
}
fn pressure() {
    let target = b"192.0.2.10";
    let hash = compute_key_hash(target, None, b"/login");
    let collider = (0..65536)
        .map(|n| format!("198.18.{}.{}", n / 256, n % 256))
        .find(|ip| compute_key_hash(ip.as_bytes(), None, b"/login") & 255 == hash & 255)
        .unwrap();
    let r = RateLimiter::new(256);
    let mut allowed = 0;
    let mut last = 0;
    for _ in 0..20 {
        let (allow, count) = parts(r.check(target, None, b"/login", 100, 60, 3));
        allowed += usize::from(allow);
        last = count;
        black_box(r.check(collider.as_bytes(), None, b"/login", 100, 60, 3));
    }
    assert_eq!(last, 1);
    assert_eq!(allowed, 20);
    println!(
        "{{\"case\":\"live_slot_collision\",\"capacity\":256,\"target_requests\":20,\"expected_allowed\":3,\"observed_allowed\":{allowed},\"excess_allowed\":{},\"last_count\":{last}}}",
        allowed - 3
    );

    let r = RateLimiter::new(256);
    let mut reference = HashMap::new();
    let mut buckets = HashSet::new();
    let (mut expected_allow, mut observed_allow, mut excess_allow) = (0, 0, 0);
    for _ in 0..10 {
        for n in 0..512 {
            let ip = format!("198.18.{}.{}", n / 256, n % 256);
            buckets.insert(compute_key_hash(ip.as_bytes(), None, b"/login") & 255);
            let count = reference.entry(n).or_insert(0);
            *count += 1;
            let expected = *count <= 3;
            let observed = parts(r.check(ip.as_bytes(), None, b"/login", 100, 60, 3)).0;
            expected_allow += usize::from(expected);
            observed_allow += usize::from(observed);
            excess_allow += usize::from(observed && !expected);
        }
    }
    assert!(excess_allow > 0);
    println!(
        "{{\"case\":\"table_pressure\",\"capacity\":256,\"unique_keys\":512,\"occupied_home_buckets\":{},\"requests\":5120,\"expected_allowed\":{expected_allow},\"observed_allowed\":{observed_allow},\"excess_allowed\":{excess_allow}}}",
        buckets.len()
    );

    for rollover in [false, true] {
        concurrent(rollover);
    }
    let case_equal =
        compute_key_hash(target, None, b"/Login") == compute_key_hash(target, None, b"/login");
    assert!(case_equal);
    let ipv6_equal = compute_key_hash(b"2001:db8::1", None, b"/login")
        == compute_key_hash(b"2001:0db8:0:0:0:0:0:1", None, b"/login");
    println!(
        "{{\"case\":\"key_normalization\",\"case_sensitive_paths_collapsed\":{case_equal},\"equivalent_ipv6_same_hash\":{ipv6_equal}}}"
    );
    let spoof = resolve_client_ip(b"192.0.2.1", Some(b"198.51.100.66, 203.0.113.10"), true);
    let bad = resolve_client_ip(b"192.0.2.1", Some(b"garbage, 203.0.113.10"), true);
    assert_eq!(spoof, b"198.51.100.66");
    assert_eq!(bad, b"garbage");
    println!(
        "{{\"case\":\"forwarded_chain\",\"selected_leftmost\":true,\"accepted_malformed_ip\":true,\"scope\":\"standalone_helper_only\"}}"
    );
    black_box(prototype::DEFAULT_BUCKETS);
}
fn concurrent(rollover: bool) {
    const TRIALS: usize = 2000;
    const THREADS: usize = 8;
    let tables = Arc::new(
        (0..TRIALS)
            .map(|_| {
                let r = RateLimiter::new(256);
                if rollover {
                    black_box(r.check(b"192.0.2.10", None, b"/login", 60, 60, 1));
                }
                r
            })
            .collect::<Vec<_>>(),
    );
    let allows = Arc::new((0..TRIALS).map(|_| AtomicUsize::new(0)).collect::<Vec<_>>());
    let barrier = Arc::new(Barrier::new(THREADS));
    let threads = (0..THREADS)
        .map(|_| {
            let (tables, allows, barrier) = (tables.clone(), allows.clone(), barrier.clone());
            std::thread::spawn(move || {
                for trial in 0..TRIALS {
                    barrier.wait();
                    if parts(tables[trial].check(b"192.0.2.10", None, b"/login", 120, 60, 1)).0 {
                        allows[trial].fetch_add(1, Relaxed);
                    }
                    barrier.wait();
                }
            })
        })
        .collect::<Vec<_>>();
    for t in threads {
        t.join().unwrap();
    }
    let mut extra = 0;
    let mut wrong_allow = 0;
    let mut lost = 0;
    for trial in 0..TRIALS {
        let n = allows[trial].load(Relaxed);
        extra += n.saturating_sub(1);
        wrong_allow += usize::from(n > 1);
        // One final observation adds one request; correct count is THREADS+1.
        let count = parts(tables[trial].check(b"192.0.2.10", None, b"/login", 120, 60, 1)).1;
        lost += usize::from(count < (THREADS + 1) as u64);
    }
    println!(
        "{{\"case\":\"concurrent_{}\",\"threads\":{THREADS},\"trials\":{TRIALS},\"requests_per_trial\":{THREADS},\"limit\":1,\"extra_allows\":{extra},\"wrong_allow_trials\":{wrong_allow},\"lost_count_trials\":{lost}}}",
        if rollover { "rollover" } else { "first_use" }
    );
}
fn bench() {
    const N: usize = 1_000_000;
    for sample in 0..5 {
        let r = RateLimiter::new(16384);
        let start = Instant::now();
        for _ in 0..N {
            black_box(r.check(
                black_box(b"192.0.2.10"),
                None,
                black_box(b"/login"),
                100,
                60,
                u64::MAX,
            ));
        }
        let ns = start.elapsed().as_nanos();
        println!(
            "{{\"case\":\"prototype_component_bench\",\"sample\":{sample},\"requests\":{N},\"total_ns\":{ns},\"ns_per_check\":{:.3},\"scope\":\"single_thread_component_not_proxy_overhead\"}}",
            ns as f64 / N as f64
        );
    }
}
fn main() {
    if std::env::args().any(|s| s == "--bench") {
        bench()
    } else {
        pressure()
    }
}
