//! Benchmark for budget overshoot on pathological 1 MB payloads (W07-R-01).
//! Run with: cargo test --release -p libstrata --test budget_overshoot -- --ignored --nocapture

use std::time::Instant;

use libstrata::budget::TxBudget;
use libstrata::detectors::injection::sqli;
use libstrata::detectors::injection::xss;
use libstrata::detectors::protocol;
use libstrata::eval::{dfa_is_match_with_budget, fallback_dfa, fallback_regex};
use libstrata::json;
use libstrata::multipart;

struct PayloadStats {
    name: &'static str,
    target_us: u64,
    p50_overshoot_us: u64,
    p99_overshoot_us: u64,
    max_overshoot_us: u64,
}

#[test]
#[ignore]
fn budget_overshoot_pathological_payloads() {
    let one_mb = 1024 * 1024;
    let target_us = 1000; // 1 ms target budget
    let iterations = 100;
    let mut stats = Vec::new();

    let benchmark_payload = |name: &'static str, f: &dyn Fn(&mut TxBudget)| -> PayloadStats {
        let mut overshoots = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let mut budget = TxBudget::new(target_us);
            let start = Instant::now();
            let _ = budget.enter();
            f(&mut budget);
            budget.exit();
            let elapsed_us = start.elapsed().as_micros() as u64;
            let overshoot = elapsed_us.saturating_sub(target_us);
            overshoots.push(overshoot);
        }
        overshoots.sort_unstable();
        let p50 = overshoots[iterations * 50 / 100];
        let p99 = overshoots[iterations * 99 / 100];
        let max = *overshoots.last().unwrap();
        PayloadStats {
            name,
            target_us,
            p50_overshoot_us: p50,
            p99_overshoot_us: p99,
            max_overshoot_us: max,
        }
    };

    // 1. Long unclosed string in JSON (1 MB)
    {
        let mut payload = vec![b'"'];
        payload.extend(vec![b'a'; one_mb]);
        stats.push(benchmark_payload("1. JSON unclosed string (1 MB)", &|_| {
            let _ = json::args(&payload, 10);
        }));
    }

    // 2. Pathological unclosed XML CDATA (1 MB)
    {
        let mut payload = b"<![CDATA[".to_vec();
        payload.extend(vec![b'x'; one_mb]);
        stats.push(benchmark_payload("2. XML unclosed CDATA (1 MB)", &|_| {
            let _ = libstrata::xml::parse(&payload);
        }));
    }

    // 3. Pathological Multipart without boundary (1 MB)
    {
        let payload = vec![b'm'; one_mb];
        stats.push(benchmark_payload(
            "3. Multipart without boundary (1 MB)",
            &|_| {
                let _ = multipart::parts(&payload, b"nonexistent-boundary");
            },
        ));
    }

    // 4. Pathological SQLi unclosed comment (1 MB)
    {
        let mut payload = b"/*".to_vec();
        payload.extend(vec![b'c'; one_mb]);
        stats.push(benchmark_payload(
            "4. SQLi unclosed comment (1 MB)",
            &|_| {
                let _ = sqli::detect(&payload);
            },
        ));
    }

    // 5. Pathological XSS unclosed tag/attribute (1 MB)
    {
        let mut payload = b"<div attr=\"".to_vec();
        payload.extend(vec![b'y'; one_mb]);
        stats.push(benchmark_payload(
            "5. XSS unclosed attribute (1 MB)",
            &|_| {
                let _ = xss::detect(&payload);
            },
        ));
    }

    // 6. Regex lazy DFA stepping on 1 MB
    {
        let pattern = br"(?:^|[;&|])\s*(?:bash|sh|zsh)\b";
        let dfa = fallback_dfa(pattern).unwrap();
        let re = fallback_regex(pattern).unwrap();
        let payload = vec![b'x'; one_mb];
        stats.push(benchmark_payload(
            "6. Regex fallback lazy DFA (1 MB)",
            &|bgt| {
                let mut b_opt = Some(bgt);
                let _ = dfa_is_match_with_budget(1, &dfa, &re, &payload, &mut b_opt);
            },
        ));
    }

    // 7. Repetitive URI without query delimiters (1 MB)
    {
        let payload = vec![b'q'; one_mb];
        stats.push(benchmark_payload(
            "7. URI without query delimiter (1 MB)",
            &|_| {
                let mut count = 0;
                protocol::check_uri(&payload, &mut |_| count += 1);
            },
        ));
    }

    println!(
        "\n| Payload (1 MB) | Target Budget | p50 Overshoot | p99 Overshoot | Max Overshoot | Status |"
    );
    println!("| :--- | :---: | :---: | :---: | :---: | :---: |");
    for s in &stats {
        let status = if s.max_overshoot_us < 100 {
            "PASS (<100 µs)"
        } else {
            "FAIL (>=100 µs)"
        };
        println!(
            "| {} | {} µs | {} µs | {} µs | {} µs | {} |",
            s.name, s.target_us, s.p50_overshoot_us, s.p99_overshoot_us, s.max_overshoot_us, status
        );
        assert!(
            s.max_overshoot_us < 100,
            "Payload '{}' exceeded max overshoot: {} µs >= 100 µs",
            s.name,
            s.max_overshoot_us
        );
    }
    println!();
}
