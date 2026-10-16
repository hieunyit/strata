//! strata-bench: time the engine alone (no NGINX) on the benchmark requests
//! of W09-Q-01, with a real bundle, as the NGINX connector calls it.
//!
//! strata-bench --bundle <file> --pubkey <file> [--policy example-api] [--iterations 2000]
//!              [--budget-us N] [--only small|nul|attack|json|64k|json64k|1m] [--event] [--diagnose]
//!              [--profile-cost] [--cold N [--warm]] [--rule-cost-every N] [--rule-cost-ab]
//!
//! `--rule-cost-ab` (W13-R-02) runs the iterations in turn with rule-cost
//! sampling off, at 1% and at 100%, in one process (the machine drifts
//! more between runs than the cost measured), and prints the mean of each.
//!
//! For each request kind (small GET, 64 KB and 1 MB urlencoded POST, JSON
//! POST, an attack GET) prints one JSON line: mean, p50, p99 and max in µs,
//! the action and the matched rules of the last run (so a speed-up that
//! changes a verdict shows).
//!
//! `--cold N` times instead the first request of a freshly mapped engine, N
//! times per request kind: what a worker pays right after a bundle load
//! (fallback regexes of gated rules are compiled on first use). `--warm`
//! allocates the thread's Hyperscan scratch first (#49).

use std::sync::Arc;
use std::time::Instant;

use libstrata::engine::Engine;
use libstrata::tx::Tx;

struct Req {
    name: &'static str,
    method: &'static [u8],
    uri: String,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

fn form(n: usize) -> Vec<u8> {
    let mut b = Vec::with_capacity(n + 64);
    let mut i = 0;
    while b.len() < n {
        b.extend_from_slice(format!("field{i}=some+ordinary+text+value+{i}&").as_bytes());
        i += 1;
    }
    b.truncate(n);
    b
}

/// A JSON document of about `n` bytes: records of a few fields with text
/// of some hundred bytes each, as an API that takes a list of items sends.
fn json_doc(n: usize) -> Vec<u8> {
    let mut b = b"{\"items\":[".to_vec();
    let mut i = 0;
    while b.len() < n {
        if i > 0 {
            b.push(b',');
        }
        b.extend_from_slice(
            format!(
                "{{\"id\":{i},\"name\":\"Item number {i}\",\"description\":\"{}\",\"price\":{}.99}}",
                "An ordinary product description with some words in it. ".repeat(6),
                i % 500
            )
            .as_bytes(),
        );
        i += 1;
    }
    b.extend_from_slice(b"]}");
    b
}

fn requests() -> Vec<Req> {
    let base = |name, method, uri: &str, body: Vec<u8>, ct: Option<&str>| {
        let mut headers = vec![
            ("Host", "api.example.test".to_string()),
            (
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
                    .to_string(),
            ),
            ("Accept", "text/html,application/xhtml+xml".to_string()),
            ("Accept-Language", "en-US,en;q=0.5".to_string()),
            ("Cookie", "session=4f9c2b7e1a; theme=dark".to_string()),
        ];
        if let Some(ct) = ct {
            headers.push(("Content-Type", ct.to_string()));
            headers.push(("Content-Length", body.len().to_string()));
        }
        Req {
            name,
            method,
            uri: uri.to_string(),
            headers,
            body,
        }
    };
    let mut cases = vec![
        base(
            "small",
            b"GET",
            "/t?q=hello&page=2&sort=price",
            vec![],
            None,
        ),
        // the events scenario of bench.sh: crosses the threshold (100013)
        base(
            "nul",
            b"GET",
            "/t?q=hello&page=2&sort=price&x=1%00",
            vec![],
            None,
        ),
        base(
            "attack",
            b"GET",
            "/t?id=1%27%20OR%20%271%27%3D%271&q=%3Cscript%3E",
            vec![],
            None,
        ),
        base(
            "json",
            b"POST",
            "/t/v1/items",
            br#"{"name":"alice","tags":["a","b"],"n":12}"#.to_vec(),
            Some("application/json"),
        ),
        base(
            "64k",
            b"POST",
            "/t",
            form(65536),
            Some("application/x-www-form-urlencoded"),
        ),
        // #28: a 64 KB body as an API sends it: records of four fields
        base(
            "json64k",
            b"POST",
            "/t/v1/items",
            json_doc(65536),
            Some("application/json"),
        ),
        base(
            "1m",
            b"POST",
            "/t",
            form(1_000_000),
            Some("application/x-www-form-urlencoded"),
        ),
    ];
    // Same payload at opposite ends, without changing the bundle or budget.
    for (name, ct, front, back) in [
        (
            "form-front",
            "application/x-www-form-urlencoded",
            true,
            false,
        ),
        (
            "form-back",
            "application/x-www-form-urlencoded",
            false,
            true,
        ),
        ("json-front", "application/json", true, false),
        ("json-back", "application/json", false, true),
        (
            "multipart-front",
            "multipart/form-data; boundary=strata-bench",
            true,
            false,
        ),
        (
            "multipart-back",
            "multipart/form-data; boundary=strata-bench",
            false,
            true,
        ),
    ] {
        let attack = "<script>alert(1)</script>";
        let mut body = if ct == "application/json" {
            let mut doc = json_doc(65536);
            let field = format!("\"probe\":\"{attack}\",");
            if front {
                doc.splice(1..1, field.bytes());
            }
            if back {
                doc.pop();
                doc.push(b',');
                doc.extend_from_slice(field.trim_end_matches(',').as_bytes());
                doc.push(b'}');
            }
            doc
        } else if ct.starts_with("multipart/") {
            let field = |key: &str, value: &str| {
                format!(
                    "--strata-bench\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n"
                )
            };
            let mut doc = Vec::new();
            if front {
                doc.extend_from_slice(field("probe", attack).as_bytes());
            }
            for i in 0..256 {
                doc.extend_from_slice(field(&format!("field{i}"), &"a".repeat(256)).as_bytes());
            }
            if back {
                doc.extend_from_slice(field("probe", attack).as_bytes());
            }
            doc.extend_from_slice(b"--strata-bench--\r\n");
            doc
        } else {
            let probe = format!("probe={attack}&");
            let mut doc = form(65536);
            if front {
                doc.splice(0..0, probe.bytes());
            }
            if back {
                doc.push(b'&');
                doc.extend_from_slice(probe.as_bytes());
            }
            doc
        };
        body.shrink_to_fit();
        cases.push(base(name, b"POST", "/t", body, Some(ct)));
    }
    let mut header = base("headers", b"GET", "/metadata", vec![], None);
    header.headers.extend([
        ("X-Example-Filter", "1".to_string()),
        (
            "Authorization",
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJleGFtcGxlIn0.signature".to_string(),
        ),
        ("If-None-Match", "W/\"example-v1\"".to_string()),
        (
            "X-Example-Text",
            "select the best union membership plan".to_string(),
        ),
        (
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
        ),
    ]);
    cases.push(header);
    cases
}

fn run_one(
    e: &Arc<Engine>,
    policy: &[u8],
    budget_us: u64,
    event: bool,
    r: &Req,
) -> (u32, Vec<u32>, u8, i32) {
    let (path, args) = r.uri.split_once('?').unwrap_or((&r.uri, ""));
    let mut t = Tx::new(Some(e.clone()), b"bench", 0);
    if budget_us > 0 {
        t.set_budget(budget_us);
    }
    t.set_policy(policy);
    t.set_client_addr(b"192.0.2.10");
    t.request_line(
        r.method,
        r.uri.as_bytes(),
        path.as_bytes(),
        args.as_bytes(),
        b"HTTP/1.1",
    );
    let hs: Vec<(&[u8], &[u8])> = r
        .headers
        .iter()
        .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
        .collect();
    t.request_headers(&hs);
    // as NGINX hands it over: in buffers of 8 KB; a request without a body
    // still ends the body stage (the request_body rules run)
    if r.body.is_empty() {
        t.request_body_chunk(b"", true);
    }
    let mut chunks = r.body.chunks(8192).peekable();
    while let Some(c) = chunks.next() {
        t.request_body_chunk(c, chunks.peek().is_none());
    }
    let v = t.verdict();
    if event {
        // as the connector does when the transaction ends
        std::hint::black_box(t.encode_event());
    }
    let mut rules = v.rules[..v.n_rules as usize].to_vec();
    rules.sort_unstable();
    (v.action, rules, t.inspection() as u8, v.error)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let get = |k: &str| {
        args.iter()
            .position(|a| a == k)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let bundle = std::fs::read(get("--bundle").expect("--bundle")).expect("bundle");
    let pubkey = std::fs::read(get("--pubkey").expect("--pubkey")).expect("pubkey");
    let policy = get("--policy").unwrap_or_else(|| "example-api".into());
    let iters: usize = get("--iterations")
        .map(|s| s.parse().expect("--iterations"))
        .unwrap_or(2000);
    assert!(iters > 0, "--iterations must be positive");
    let only = get("--only");
    if let Some(name) = &only {
        assert!(
            requests().iter().any(|r| r.name == name),
            "unknown --only request"
        );
    }
    // W13-R-02: one transaction in N timed rule by rule (0: none; the
    // engine's default is 100)
    if let Some(n) = get("--rule-cost-every") {
        libstrata::rulecost::set_sample_every(n.parse().expect("--rule-cost-every"));
    }
    // also encode the event of each transaction, as the connector does
    let event = args.iter().any(|a| a == "--event");
    // Opt-in diagnostic only: 100% sampling changes timings, never an SLO run.
    let profile_cost = args.iter().any(|a| a == "--profile-cost");
    if profile_cost {
        assert!(
            !args
                .iter()
                .any(|a| matches!(a.as_str(), "--cold" | "--rule-cost-ab")),
            "--profile-cost requires the regular timed workload"
        );
        libstrata::rulecost::set_sample_every(1);
    }
    // as NGINX runs it: strata_cpu_budget (10 ms by default); 0 = none
    let budget_us: u64 = get("--budget-us")
        .map(|s| s.parse().expect("--budget-us"))
        .unwrap_or(0);

    let map = || {
        Arc::new(
            Engine::map(
                Box::new(strata_hs::AlignedBuf::from_bytes(&bundle)),
                &pubkey,
            )
            .unwrap_or_else(|(rc, m)| panic!("bundle: {rc} {m}")),
        )
    };
    if let Some(n) = get("--cold") {
        let n: usize = n.parse().expect("--cold");
        assert!(n > 0, "--cold must be positive");
        for r in requests() {
            if only.as_deref().is_some_and(|o| o != r.name) {
                continue;
            }
            let mut first = Vec::with_capacity(n);
            let mut warm = Vec::with_capacity(n);
            let mut last = (0, vec![], 0, 0);
            let warm_first = args.iter().any(|a| a == "--warm");
            let mut first_full = 0usize;
            let mut first_errors = 0usize;
            for _ in 0..n {
                let e = map();
                // as a connector may do after loading a bundle, off the
                // request path
                if warm_first {
                    e.warm_thread();
                }
                let s = Instant::now();
                last = run_one(&e, policy.as_bytes(), budget_us, event, &r);
                first.push(s.elapsed().as_secs_f64() * 1e6);
                first_full += usize::from(last.2 == libstrata::event::Inspection::Full as u8);
                first_errors += usize::from(last.3 != libstrata::verdict::OK);
                let s = Instant::now();
                run_one(&e, policy.as_bytes(), budget_us, event, &r);
                warm.push(s.elapsed().as_secs_f64() * 1e6);
            }
            first.sort_by(|a, b| a.total_cmp(b));
            warm.sort_by(|a, b| a.total_cmp(b));
            println!(
                "{}",
                serde_json::json!({
                    "request":r.name,"cold":n,"warm_first":warm_first,"budget_us":budget_us,
                    "first_p50_us":first[n/2],"first_max_us":first[n-1],"second_p50_us":warm[n/2],
                    "first_full":first_full,"first_errors":first_errors,"action":last.0,"rules":last.1
                })
            );
        }
        return;
    }

    let t0 = Instant::now();
    let e = map();
    eprintln!(
        "strata-bench: bundle mapped in {} ms",
        t0.elapsed().as_millis()
    );
    let rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS"))
                .map(str::to_string)
        })
        .unwrap_or_default();
    eprintln!("strata-bench: after map {rss}");
    if args.iter().any(|a| a == "--compile-all") {
        let t = Instant::now();
        let n = e.regexes().compile_all();
        let rss = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS"))
                    .map(str::to_string)
            })
            .unwrap_or_default();
        eprintln!(
            "strata-bench: {n}/{} fallback regexes compiled in {} ms, {rss}",
            e.regexes().len(),
            t.elapsed().as_millis()
        );
    }
    eprintln!(
        "strata-bench: {} of {} fallback regexes compiled at map (rules evaluated on every request)",
        e.precompile_hot_regexes(),
        e.regexes().len()
    );
    let (gated, groups) = e.prefilter().stats();
    eprintln!(
        "strata-bench: {} rules, {gated} gated by the prefilter, {groups} scan groups",
        e.n_rules()
    );
    if args.iter().any(|a| a == "--diagnose") {
        for (k, n) in libstrata::eval::Prefilter::diagnose(&e.tables(), e.regexes()) {
            eprintln!("  {n:6} {k}");
        }
    }

    if args.iter().any(|a| a == "--rule-cost-ab") {
        for r in requests() {
            if only.as_deref().is_some_and(|o| o != r.name) {
                continue;
            }
            for _ in 0..50 {
                run_one(&e, policy.as_bytes(), budget_us, event, &r);
            }
            let modes = [0u64, 100, 1];
            let mut sum = [0f64; 3];
            let mut count = [0usize; 3];
            for i in 0..iters * 3 {
                let m = i % 3;
                libstrata::rulecost::set_sample_every(modes[m]);
                let s = Instant::now();
                run_one(&e, policy.as_bytes(), budget_us, event, &r);
                sum[m] += s.elapsed().as_secs_f64() * 1e6;
                count[m] += 1;
            }
            let mean = |m: usize| sum[m] / count[m].max(1) as f64;
            println!(
                "{{\"request\":\"{}\",\"n\":{},\"off_us\":{:.1},\"one_percent_us\":{:.1},\"all_us\":{:.1}}}",
                r.name,
                iters,
                mean(0),
                mean(1),
                mean(2)
            );
        }
        return;
    }
    for r in requests() {
        if only.as_deref().is_some_and(|o| o != r.name) {
            continue;
        }
        let n = if r.body.len() > 100_000 {
            (iters / 20).max(20)
        } else {
            iters
        };
        for _ in 0..n.min(50) {
            run_one(&e, policy.as_bytes(), budget_us, event, &r); // warm-up
        }
        if profile_cost {
            e.rule_costs().take(); // discard warm-up samples
        }
        let mut us = Vec::with_capacity(n);
        let mut last = (0, vec![], 0, 0);
        let mut inspections = [0usize; 4];
        let mut blocked = 0usize;
        let mut matched = 0usize;
        let mut errors = 0usize;
        let mut budget_errors = 0usize;
        for _ in 0..n {
            let s = Instant::now();
            last = run_one(&e, policy.as_bytes(), budget_us, event, &r);
            us.push(s.elapsed().as_secs_f64() * 1e6);
            inspections[usize::from(last.2)] += 1;
            blocked += usize::from(last.0 == libstrata::verdict::ACTION_BLOCK);
            matched += usize::from(!last.1.is_empty());
            errors += usize::from(last.3 != libstrata::verdict::OK);
            budget_errors += usize::from(last.3 == libstrata::verdict::E_BUDGET);
        }
        if profile_cost {
            let (costs, sampled_requests, engine_ns) = e.rule_costs().take();
            let tables = e.tables();
            let rows: Vec<_> = costs
                .iter()
                .take(20)
                .map(|&(index, samples, total_ns, max_ns)| {
                    serde_json::json!({
                        "rule_id": index.and_then(|i| tables.rule(i as usize)).map(|r| r.id),
                        "phase": if index.is_none() { "prefilter" } else { "rule" },
                        "samples": samples, "total_ns": total_ns, "max_ns": max_ns
                    })
                })
                .collect();
            eprintln!(
                "{}",
                serde_json::json!({"kind":"sampled_rule_cost_diagnostic", "request":r.name,
                "sample_every":1, "sampled_requests":sampled_requests, "recorded_engine_ns":engine_ns, "top20":rows})
            );
        }
        us.sort_by(|a, b| a.total_cmp(b));
        let mean = us.iter().sum::<f64>() / n as f64;
        let pct = |p: f64| us[((n as f64 * p) as usize).min(n - 1)];
        println!(
            "{}",
            serde_json::json!({
                "request": r.name, "n": n, "body_bytes": r.body.len(), "budget_us": budget_us,
                "mean_us": mean, "p50_us": pct(0.5), "p99_us": pct(0.99), "max_us": us[n-1],
                "action": last.0, "rules": last.1,
                "full": inspections[1], "partial": inspections[2], "body_skipped": inspections[3],
                "blocked": blocked, "matched": matched, "errors": errors, "budget_errors": budget_errors,
                "engine_serial_rps": 1_000_000.0 / mean
            })
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_probes_are_valid_and_at_both_ends() {
        let cases = requests();
        for kind in ["form", "json", "multipart"] {
            let front = cases
                .iter()
                .find(|r| r.name == format!("{kind}-front"))
                .unwrap();
            let back = cases
                .iter()
                .find(|r| r.name == format!("{kind}-back"))
                .unwrap();
            for r in [front, back] {
                assert!(r.body.len() >= 65536);
                assert!(
                    r.headers
                        .iter()
                        .any(|(k, v)| *k == "Content-Length" && v == &r.body.len().to_string())
                );
                if kind == "json" {
                    serde_json::from_slice::<serde_json::Value>(&r.body).unwrap();
                }
                let positions: Vec<_> = r
                    .body
                    .windows(8)
                    .enumerate()
                    .filter(|(_, v)| *v == b"<script>")
                    .map(|(i, _)| i)
                    .collect();
                assert_eq!(positions.len(), 1);
                if r.name.ends_with("front") {
                    assert!(positions[0] < 256);
                } else {
                    assert!(positions[0] > r.body.len() - 256);
                }
            }
        }
    }
}
