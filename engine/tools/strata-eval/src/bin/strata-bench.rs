//! strata-bench: time the engine alone (no NGINX) on the benchmark requests
//! of W09-Q-01, with a real bundle, as the NGINX connector calls it.
//!
//! strata-bench --bundle <file> --pubkey <file> [--policy example-api] [--iterations 2000]
//!              [--budget-us N] [--only small|nul|attack|json|64k|1m] [--event] [--diagnose]
//!              [--cold N]
//!
//! For each request kind (small GET, 64 KB and 1 MB urlencoded POST, JSON
//! POST, an attack GET) prints one JSON line: mean, p50, p99 and max in µs,
//! the action and the matched rules of the last run (so a speed-up that
//! changes a verdict shows).
//!
//! `--cold N` times instead the first request of a freshly mapped engine, N
//! times per request kind: what a worker pays right after a bundle load
//! (fallback regexes are compiled on first use).

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
    vec![
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
        base(
            "1m",
            b"POST",
            "/t",
            form(1_000_000),
            Some("application/x-www-form-urlencoded"),
        ),
    ]
}

fn run_one(
    e: &Arc<Engine>,
    policy: &[u8],
    budget_us: u64,
    event: bool,
    r: &Req,
) -> (u32, Vec<u32>) {
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
    (v.action, rules)
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
    let only = get("--only");
    // also encode the event of each transaction, as the connector does
    let event = args.iter().any(|a| a == "--event");
    // as NGINX runs it: strata_cpu_budget (2 ms by default); 0 = none
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
        for r in requests() {
            if only.as_deref().is_some_and(|o| o != r.name) {
                continue;
            }
            let mut first = Vec::with_capacity(n);
            let mut warm = Vec::with_capacity(n);
            let mut last = (0, vec![]);
            for _ in 0..n {
                let e = map();
                let s = Instant::now();
                last = run_one(&e, policy.as_bytes(), budget_us, event, &r);
                first.push(s.elapsed().as_secs_f64() * 1e6);
                let s = Instant::now();
                run_one(&e, policy.as_bytes(), budget_us, event, &r);
                warm.push(s.elapsed().as_secs_f64() * 1e6);
            }
            first.sort_by(|a, b| a.total_cmp(b));
            warm.sort_by(|a, b| a.total_cmp(b));
            println!(
                "{{\"request\":\"{}\",\"cold\":{},\"first_p50_us\":{:.1},\"first_max_us\":{:.1},\"second_p50_us\":{:.1},\"action\":{},\"rules\":{:?}}}",
                r.name,
                n,
                first[n / 2],
                first[n - 1],
                warm[n / 2],
                last.0,
                last.1
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
        let mut us = Vec::with_capacity(n);
        let mut last = (0, vec![]);
        for _ in 0..n {
            let s = Instant::now();
            last = run_one(&e, policy.as_bytes(), budget_us, event, &r);
            us.push(s.elapsed().as_secs_f64() * 1e6);
        }
        us.sort_by(|a, b| a.total_cmp(b));
        let mean = us.iter().sum::<f64>() / n as f64;
        let pct = |p: f64| us[((n as f64 * p) as usize).min(n - 1)];
        println!(
            "{{\"request\":\"{}\",\"n\":{},\"mean_us\":{:.1},\"p50_us\":{:.1},\"p99_us\":{:.1},\"max_us\":{:.1},\"action\":{},\"rules\":{:?}}}",
            r.name,
            n,
            mean,
            pct(0.5),
            pct(0.99),
            us[n - 1],
            last.0,
            last.1
        );
    }
}
