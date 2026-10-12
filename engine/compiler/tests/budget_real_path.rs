//! W07-R-01 review: the CPU budget measured on the real path (Tx and the
//! CRS and protocol rules), and no truncation that lets an attack through.

use std::sync::Arc;
use std::time::Instant;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::E_BUDGET;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [5; 32];

/// Every rule under the given directories of the repository, plus `extra` (an IR document).
fn engine_from(dirs: &[&str], extra: &str) -> Arc<Engine> {
    let mut defs = vec![];
    for d in dirs {
        let path = format!("{}/../../{}", env!("CARGO_MANIFEST_DIR"), d);
        let mut files: Vec<_> = std::fs::read_dir(&path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        for f in files {
            if f.extension().is_none_or(|e| e != "yaml") {
                continue;
            }
            let mut doc = from_yaml(&std::fs::read_to_string(&f).unwrap()).unwrap();
            if doc.get("rule").is_some() {
                doc = serde_json::json!({"ir_version": 1, "ruleset": {"name": "p", "version": "1"}, "rules": [doc["rule"].clone()]});
            }
            defs.extend(rules_from_ir(&doc).unwrap());
        }
    }
    if !extra.is_empty() {
        defs.extend(rules_from_ir(&from_yaml(extra).unwrap()).unwrap());
    }
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        std::path::Path::new("."),
    )
    .unwrap();
    let b = compile(
        &defs,
        &pol,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )
    .unwrap();
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

/// POST `body` through a transaction with `budget_us` (0: none); (rc of the body call, engine time in µs, rules).
fn post(e: &Arc<Engine>, budget_us: u64, ct: &str, body: &[u8]) -> (i32, u128, Vec<u32>) {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-api");
    t.set_budget(budget_us);
    let start = Instant::now();
    let _ = t.request_line(b"POST", b"/p", b"/p", b"", b"HTTP/1.1");
    let _ = t.request_headers(&[
        (b"Host", b"api.example.test"),
        (b"Content-Type", ct.as_bytes()),
    ]);
    let rc = t.request_body_chunk(body, true);
    let us = if budget_us > 0 && t.budget_elapsed_us() > 0 {
        t.budget_elapsed_us() as u128
    } else {
        start.elapsed().as_micros()
    };
    let v = t.verdict();
    (rc, us, v.rules[..v.n_rules as usize].to_vec())
}

#[test]
fn xss_after_64kb_padding_is_detected() {
    let e = engine_from(
        &[],
        r#"
ir_version: 1
ruleset: { name: p, version: "1" }
rules:
  - { id: 800601, name: xss, layer: managed, stage: request_body, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: args } ], operator: { type: detect_xss } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#,
    );
    let mut body = b"q=".to_vec();
    body.extend(std::iter::repeat_n(b'a', 70_000));
    body.extend_from_slice(b"%3Cscript%3Ealert(1)%3C/script%3E");
    let (_, _, rules) = post(&e, 0, "application/x-www-form-urlencoded", &body);
    assert!(
        rules.contains(&800601),
        "XSS after 64 KB of padding not detected: {rules:?}"
    );
}

/// Run with: cargo test --release -p strata-compiler --test budget_real_path -- --ignored --nocapture
#[test]
#[ignore]
fn budget_really_stops_full_crs_1mb() {
    let e = engine_from(&["rules/crs", "rules/protocol"], "");
    let mut entities = b"q=".to_vec();
    while entities.len() < 1 << 20 {
        entities.extend_from_slice(b"%26amp%3B%26lt%3B");
    }
    let budget = 1_000u64;
    let mut over = vec![];
    for _ in 0..20 {
        let (rc, us, _) = post(&e, budget, "application/x-www-form-urlencoded", &entities);
        assert_eq!(rc, E_BUDGET, "the budget must stop the request");
        over.push(us.saturating_sub(budget as u128));
    }
    over.sort_unstable();
    eprintln!(
        "html entities 1 MB, full CRS, budget {budget} us: overshoot p50 {} us, max {} us",
        over[10], over[19]
    );
}

/// Run with: cargo test --release -p strata-compiler --test budget_real_path -- budget_overshoot_all_9_payloads --exact --ignored --nocapture
#[test]
#[ignore]
fn budget_overshoot_all_9_payloads() {
    let e = engine_from(&["rules/crs", "rules/protocol"], "");
    let one_mb = 1 << 20;
    let budget = 1_000u64;
    let iterations = 200;

    // Helper to run one benchmark and compute p50, p99, max overshoot
    let run_bench = |name: &str, f: &dyn Fn() -> (i32, u128)| {
        // warm up
        for _ in 0..5 {
            let (rc, _) = f();
            assert_eq!(rc, E_BUDGET, "warmup: budget must stop request for {name}");
        }
        let mut overshoots = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let (rc, us) = f();
            assert_eq!(
                rc, E_BUDGET,
                "measurement: budget must stop request for {name}"
            );
            overshoots.push(us.saturating_sub(budget as u128));
        }
        overshoots.sort_unstable();
        let p50 = overshoots[iterations * 50 / 100];
        let p99 = overshoots[(iterations * 99 / 100).saturating_sub(1)];
        let max = *overshoots.last().unwrap();
        eprintln!(
            "| {:<38} | {:>6} us | {:>6} us | {:>6} us |",
            name, p50, p99, max
        );
        (p50, p99, max)
    };

    eprintln!(
        "\n| {:<38} | {:>9} | {:>9} | {:>9} |",
        "Payload (1 MB)", "p50 over", "p99 over", "max over"
    );
    eprintln!("|:{:-<38}-|-{:-<9}:|-{:-<9}:|-{:-<9}:|", "", "", "", "");

    // 1. JSON unclosed string (1 MB)
    let mut json_payload = b"{\"k\":\"".to_vec();
    json_payload.extend(vec![b'a'; one_mb]);
    run_bench("1. JSON unclosed string (1 MB)", &|| {
        let (rc, us, _) = post(&e, budget, "application/json", &json_payload);
        (rc, us)
    });

    // 2. XML CDATA unclosed (1 MB)
    let mut xml_payload = b"<root><![CDATA[".to_vec();
    xml_payload.extend(vec![b'x'; one_mb]);
    run_bench("2. XML unclosed CDATA (1 MB)", &|| {
        let (rc, us, _) = post(&e, budget, "application/xml", &xml_payload);
        (rc, us)
    });

    // 3. Multipart without boundary (1 MB)
    let mp_payload = vec![b'm'; one_mb];
    run_bench("3. Multipart without boundary (1 MB)", &|| {
        let (rc, us, _) = post(&e, budget, "multipart/form-data; boundary=xyz", &mp_payload);
        (rc, us)
    });

    // 4. SQLi comment unclosed (1 MB)
    let mut sqli_payload = b"q=/*".to_vec();
    sqli_payload.extend(vec![b'c'; one_mb]);
    run_bench("4. SQLi unclosed comment (1 MB)", &|| {
        let (rc, us, _) = post(
            &e,
            budget,
            "application/x-www-form-urlencoded",
            &sqli_payload,
        );
        (rc, us)
    });

    // 5. XSS attribute unclosed (1 MB)
    let mut xss_payload = b"q=<div+attr=\"".to_vec();
    xss_payload.extend(vec![b'y'; one_mb]);
    run_bench("5. XSS unclosed attribute (1 MB)", &|| {
        let (rc, us, _) = post(
            &e,
            budget,
            "application/x-www-form-urlencoded",
            &xss_payload,
        );
        (rc, us)
    });

    // 6. 1 MB for rule regex fallback 932230
    let mut fb_payload = b"q=".to_vec();
    fb_payload.extend(vec![b'x'; one_mb]);
    run_bench("6. Regex fallback 932230 (1 MB)", &|| {
        let (rc, us, _) = post(&e, budget, "application/x-www-form-urlencoded", &fb_payload);
        (rc, us)
    });

    // 7. Long URI (1 MB)
    let long_uri = [b"/p?", &vec![b'u'; one_mb][..]].concat();
    run_bench("7. Long URI without delimiter (1 MB)", &|| {
        let mut t = Tx::new(Some(e.clone()), b"node", 0);
        t.set_policy(b"example-api");
        t.set_budget(budget);
        let start = Instant::now();
        let _ = t.request_line(b"GET", &long_uri, &long_uri, b"", b"HTTP/1.1");
        let rc = t.request_headers(&[(b"Host", b"api.example.test")]);
        let us = if budget > 0 && t.budget_elapsed_us() > 0 {
            t.budget_elapsed_us() as u128
        } else {
            start.elapsed().as_micros()
        };
        (rc, us)
    });

    // 8. HTML entity 1 MB
    let mut entities = b"q=".to_vec();
    while entities.len() < one_mb {
        entities.extend_from_slice(b"%26amp%3B%26lt%3B");
    }
    run_bench("8. HTML entities (1 MB)", &|| {
        let (rc, us, _) = post(&e, budget, "application/x-www-form-urlencoded", &entities);
        (rc, us)
    });

    // 9. Plain param 1 MB
    let mut plain = b"q=".to_vec();
    plain.extend(vec![b'a'; one_mb]);
    run_bench("9. Plain parameter (1 MB)", &|| {
        let (rc, us, _) = post(&e, budget, "application/x-www-form-urlencoded", &plain);
        (rc, us)
    });
}

#[test]
#[ignore]
fn zz_review_many_short_tokens() {
    let e = engine_from(&["rules/crs", "rules/protocol"], "");
    for (name, unit) in [
        ("xss many tags", &b"%3Ca+b%3Dc%3E"[..]),
        ("sqli 1-1-1", &b"1-"[..]),
        ("sqli or chain", &b"1+or+1+"[..]),
    ] {
        let mut body = b"q=".to_vec();
        while body.len() < 1 << 20 {
            body.extend_from_slice(unit);
        }
        let mut over = vec![];
        let mut rcs = std::collections::BTreeSet::new();
        for _ in 0..30 {
            let (rc, us, _) = post(&e, 1_000, "application/x-www-form-urlencoded", &body);
            rcs.insert(rc);
            over.push(us.saturating_sub(1_000));
        }
        over.sort_unstable();
        eprintln!(
            "REVIEW {name}: rc {rcs:?} overshoot p50 {} us max {} us",
            over[15], over[29]
        );
    }
}

/// Two chains sharing their first 8 transformations must not share a scan
/// (the scan cache key used to keep only 8 of the up to 16 codes).
#[test]
fn chains_sharing_a_prefix_do_not_share_a_scan() {
    let e = engine_from(
        &[],
        r#"
ir_version: 1
ruleset: { name: p, version: "1" }
rules:
  - { id: 800701, name: with lowercase, layer: managed, stage: request_body, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: args } ],
        transforms: [remove_nulls, remove_nulls, remove_nulls, remove_nulls, remove_nulls, remove_nulls, remove_nulls, remove_nulls, lowercase],
        operator: { type: contains, value: abc } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800702, name: without lowercase, layer: managed, stage: request_body, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: args } ],
        transforms: [remove_nulls, remove_nulls, remove_nulls, remove_nulls, remove_nulls, remove_nulls, remove_nulls, remove_nulls, url_decode],
        operator: { type: contains, value: abc } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#,
    );
    let (_, _, rules) = post(&e, 0, "application/x-www-form-urlencoded", b"q=ABC");
    assert!(rules.contains(&800701), "{rules:?}");
    assert!(
        !rules.contains(&800702),
        "800702 took the scan of another chain: {rules:?}"
    );
}
