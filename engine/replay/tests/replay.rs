//! W11-R-01: the replay core reads the sample files the control plane
//! writes (format 1; fixture written by control-plane/replay's
//! TestVectors -update from docs/spec/examples/replay-anon-v1.json) and
//! replays them through a bundle.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use strata_compiler::{Build, compile, from_yaml, load, policies_from, rules_from_ir};
use strata_replay::{Sample, compare, evaluate, read_file, run, write_file};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/samples-v1.parquet")
}

// the records the Go writer produced, from the vector file
fn vectors() -> Vec<serde_json::Value> {
    let b = std::fs::read(repo().join("docs/spec/examples/replay-anon-v1.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["output"].clone())
        .collect()
}

#[test]
fn reads_what_the_control_plane_writes() {
    let (key, samples) = read_file(&fixture()).unwrap();
    assert_eq!(key, "test-1");
    let want = vectors();
    assert_eq!(samples.len(), want.len());
    for (s, w) in samples.iter().zip(&want) {
        let str_of = |k: &str| w[k].as_str().unwrap_or_default().to_string();
        assert_eq!(s.ts_ms, w["ts_ms"].as_i64().unwrap());
        assert_eq!(
            (
                &s.node_id, &s.policy, &s.method, &s.raw_uri, &s.uri, &s.args, &s.proto, &s.client
            ),
            (
                &str_of("node_id"),
                &str_of("policy"),
                &str_of("method"),
                &str_of("raw_uri"),
                &str_of("uri"),
                &str_of("args"),
                &str_of("proto"),
                &str_of("client")
            )
        );
        assert_eq!(s.headers, str_of("headers"));
        assert_eq!(
            (s.action.clone(), s.rules.clone()),
            (str_of("action"), str_of("rules"))
        );
        assert_eq!(s.body_len, w["body_len"].as_i64().unwrap());
        assert_eq!(s.body_truncated, w["body_truncated"].as_bool().unwrap());
        // Go's encoding/json writes []byte as base64
        let body = w["body"].as_str().map(b64).unwrap_or_default();
        assert_eq!(s.body, body);
    }
}

fn b64(s: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = vec![];
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|&c| c != b'=') {
        acc = (acc << 6) | T.iter().position(|&t| t == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

#[test]
fn write_then_read_round_trip() {
    let (_, samples) = read_file(&fixture()).unwrap();
    let dir = std::env::temp_dir().join(format!("strata-replay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("rt.parquet");
    write_file(&p, "test-1", &samples, 3).unwrap();
    let (key, back) = read_file(&p).unwrap();
    assert_eq!(key, "test-1");
    assert_eq!(back, samples);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn refuses_another_format() {
    let dir = std::env::temp_dir().join(format!("strata-replay-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("x.parquet");
    std::fs::write(&p, b"not a parquet file").unwrap();
    assert!(read_file(&p).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

const SEED: [u8; 32] = [11; 32];

// the CRS pack of the repository (the protocol layer is built in)
fn engine() -> Arc<Engine> {
    let mut rules = vec![];
    for dir in ["rules/crs"] {
        let mut files: Vec<_> = std::fs::read_dir(repo().join(dir))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
            .collect();
        files.sort();
        for f in files {
            rules.extend(rules_from_ir(&load(&f).unwrap()).unwrap());
        }
    }
    let pol = policies_from(
        &from_yaml("policies:\n  - { name: example-api, mode: enforce }\n  - { name: example-web, mode: shadow }\n").unwrap(),
        Path::new("."),
    )
    .unwrap();
    let b = compile(
        &rules,
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

#[test]
fn replays_anonymized_samples() {
    let e = engine();
    let (_, samples) = read_file(&fixture()).unwrap();
    let got: Vec<&str> = samples
        .iter()
        .map(|s| evaluate(&e, s, None).action)
        .collect();
    // 0: SQLi in the query and the JSON body survive anonymization: blocked
    // 1: XSS in a multipart field of an enforce policy: blocked
    // 2: double-encoded <script> on the shadow policy: never blocked
    // 3: a login form: no injection rule
    assert_eq!(got[0], "block", "{:?}", evaluate(&e, &samples[0], None));
    assert_eq!(got[1], "block", "{:?}", evaluate(&e, &samples[1], None));
    assert_ne!(got[2], "block");
    // the vector has no Host and no Content-Length (and no User-Agent): only those protocol
    // rules (920180, 920280, 920320), logged on the shadow policy
    let o = evaluate(&e, &samples[3], None);
    assert_eq!((o.action, o.rules), ("log", vec![920180, 920280, 920320]));
    // the draft runs under another policy name: example-web is shadow
    assert_eq!(evaluate(&e, &samples[0], Some("example-web")).action, "log");

    let r = run(e.clone(), &[&fixture()], None, 3).unwrap();
    assert_eq!(r.samples, 4);
    let api = &r.routes["example-api"];
    assert_eq!(api.samples, 2);
    assert_eq!(api.actions.get("block"), Some(&2));
    // sample 1 was "log" when sampled, "block" now: a candidate false
    // positive of this bundle
    assert_eq!(api.newly_blocked, 1);
    assert_eq!(api.changed.get("log -> block"), Some(&1));
    // sample 0 stops at its sqlmap user agent (913100 blocks alone); without
    // it the SQL injection of the anonymized query and body still blocks
    let o = evaluate(&e, &samples[0], None);
    assert_eq!(o.rules, [913100]);
    let mut no_ua = samples[0].clone();
    no_ua.headers = no_ua.headers.replace(r#"["User-Agent","sqlmap/1.8"],"#, "");
    let o2 = evaluate(&e, &no_ua, None);
    assert_eq!(o2.action, "block");
    assert!(
        o2.rules.iter().any(|id| (942000..943000).contains(id)),
        "SQLi rules: {:?}",
        o2.rules
    );
    assert!(o.rules.iter().all(|id| r.rules.contains_key(id)));
}

#[test]
fn threads_give_the_same_report() {
    let e = engine();
    let (_, base) = read_file(&fixture()).unwrap();
    let samples: Vec<Sample> = (0..2_000).map(|i| base[i % base.len()].clone()).collect();
    let dir = std::env::temp_dir().join(format!("strata-replay-thr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("many.parquet");
    write_file(&p, "test-1", &samples, 300).unwrap();
    let one = run(e.clone(), &[&p], None, 1).unwrap();
    let four = run(e, &[&p, &p], None, 4).unwrap();
    assert_eq!(one.samples, 2_000);
    assert_eq!(four.samples, 4_000);
    for (k, r) in &one.routes {
        let f = &four.routes[k];
        assert_eq!(f.samples, 2 * r.samples, "{k}");
        assert_eq!(f.newly_blocked, 2 * r.newly_blocked, "{k}");
        for (a, n) in &r.actions {
            assert_eq!(f.actions[a], 2 * n, "{k} {a}");
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

// a bundle of the same policies without any CRS rule (protocol layer only)
fn bare_engine() -> Arc<Engine> {
    let pol = policies_from(
        &from_yaml("policies:\n  - { name: example-api, mode: enforce }\n  - { name: example-web, mode: shadow }\n").unwrap(),
        Path::new("."),
    )
    .unwrap();
    let b = compile(
        &[],
        &pol,
        &Build {
            version: 2,
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

// W12-R-01: a draft bundle against the bundle in force on the same
// samples, per route: what the draft newly blocks (candidate false
// positives) and newly lets through (candidate false negatives), with the
// rules responsible.
#[test]
fn compare_a_draft_with_the_baseline() {
    let (crs, bare) = (engine(), bare_engine());
    let c = compare(crs.clone(), bare.clone(), &[&fixture()], None, 2).unwrap();
    assert_eq!(c.samples, 4);
    let api = &c.routes["example-api"];
    assert_eq!(
        (api.samples, api.newly_blocked, api.newly_allowed),
        (2, 2, 0),
        "{api:?}"
    );
    assert!(
        api.newly_blocked_rules.contains_key(&913100),
        "{:?}",
        api.newly_blocked_rules
    );
    assert_eq!(api.examples_blocked.len(), 2);
    assert_eq!(api.examples_blocked[0].baseline, "allow");
    // the samples recorded block and log when taken
    assert_eq!(
        api.newly_blocked_sampled.values().sum::<u64>(),
        2,
        "{:?}",
        api.newly_blocked_sampled
    );
    // the shadow policy never blocks: nothing changes there
    assert_eq!(c.routes["example-web"].newly_blocked, 0);

    // the other way round: the rules the draft drops
    let r = compare(bare, crs, &[&fixture()], None, 1).unwrap();
    let api = &r.routes["example-api"];
    assert_eq!((api.newly_blocked, api.newly_allowed), (0, 2));
    assert!(api.newly_allowed_rules.contains_key(&913100));
    let md = r.markdown("Draft: no CRS rule");
    assert!(
        md.contains("| `example-api` | 2 | 2 → 0 | 0 (0.00%) | 2 |"),
        "{md}"
    );
    assert!(md.contains("Baseline rules of the newly allowed: "), "{md}");
}

#[test]
fn compare_threads_give_the_same_counts() {
    let (crs, bare) = (engine(), bare_engine());
    let (_, base) = read_file(&fixture()).unwrap();
    let samples: Vec<Sample> = (0..1_000).map(|i| base[i % base.len()].clone()).collect();
    let dir = std::env::temp_dir().join(format!("strata-replay-cmp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("many.parquet");
    write_file(&p, "test-1", &samples, 128).unwrap();
    let one = compare(crs.clone(), bare.clone(), &[&p], None, 1).unwrap();
    let four = compare(crs, bare, &[&p], None, 4).unwrap();
    for (k, r) in &one.routes {
        let f = &four.routes[k];
        assert_eq!(
            (r.samples, r.newly_blocked, r.newly_allowed),
            (f.samples, f.newly_blocked, f.newly_allowed),
            "{k}"
        );
        assert_eq!(r.newly_blocked_rules, f.newly_blocked_rules, "{k}");
        assert!(f.examples_blocked.len() <= 5);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
