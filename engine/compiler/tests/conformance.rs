//! W08-Q-01: the conformance corpus v1. Every request in
//! conformance/corpus/v1.jsonl is run through a real compiled bundle and the
//! engine's decision (allow vs block) must match the expectation. It pins the
//! shared decision of the engine and the connectors: the built-in protocol
//! layer (null byte, encoded dot-segment), the stub rule and representative
//! score / block_alone rules. Run on every engine/ and connectors/ PR
//! (`make test-conformance`).

use std::path::PathBuf;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK};
use serde_json::Value;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [8; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: conformance, version: "1" }
rules:
  - { id: 800300, name: sqli union select, layer: managed, stage: request_headers, score: 100,
      action_mode: score, severity: critical,
      match: { all: [ { targets: [ { var: args } ], transforms: [url_decode_uni, lowercase],
                        operator: { type: rx, value: 'union\s+select' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 700300, name: virtual patch evil exploit, layer: managed, stage: request_headers, score: 10,
      action_mode: block_alone, severity: critical,
      match: { all: [ { targets: [ { var: uri_raw } ], operator: { type: contains, value: "/evil/exploit" } } ] },
      metadata: { source: strata, license: Apache-2.0 } }
"#;

fn engine() -> Arc<Engine> {
    let rules = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(&from_yaml("policies: []").unwrap(), std::path::Path::new(".")).unwrap();
    let b = compile(&rules, &pol, &Build { version: 1, created_at_ms: 0, rollback: false }, &SEED).unwrap();
    let mapped = strata_hs::AlignedBuf::from_bytes(&b);
    Arc::new(Engine::map(Box::new(mapped), &public_key(&SEED)).unwrap())
}

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/corpus/v1.jsonl")
}

#[test]
fn conformance_corpus_v1() {
    let e = engine();
    let text = std::fs::read_to_string(corpus_path()).expect("read corpus");
    let mut checked = 0;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let c: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("bad corpus line {line:?}: {e}"));
        let name = c["name"].as_str().unwrap_or("?");
        let method = c["method"].as_str().unwrap_or("GET");
        let uri = c["uri"].as_str().unwrap_or("/");
        let want = c["expect"].as_str().unwrap_or("allow");
        let (path, args) = uri.split_once('?').unwrap_or((uri, ""));

        let mut headers: Vec<(&[u8], &[u8])> = Vec::new();
        if let Some(obj) = c["headers"].as_object() {
            for (k, v) in obj {
                headers.push((k.as_bytes(), v.as_str().unwrap_or("").as_bytes()));
            }
        }
        let body = c["body"].as_str().unwrap_or("");

        let mut t = Tx::new(Some(e.clone()), b"node", 0);
        t.set_client_addr(b"192.0.2.1");
        t.request_line(method.as_bytes(), uri.as_bytes(), path.as_bytes(), args.as_bytes(), b"HTTP/1.1");
        t.request_headers(&headers);
        if !body.is_empty() {
            t.request_body_chunk(body.as_bytes(), true);
        }
        let v = t.verdict();

        let want_action = if want == "block" { ACTION_BLOCK } else { ACTION_ALLOW };
        assert_eq!(
            v.action, want_action,
            "conformance {name:?}: action {} (score {}, rules {:?}), want {want}",
            v.action, v.score, &v.rules[..v.n_rules as usize]
        );
        checked += 1;
    }
    assert!(checked >= 10, "corpus v1 should have at least 10 cases, ran {checked}");
    println!("conformance corpus v1: {checked} cases pass");
}
