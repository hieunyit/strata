//! Hyperscan streaming mode tests (W07-R-01):
//! 1. Pattern with end anchor ($) matches when value is 8192 + k bytes long.
//! 2. Two consecutive values do not bleed state.
//! 3. Budget exhaustion mid-value resets stream and scratch cleanly for next transaction.

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{E_BUDGET, OK};
use std::sync::Arc;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [43; 32];

fn make_engine(rule_id: u32, rx_pattern: &str) -> Arc<Engine> {
    let yaml = format!(
        r#"
ir_version: 1
ruleset: {{ name: test, version: "1" }}
rules:
  - id: {rule_id}
    name: stream_test_rule_{rule_id}
    layer: managed
    stage: request_body
    score: 100
    severity: critical
    match:
      all:
        - targets: [ {{ var: request_body }} ]
          operator: {{ type: rx, value: "{rx_pattern}" }}
    metadata: {{ source: organization, license: Apache-2.0 }}
"#
    );
    let doc = from_yaml(&yaml).unwrap();
    let defs = rules_from_ir(&doc).unwrap();
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

#[test]
fn stream_end_anchor_across_8192_boundary() {
    let engine = make_engine(910001, "end_token$");

    // 1. Value of 8192 + k bytes matching end anchor $
    let mut payload = vec![b'x'; 8192 + 100];
    payload.extend_from_slice(b"end_token");

    let mut tx = Tx::new(Some(engine.clone()), b"node", 0);
    tx.set_policy(b"example-api");
    assert_eq!(tx.request_line(b"POST", b"/p", b"/p", b"", b"HTTP/1.1"), OK);
    assert_eq!(tx.request_headers(&[(b"Host", b"example.test")]), OK);
    // Send in chunks to exercise streaming
    assert_eq!(tx.request_body_chunk(&payload[..4096], false), OK);
    assert_eq!(tx.request_body_chunk(&payload[4096..8192], false), OK);
    assert_eq!(tx.request_body_chunk(&payload[8192..], true), OK);

    let v = tx.verdict();
    assert!(
        v.rules[..v.n_rules as usize].contains(&910001),
        "end anchor $ must match across 8192 boundary"
    );
}

#[test]
fn consecutive_transactions_no_state_bleed() {
    let engine = make_engine(910002, "split_secret_token");

    // Transaction 1: sends prefix only
    {
        let mut tx = Tx::new(Some(engine.clone()), b"node", 0);
        tx.set_policy(b"example-api");
        assert_eq!(tx.request_line(b"POST", b"/p", b"/p", b"", b"HTTP/1.1"), OK);
        assert_eq!(tx.request_headers(&[(b"Host", b"example.test")]), OK);
        assert_eq!(tx.request_body_chunk(b"hello split_secret_", true), OK);
        let v = tx.verdict();
        assert_eq!(v.n_rules, 0, "partial prefix must not match");
    }

    // Transaction 2: sends suffix only; must NOT match even though previous tx had prefix
    {
        let mut tx = Tx::new(Some(engine.clone()), b"node", 0);
        tx.set_policy(b"example-api");
        assert_eq!(tx.request_line(b"POST", b"/p", b"/p", b"", b"HTTP/1.1"), OK);
        assert_eq!(tx.request_headers(&[(b"Host", b"example.test")]), OK);
        assert_eq!(tx.request_body_chunk(b"token goodbye", true), OK);
        let v = tx.verdict();
        assert_eq!(
            v.n_rules, 0,
            "suffix alone must not match (no cross-tx state bleed)"
        );
    }

    // Transaction 3: sends full pattern; must match cleanly
    {
        let mut tx = Tx::new(Some(engine.clone()), b"node", 0);
        tx.set_policy(b"example-api");
        assert_eq!(tx.request_line(b"POST", b"/p", b"/p", b"", b"HTTP/1.1"), OK);
        assert_eq!(tx.request_headers(&[(b"Host", b"example.test")]), OK);
        assert_eq!(
            tx.request_body_chunk(b"here is split_secret_token now", true),
            OK
        );
        let v = tx.verdict();
        assert!(
            v.rules[..v.n_rules as usize].contains(&910002),
            "full token must match cleanly"
        );
    }
}

#[test]
fn budget_exhaustion_mid_stream_resets_cleanly() {
    let engine = make_engine(910003, "clean_reset_probe");

    // 1. Transaction that exhausts budget mid-stream
    {
        let mut tx = Tx::new(Some(engine.clone()), b"node", 0);
        tx.set_policy(b"example-api");
        tx.set_budget(50); // 50 µs budget
        let _ = tx.request_line(b"POST", b"/p", b"/p", b"", b"HTTP/1.1");
        let _ = tx.request_headers(&[
            (b"Host", b"example.test"),
            (b"Content-Type", b"application/x-www-form-urlencoded"),
        ]);
        let big_body = vec![b'a'; 1 << 20];
        let rc = tx.request_body_chunk(&big_body, true);
        assert_eq!(rc, E_BUDGET, "low budget must stop the request");
    }

    // 2. Next transaction on the same thread: normal budget, matching payload
    {
        let mut tx = Tx::new(Some(engine.clone()), b"node", 0);
        tx.set_policy(b"example-api");
        tx.set_budget(100_000);
        assert_eq!(tx.request_line(b"POST", b"/p", b"/p", b"", b"HTTP/1.1"), OK);
        assert_eq!(tx.request_headers(&[(b"Host", b"example.test")]), OK);
        assert_eq!(
            tx.request_body_chunk(b"hello clean_reset_probe world", true),
            OK
        );
        let v = tx.verdict();
        assert!(
            v.rules[..v.n_rules as usize].contains(&910003),
            "subsequent tx after budget exhaustion must match cleanly"
        );
    }

    // 3. Third transaction: normal budget, non-matching payload
    {
        let mut tx = Tx::new(Some(engine.clone()), b"node", 0);
        tx.set_policy(b"example-api");
        tx.set_budget(100_000);
        assert_eq!(tx.request_line(b"POST", b"/p", b"/p", b"", b"HTTP/1.1"), OK);
        assert_eq!(tx.request_headers(&[(b"Host", b"example.test")]), OK);
        assert_eq!(
            tx.request_body_chunk(b"hello innocent request world", true),
            OK
        );
        let v = tx.verdict();
        assert_eq!(
            v.n_rules, 0,
            "non-matching request must produce 0 violations"
        );
    }
}
