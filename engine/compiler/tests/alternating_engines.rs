//! Test that two different engines alternating on the same thread isolate
//! DFA cache and Hyperscan scratch/stream correctly by engine ID.

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::OK;
use std::sync::Arc;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [42; 32];

fn make_engine(rule_id: u32, keyword: &str) -> Arc<Engine> {
    let yaml = format!(
        r#"
ir_version: 1
ruleset: {{ name: test, version: "1" }}
rules:
  - id: {rule_id}
    name: test_rule_{rule_id}
    layer: managed
    stage: request_headers
    score: 100
    severity: critical
    match:
      all:
        - targets: [ {{ var: args }} ]
          operator: {{ type: contains, value: "{keyword}" }}
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
fn alternating_engines_on_same_thread() {
    let engine1 = make_engine(900001, "alpha_token");
    let engine2 = make_engine(900002, "beta_token");

    assert_ne!(engine1.id(), engine2.id(), "engines must have distinct IDs");

    for i in 0..20 {
        // Run on engine 1 with alpha payload
        {
            let mut tx = Tx::new(Some(engine1.clone()), b"node", 0);
            tx.set_policy(b"example-api");
            assert_eq!(
                tx.request_line(b"GET", b"/test", b"/test", b"q=alpha_token", b"HTTP/1.1"),
                OK
            );
            assert_eq!(tx.request_headers(&[(b"Host", b"example.test")]), OK);
            let v = tx.verdict();
            assert!(
                v.rules[..v.n_rules as usize].contains(&900001),
                "engine1 must match alpha in iter {i}"
            );
        }

        // Run on engine 2 with beta payload
        {
            let mut tx = Tx::new(Some(engine2.clone()), b"node", 0);
            tx.set_policy(b"example-api");
            assert_eq!(
                tx.request_line(b"GET", b"/test", b"/test", b"q=beta_token", b"HTTP/1.1"),
                OK
            );
            assert_eq!(tx.request_headers(&[(b"Host", b"example.test")]), OK);
            let v = tx.verdict();
            assert!(
                v.rules[..v.n_rules as usize].contains(&900002),
                "engine2 must match beta in iter {i}"
            );
        }

        // Run on engine 1 with beta payload (should NOT match)
        {
            let mut tx = Tx::new(Some(engine1.clone()), b"node", 0);
            tx.set_policy(b"example-api");
            assert_eq!(
                tx.request_line(b"GET", b"/test", b"/test", b"q=beta_token", b"HTTP/1.1"),
                OK
            );
            assert_eq!(tx.request_headers(&[(b"Host", b"example.test")]), OK);
            let v = tx.verdict();
            assert_eq!(v.n_rules, 0, "engine1 must not match beta in iter {i}");
        }

        // Run on engine 2 with alpha payload (should NOT match)
        {
            let mut tx = Tx::new(Some(engine2.clone()), b"node", 0);
            tx.set_policy(b"example-api");
            assert_eq!(
                tx.request_line(b"GET", b"/test", b"/test", b"q=alpha_token", b"HTTP/1.1"),
                OK
            );
            assert_eq!(tx.request_headers(&[(b"Host", b"example.test")]), OK);
            let v = tx.verdict();
            assert_eq!(v.n_rules, 0, "engine2 must not match alpha in iter {i}");
        }
    }
}
