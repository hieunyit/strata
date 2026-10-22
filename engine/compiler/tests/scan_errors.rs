//! Audit 22/10/2026 (A-05): a failed Hyperscan scan read as "no match", so
//! the request passed as if inspected. It is now an engine error
//! (E_INTERNAL): the connector applies its fail mode and the breaker counts
//! it. (The prefilter scans before any rule runs, so a failure there comes
//! before any match.)

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::eval::fail_scans_for_test;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_BLOCK, E_INTERNAL, OK};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [52; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: scan-errors, version: "1" }
rules:
  - id: 930702
    name: marker in an argument
    layer: managed
    stage: request_headers
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args } ]
          operator: { type: rx, value: "attack-marker" }
    metadata: { source: organization, license: Apache-2.0 }
"#;

fn engine() -> Arc<Engine> {
    let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        Path::new("."),
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

/// (rc of the headers call, action, error)
fn get(e: &Arc<Engine>, client: &[u8], args: &[u8], fail: bool) -> (i32, u32, i32) {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_client_addr(client);
    t.set_policy(b"example-api");
    t.request_line(b"GET", b"/p", b"/p", args, b"HTTP/1.1");
    fail_scans_for_test(fail);
    let rc = t.request_headers(&[(b"Host", b"api.example.test")]);
    fail_scans_for_test(false);
    let v = t.verdict();
    (rc, v.action, v.error)
}

#[test]
fn failed_scan_is_an_engine_error() {
    let e = engine();
    assert!(
        e.hyperscan().is_some(),
        "the test needs a Hyperscan database"
    );
    let (_, action, error) = get(&e, b"198.51.100.7", b"q=attack-marker", false);
    assert_eq!((action, error), (ACTION_BLOCK, OK), "control: blocked");
    let (rc, action, error) = get(&e, b"198.51.100.7", b"q=attack-marker", true);
    assert_eq!((rc, error), (E_INTERNAL, E_INTERNAL), "not a clean pass");
    assert_ne!(action, ACTION_BLOCK);
    // the flag does not outlive the evaluation
    assert_eq!(get(&e, b"198.51.100.7", b"q=clean", false).2, OK);
}
