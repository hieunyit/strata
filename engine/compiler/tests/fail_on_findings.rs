//! A request that runs the CPU budget out was not inspected whole: in an
//! enforced policy the verdict carries `fail_closed` (ABI flag
//! STRATA_VF_FAIL_CLOSED, 503) whatever the connector's fail mode, with or
//! without findings (22/10/2026; before, #98 did so only with findings and
//! `fail_on_findings: block`, so padding first and the payload last
//! passed). A shadow policy never blocks.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [50; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: fail-on-findings, version: "1" }
rules:
  - id: 930401
    name: a weak sign, below the threshold
    layer: managed
    stage: request_headers
    score: 40
    severity: warning
    action_mode: score
    match:
      all:
        - targets: [ { var: args } ]
          operator: { type: contains, value: "weak-sign" }
    metadata: { source: organization, license: Apache-2.0 }
"#;

const POLICIES: &str = "policies:
  - { name: example-api, mode: enforce, fail_on_findings: block }
  - { name: example-web, mode: enforce }
  - { name: example-shadow, mode: shadow, fail_on_findings: block }";

fn engine(policies: &str) -> Result<Arc<Engine>, String> {
    let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(&from_yaml(policies).unwrap(), Path::new("."))?;
    let b = compile(
        &defs,
        &pol,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )?;
    Engine::map(
        Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
        &public_key(&SEED),
    )
    .map(Arc::new)
    .map_err(|e| e.1.to_string())
}

/// A request with `query`, then the budget runs out.
fn out_of_budget(e: &Arc<Engine>, policy: &[u8], query: &str) -> Tx {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(policy);
    let uri = format!("/v1/items?{query}");
    t.request_line(
        b"GET",
        uri.as_bytes(),
        b"/v1/items",
        query.as_bytes(),
        b"HTTP/1.1",
    );
    t.request_headers(&[(b"Host", b"api.example.test")]);
    t.set_budget_exceeded();
    t
}

#[test]
fn budget_out_fails_closed_with_findings() {
    let e = engine(POLICIES).unwrap();
    let t = out_of_budget(&e, b"example-api", "q=weak-sign");
    let v = t.verdict();
    assert_eq!(v.error, libstrata::verdict::E_BUDGET);
    assert_eq!(v.score, 40);
    assert!(v.fail_closed, "findings + block: fail closed");
}

#[test]
fn budget_out_fails_closed_without_findings_too() {
    let e = engine(POLICIES).unwrap();
    // no finding: the uninspected rest could hold the payload
    assert!(
        out_of_budget(&e, b"example-api", "q=plain")
            .verdict()
            .fail_closed
    );
    // a policy without fail_on_findings
    assert!(
        out_of_budget(&e, b"example-web", "q=plain")
            .verdict()
            .fail_closed
    );
}

#[test]
fn shadow_and_inspected_requests_do_not_fail() {
    let e = engine(POLICIES).unwrap();
    // findings in a shadow policy: never blocks
    assert!(
        !out_of_budget(&e, b"example-shadow", "q=weak-sign")
            .verdict()
            .fail_closed
    );
    // no budget problem: nothing to fail
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-api");
    t.request_line(
        b"GET",
        b"/v1/items?q=weak-sign",
        b"/v1/items",
        b"q=weak-sign",
        b"HTTP/1.1",
    );
    t.request_headers(&[(b"Host", b"api.example.test")]);
    assert!(!t.verdict().fail_closed);
}

#[test]
fn bad_values_are_refused() {
    let p = "policies:\n  - { name: example-api, mode: enforce, fail_on_findings: maybe }";
    assert!(engine(p).is_err());
}
