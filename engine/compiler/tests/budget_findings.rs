//! #28 (PO 16/10/2026): when the CPU budget runs out, what the engine found
//! before counts. The budget usually runs out in the prefilter's scans (they
//! come before any rule): the candidates it found on the values it scanned
//! get one grace (eval::GRACE_NS) to be confirmed. A payload the prefilter
//! scanned blocks, even with fail mode open; a value it did not reach is
//! not inspected and the fail mode decides, as before. And the budget grows
//! with the body inspected (tx::BODY_BUDGET_NS_PER_KB).

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_BLOCK, E_BUDGET, OK};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [51; 32];

/// The base budget: 0.5 ms, for the header stage (a budget that runs out
/// there stays out). The body adds 0.5 ms per KB (about 3 ms for these
/// 6 KB): enough to parse the form, not to scan its 2048 values (names and
/// values) through three chains of 10 transformations (about 9 ms in a
/// release build, much more in a debug one).
const BUDGET_US: u64 = 500;

const RULES: &str = r#"
ir_version: 1
ruleset: { name: budget-findings, version: "1" }
rules:
  - id: 930601
    name: marker in an argument
    layer: managed
    stage: request_body
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args }, { var: args_names } ]
          transforms: [ lowercase ]
          operator: { type: contains, value: "evil-marker" }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 930602
    name: another pattern, so that values are scanned
    layer: managed
    stage: request_body
    score: 5
    severity: notice
    action_mode: score
    match:
      all:
        - targets: [ { var: args }, { var: args_names } ]
          multi_match: true
          transforms: [ url_decode_uni, html_entity_decode, js_decode, css_decode, remove_nulls, compress_whitespace, remove_whitespace, cmd_line, replace_comments, normalize_path ]
          operator: { type: rx, value: "(?i)union.{0,20}select" }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 930603
    name: more scanning, another chain
    layer: managed
    stage: request_body
    score: 5
    severity: notice
    action_mode: score
    match:
      all:
        - targets: [ { var: args }, { var: args_names } ]
          multi_match: true
          transforms: [ normalize_path, replace_comments, cmd_line, remove_whitespace, compress_whitespace, remove_nulls, css_decode, js_decode, html_entity_decode, url_decode_uni ]
          operator: { type: rx, value: "(?i)sleep\\s*\\(\\s*3" }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 930604
    name: more scanning, another chain
    layer: managed
    stage: request_body
    score: 5
    severity: notice
    action_mode: score
    match:
      all:
        - targets: [ { var: args }, { var: args_names } ]
          multi_match: true
          transforms: [ lowercase, js_decode, url_decode_uni, cmd_line, normalize_path, remove_nulls, html_entity_decode, css_decode, replace_comments, compress_whitespace ]
          operator: { type: rx, value: "(?i)sleep\\s*\\(\\s*4" }
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

/// Where the marker is. The prefilter scans every value of the form, then
/// every name: the first value is scanned first, the last name last.
#[derive(Clone, Copy)]
enum At {
    FirstValue,
    LastName,
}

/// A form of 1024 tiny fields and the marker: few bytes (the body adds
/// little budget), many values to scan (each through long chains of
/// transformations, every step scanned: multi_match).
fn form(at: At) -> String {
    (0..1024)
        .map(|i| match (at, i) {
            (At::FirstValue, 0) => format!("{i}=evil-marker"),
            (At::LastName, 1023) => "evil-marker=x".to_string(),
            _ => format!("{i}=x"),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// The request with a CPU budget of `budget_us`; (action, error).
fn post(e: &Arc<Engine>, budget_us: u64, body: &str) -> (u32, u32) {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_budget(budget_us);
    t.set_policy(b"example-api");
    t.set_client_addr(b"192.0.2.10");
    t.request_line(b"POST", b"/submit", b"/submit", b"", b"HTTP/1.1");
    let len = body.len().to_string();
    t.request_headers(&[
        (b"Host", b"api.example.test"),
        (b"Content-Type", b"application/x-www-form-urlencoded"),
        (b"Content-Length", len.as_bytes()),
    ]);
    t.request_body_chunk(body.as_bytes(), true);
    let v = t.verdict();
    (v.action, v.error as u32)
}

#[test]
fn a_payload_found_before_the_budget_ran_out_blocks() {
    let e = engine();
    // without a budget: blocked wherever the marker is
    assert_eq!(post(&e, 0, &form(At::FirstValue)).0, ACTION_BLOCK);
    assert_eq!(post(&e, 0, &form(At::LastName)).0, ACTION_BLOCK);
    // the marker in the first field was scanned before the budget ran
    // out: confirmed in the grace, blocked, and not a fail-mode error
    let (action, error) = post(&e, BUDGET_US, &form(At::FirstValue));
    assert_eq!((action, error), (ACTION_BLOCK, OK as u32));
}

#[test]
fn a_payload_past_the_scans_is_not_inspected() {
    let e = engine();
    // the last name was not reached: the fail mode decides, as before
    let (action, error) = post(&e, BUDGET_US, &form(At::LastName));
    assert_ne!(action, ACTION_BLOCK);
    assert_eq!(error, E_BUDGET as u32);
}
