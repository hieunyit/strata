//! #28: the rx conditions of the rules in REGEX_OUTSIDE_HS (932340: one
//! pattern that made every scan of the full pack a third slower) run with
//! the regex crate, not in the Hyperscan database, and still match.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{
    Build, REGEX_OUTSIDE_HS, compile, from_yaml, hyperscan_patterns, policies_from, rules_from_ir,
};

const SEED: [u8; 32] = [49; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: regex-outside-hs, version: "1" }
rules:
  - id: 932340
    name: stands for the costly rule
    layer: managed
    stage: request_body
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args } ]
          operator: { type: rx, value: "(?i)w[\"'\\\\]*h[\"'\\\\]*o[\"'\\\\]*a[\"'\\\\]*m[\"'\\\\]*i" }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 930401
    name: another rx rule
    layer: managed
    stage: request_body
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args } ]
          operator: { type: rx, value: "evil[0-9]+marker" }
    metadata: { source: organization, license: Apache-2.0 }
"#;

#[test]
fn the_costly_rule_runs_outside_hyperscan_and_still_matches() {
    assert!(REGEX_OUTSIDE_HS.contains(&932_340));
    let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    // its pattern is not in the database; the other rule's is
    let hs = hyperscan_patterns(&defs).unwrap().unwrap();
    assert!(!hs.rule_of.contains(&932_340), "{:?}", hs.rule_of);
    assert!(hs.rule_of.contains(&930_401));

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
    let e = Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap(),
    );
    let rules = |q: &str| {
        let mut t = Tx::new(Some(e.clone()), b"node", 0);
        t.set_policy(b"example-api");
        t.set_client_addr(b"192.0.2.10");
        let uri = format!("/run?{q}");
        t.request_line(b"GET", uri.as_bytes(), b"/run", q.as_bytes(), b"HTTP/1.1");
        t.request_headers(&[(b"Host", b"api.example.test")]);
        t.request_body_chunk(b"", true);
        let v = t.verdict();
        v.rules[..v.n_rules as usize].to_vec()
    };
    assert_eq!(rules("cmd=w%27h%22o%5Cami"), [932_340]);
    assert_eq!(rules("cmd=WHOAMI"), [932_340]);
    assert_eq!(rules("x=evil42marker"), [930_401]);
    assert!(rules("cmd=who+am+i").is_empty());
}
