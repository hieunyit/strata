//! W17-S-01: CRS paranoia levels per policy, compiled. A rule up to the
//! policy's `crs_paranoia` blocks as usual; above it, up to
//! `crs_paranoia_shadow`, it is reported with an Event ID but never blocks;
//! above that it does not run. A bundle where no policy goes past level 1
//! leaves the higher rules out.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_LOG, OK};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [13; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: example-crs, version: "1" }
rules:
  - id: 942901
    name: level 1
    layer: managed
    stage: request_headers
    match: { all: [ { targets: [{ var: args }], operator: { type: contains, value: alpha } } ] }
    score: 100
    severity: critical
    paranoia_level: 1
    metadata: { source: strata, license: Apache-2.0, attack_type: sql-injection }
  - id: 942902
    name: level 2
    layer: managed
    stage: request_headers
    match: { all: [ { targets: [{ var: args }], operator: { type: contains, value: beta } } ] }
    score: 100
    severity: critical
    paranoia_level: 2
    metadata: { source: strata, license: Apache-2.0, attack_type: sql-injection }
  - id: 942903
    name: level 3
    layer: managed
    stage: request_headers
    match: { all: [ { targets: [{ var: args }], operator: { type: contains, value: gamma } } ] }
    score: 100
    severity: critical
    paranoia_level: 3
    metadata: { source: strata, license: Apache-2.0, attack_type: sql-injection }
"#;

fn bundle(policies: &str) -> Result<Vec<u8>, String> {
    let rules = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol =
        policies_from(&from_yaml(policies).unwrap(), Path::new(".")).map_err(|e| e.to_string())?;
    compile(
        &rules,
        &pol,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )
    .map_err(|e| e.to_string())
}

fn engine(policies: &str) -> Arc<Engine> {
    let b = bundle(policies).unwrap();
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

/// (action, score, rules, has an ID)
fn run(e: &Arc<Engine>, policy: &[u8], args: &[u8]) -> (u32, i32, Vec<u32>, bool) {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(policy);
    assert_eq!(t.request_line(b"GET", b"/q", b"/q", args, b"HTTP/1.1"), OK);
    assert_eq!(t.request_headers(&[(b"Host", b"api.example.test")]), OK);
    let v = t.verdict();
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort();
    (v.action, v.score, r, v.id.is_some())
}

#[test]
fn enforce_shadow_and_skip_per_policy() {
    let e = engine(
        "policies:
  - { name: example-default, mode: enforce }
  - { name: example-shadow, mode: enforce, crs_paranoia_shadow: 2 }
  - { name: example-pl2, mode: enforce, crs_paranoia: 2 }
  - { name: example-pl3, mode: enforce, crs_paranoia: 2, crs_paranoia_shadow: 3 }",
    );
    // level 1 blocks everywhere
    for p in [
        &b"example-default"[..],
        b"example-shadow",
        b"example-pl2",
        b"example-pl3",
    ] {
        assert_eq!(
            run(&e, p, b"q=alpha"),
            (ACTION_BLOCK, 100, vec![942901], true)
        );
    }
    // level 2: not run, reported, blocks, blocks
    assert_eq!(
        run(&e, b"example-default", b"q=beta"),
        (ACTION_ALLOW, 0, vec![], false)
    );
    assert_eq!(
        run(&e, b"example-shadow", b"q=beta"),
        (ACTION_LOG, 0, vec![942902], true)
    );
    assert_eq!(
        run(&e, b"example-pl2", b"q=beta"),
        (ACTION_BLOCK, 100, vec![942902], true)
    );
    assert_eq!(
        run(&e, b"example-pl3", b"q=beta"),
        (ACTION_BLOCK, 100, vec![942902], true)
    );
    // level 3: reported by example-pl3 only
    for p in [&b"example-default"[..], b"example-shadow", b"example-pl2"] {
        assert_eq!(run(&e, p, b"q=gamma"), (ACTION_ALLOW, 0, vec![], false));
    }
    assert_eq!(
        run(&e, b"example-pl3", b"q=gamma"),
        (ACTION_LOG, 0, vec![942903], true)
    );
    // a shadow match does not hide an enforced one, nor add to its score
    assert_eq!(
        run(&e, b"example-shadow", b"q=alpha&r=beta"),
        (ACTION_BLOCK, 100, vec![942901, 942902], true)
    );
}

#[test]
fn levels_above_every_policy_are_left_out() {
    let default = bundle("policies: [{ name: example-api, mode: enforce }]").unwrap();
    let pl2 =
        bundle("policies: [{ name: example-api, mode: enforce, crs_paranoia_shadow: 2 }]").unwrap();
    let pl3 =
        bundle("policies: [{ name: example-api, mode: enforce, crs_paranoia_shadow: 3 }]").unwrap();
    let has = |b: &[u8], id: u32| b.windows(4).any(|w| w == id.to_le_bytes());
    assert!(has(&default, 942901) && !has(&default, 942902) && !has(&default, 942903));
    assert!(has(&pl2, 942902) && !has(&pl2, 942903));
    assert!(has(&pl3, 942903));
    let e = engine("policies: [{ name: example-api, mode: enforce }]");
    assert_eq!(
        run(&e, b"example-api", b"q=beta"),
        (ACTION_ALLOW, 0, vec![], false)
    );
}

#[test]
fn invalid_levels_are_refused() {
    for p in [
        "policies: [{ name: example-api, mode: enforce, crs_paranoia: 0 }]",
        "policies: [{ name: example-api, mode: enforce, crs_paranoia: 5 }]",
        "policies: [{ name: example-api, mode: enforce, crs_paranoia_shadow: 5 }]",
        "policies: [{ name: example-api, mode: enforce, crs_paranoia: 3, crs_paranoia_shadow: 2 }]",
        "policies: [{ name: example-api, mode: enforce, crs_paranoia: \"2\" }]",
    ] {
        assert!(bundle(p).is_err(), "{p}");
    }
    // shadow defaults to the enforced level
    let e = engine("policies: [{ name: example-api, mode: enforce, crs_paranoia: 3 }]");
    assert_eq!(
        run(&e, b"example-api", b"q=gamma"),
        (ACTION_BLOCK, 100, vec![942903], true)
    );
}
