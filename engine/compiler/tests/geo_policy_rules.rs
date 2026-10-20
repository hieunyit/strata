//! W19-G2-01: a policy's own geo rules, compiled as rules scoped to it
//! (section SCOPE): block or log, in or outside the countries and ASNs.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_LOG, OK};
use strata_compiler::{Build, compile, from_yaml, geo_from_json, policies_from, rules_from_ir};

const SEED: [u8; 32] = [17; 32];

const GEO: &str = r#"{"countries": {"VN": ["198.51.100.0/25"], "US": ["203.0.113.0/24"]},
  "asns": {"64500": ["198.51.100.0/26"], "64501": ["203.0.113.128/25"]}}"#;

const RULES: &str = r#"
ir_version: 1
ruleset: { name: example-x, version: "1" }
rules:
  - id: 942901
    name: args
    layer: managed
    stage: request_headers
    match: { all: [ { targets: [{ var: args }], operator: { type: contains, value: evil } } ] }
    score: 100
    severity: critical
    metadata: { source: strata, license: Apache-2.0, attack_type: sql-injection }
"#;

fn bundle(policies: &str) -> Result<Vec<u8>, String> {
    let rules = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let mut pol =
        policies_from(&from_yaml(policies).unwrap(), Path::new(".")).map_err(|e| e.to_string())?;
    pol.geo = geo_from_json(GEO.as_bytes())?;
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

/// (action, rules)
fn run(e: &Arc<Engine>, policy: &[u8], addr: &[u8]) -> (u32, Vec<u32>) {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(policy);
    t.set_client_addr(addr);
    assert_eq!(t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1"), OK);
    assert_eq!(t.request_headers(&[(b"Host", b"api.example.test")]), OK);
    let v = t.verdict();
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort();
    (v.action, r)
}

const POLICIES: &str = "policies:
  - name: example-block
    mode: enforce
    geo_rules: [{ id: 190001, countries: [US], action: block }]
  - name: example-log
    mode: enforce
    geo_rules: [{ id: 190002, asns: [64500], action: log }]
  - name: example-only-vn
    mode: enforce
    geo_rules: [{ id: 190003, countries: [VN], not: true, action: block }]
  - name: example-none
    mode: enforce";

#[test]
fn each_policy_runs_its_own_geo_rules() {
    let e = engine(POLICIES);
    let us = b"203.0.113.7";
    let vn = b"198.51.100.10"; // VN, AS64500
    assert_eq!(run(&e, b"example-block", us), (ACTION_BLOCK, vec![190001]));
    assert_eq!(run(&e, b"example-block", vn), (ACTION_ALLOW, vec![]));
    // log: reported, never blocks
    assert_eq!(run(&e, b"example-log", vn), (ACTION_LOG, vec![190002]));
    assert_eq!(run(&e, b"example-log", us), (ACTION_ALLOW, vec![]));
    // not: everything outside VN, local addresses excepted
    assert_eq!(
        run(&e, b"example-only-vn", us),
        (ACTION_BLOCK, vec![190003])
    );
    assert_eq!(
        run(&e, b"example-only-vn", b"8.8.8.8"),
        (ACTION_BLOCK, vec![190003])
    );
    assert_eq!(run(&e, b"example-only-vn", vn), (ACTION_ALLOW, vec![]));
    assert_eq!(
        run(&e, b"example-only-vn", b"10.0.0.1"),
        (ACTION_ALLOW, vec![])
    );
    // a policy without geo rules sees none of the others'
    for a in [&us[..], vn, b"8.8.8.8"] {
        assert_eq!(run(&e, b"example-none", a), (ACTION_ALLOW, vec![]));
    }
    // the shared rules still run for every policy
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-log");
    t.set_client_addr(vn);
    assert_eq!(
        t.request_line(b"GET", b"/", b"/", b"q=evil", b"HTTP/1.1"),
        OK
    );
    assert_eq!(t.request_headers(&[(b"Host", b"api.example.test")]), OK);
    assert_eq!(t.verdict().action, ACTION_BLOCK);
}

#[test]
fn bad_geo_rules_are_refused() {
    // refused by the schema or the compiler; the message matters only
    // where the schema cannot tell
    for (p, why) in [
        (
            "{ id: 190001, countries: [US], action: block }, { id: 190001, countries: [VN], action: log }",
            Some("duplicate rule id"),
        ),
        (
            "{ id: 190001, countries: [DE], action: block }",
            Some("no networks"),
        ),
        ("{ id: 189999, countries: [US], action: block }", None),
        ("{ id: 190001, countries: [us], action: block }", None),
        ("{ id: 190001, countries: [US, US], action: block }", None),
        ("{ id: 190001, countries: [US], action: deny }", None),
        ("{ id: 190001, action: block }", None),
        ("{ id: 190001, asns: [0], action: block }", None),
    ] {
        let policies =
            format!("policies: [{{ name: example-api, mode: enforce, geo_rules: [{p}] }}]");
        let err = bundle(&policies).unwrap_err();
        if let Some(why) = why {
            assert!(err.contains(why), "{p}: {err}");
        }
    }
    // the same id in two policies
    let two = "policies:
  - { name: example-a, mode: enforce, geo_rules: [{ id: 190001, countries: [US], action: block }] }
  - { name: example-b, mode: enforce, geo_rules: [{ id: 190001, countries: [VN], action: block }] }";
    assert!(bundle(two).unwrap_err().contains("duplicate rule id"));
    let many: Vec<String> = (0..17)
        .map(|i| format!("{{ id: {}, countries: [US], action: log }}", 190100 + i))
        .collect();
    let policies = format!(
        "policies: [{{ name: example-api, mode: enforce, geo_rules: [{}] }}]",
        many.join(", ")
    );
    assert!(bundle(&policies).is_err());
}
