//! RS-2 (docs/plan/rule-sets.md): a policy's rule sets (filters on rule
//! metadata) and rule overrides, compiled into section OVERRIDE and run by
//! the engine.

use std::sync::Arc;

use libstrata::bundle::{REQUIRES_OVERRIDE, public_key, verify};
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_LOG, Verdict};
use strata_compiler::{Build, compile, from_yaml, policies_from, rule_sets, rules_from_ir};

const SEED: [u8; 32] = [9; 32];

// bot lists score 0 (they only label); a CRS-like rule scores 100
const RULES: &str = r#"
ir_version: 1
ruleset: { name: rule-sets-test, version: "1" }
rules:
  - { id: 500901, name: scanner bot, layer: managed, stage: request_headers, score: 0, severity: notice,
      match: { all: [ { targets: [ { var: request_headers, key: User-Agent } ], operator: { type: pm, value: [examplescanner] } } ] },
      metadata: { source: crawler-user-agents, license: MIT, upstream_id: s, upstream_version: "1", author: Example List Author, attack_type: bot, tags: [scanner] } }
  - { id: 500902, name: ai crawler, layer: managed, stage: request_headers, score: 0, severity: notice,
      match: { all: [ { targets: [ { var: request_headers, key: User-Agent } ], operator: { type: pm, value: [exampleai] } } ] },
      metadata: { source: crawler-user-agents, license: MIT, upstream_id: a, upstream_version: "1", author: Example List Author, attack_type: bot, tags: [ai-crawler] } }
  - { id: 500903, name: search engine, layer: managed, stage: request_headers, score: 0, severity: notice,
      match: { all: [ { targets: [ { var: request_headers, key: User-Agent } ], operator: { type: pm, value: [examplesearch] } } ] },
      metadata: { source: crawler-user-agents, license: MIT, upstream_id: g, upstream_version: "1", author: Example List Author, attack_type: bot, tags: [search-engine] } }
  - { id: 942901, name: sqli, layer: managed, stage: request_headers, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: path } ], operator: { type: ends_with, value: /union-select } } ] },
      metadata: { source: crs, license: Apache-2.0, upstream_id: "942100", upstream_version: 4.25.2, author: Example CRS Author, attack_type: sql-injection } }
"#;

const POLICIES: &str = r#"policies:
  - name: example-default
    mode: enforce
  - name: example-bots
    mode: enforce
    rule_sets:
      - { name: bots-all, match: { attack_types: [bot] }, action: log }
      - { name: bots-scanners, match: { tags: [scanner] }, action: block }
      - { name: bots-ai, match: { tags: [ai-crawler] }, action: block }
    rule_overrides:
      - { rule: 500902, action: log, reason: "our own AI assistant" }
      - { rule: 942901, action: log, reason: "FP on /union-select, watching" }
  - name: example-sqli-off
    mode: enforce
    rule_sets:
      - { name: sqli, match: { attack_types: [sql-injection] }, action: off }
"#;

fn compiled(policies: &str) -> Result<Vec<u8>, String> {
    let doc = from_yaml(RULES).unwrap();
    let rules = rules_from_ir(&doc).unwrap();
    let mut pol = policies_from(&from_yaml(policies)?, std::path::Path::new("."))?;
    pol.rule_meta = rule_sets::meta_from_ir(&doc);
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
}

fn engine(b: &[u8]) -> Arc<Engine> {
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(b)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

fn run(e: &Arc<Engine>, policy: &str, path: &str, ua: &str) -> Verdict {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_client_addr(b"192.0.2.1");
    t.set_policy(policy.as_bytes());
    t.request_line(b"GET", path.as_bytes(), path.as_bytes(), b"", b"HTTP/1.1");
    t.request_headers(&[(b"User-Agent", ua.as_bytes())]);
    t.verdict()
}

#[test]
fn rule_sets_and_overrides_reach_the_engine() {
    let b = compiled(POLICIES).unwrap();
    let info = verify(&b, &public_key(&SEED)).unwrap();
    assert_eq!(info.requires, REQUIRES_OVERRIDE);
    let e = engine(&b);
    for (policy, path, ua, action) in [
        // without rule sets: bots only label, the attack blocks
        ("example-default", "/", "examplescanner/1.0", ACTION_ALLOW),
        ("example-default", "/union-select", "x", ACTION_BLOCK),
        // scanners blocked by the later set, over "all bots: log"
        ("example-bots", "/", "examplescanner/1.0", ACTION_BLOCK),
        // the AI set blocks, but an override sets this rule back to log
        ("example-bots", "/", "exampleai/2", ACTION_ALLOW),
        // search engines: only in "all bots: log"
        ("example-bots", "/", "examplesearch", ACTION_ALLOW),
        // an attack rule overridden to log: the would-be block is logged
        ("example-bots", "/union-select", "x", ACTION_LOG),
        // a set switching a whole attack type off
        ("example-sqli-off", "/union-select", "x", ACTION_ALLOW),
        ("example-sqli-off", "/", "examplescanner/1.0", ACTION_ALLOW),
    ] {
        let v = run(&e, policy, path, ua);
        assert_eq!(v.action, action, "{policy} {path} {ua}");
    }
    // overridden to off: the rule does not even run
    let v = run(&e, "example-sqli-off", "/union-select", "x");
    assert_eq!(v.n_rules, 0);
    // log: reported, with an Event ID
    let v = run(&e, "example-bots", "/union-select", "x");
    assert_eq!(&v.rules[..v.n_rules as usize], &[942901]);
    assert!(v.id.is_some());
}

#[test]
fn a_bundle_without_rule_sets_has_no_override_section() {
    let b = compiled("policies:\n  - { name: example-default, mode: enforce }\n").unwrap();
    assert_eq!(verify(&b, &public_key(&SEED)).unwrap().requires, 0);
    // a set saying what the rules do anyway writes nothing either: bot
    // rules of the pack are already reported only (signatures: shadow)
    let b = compiled(
        "policies:\n  - { name: example-api, mode: enforce, rule_sets: [ { match: { attack_types: [bot] }, action: log } ] }\n",
    )
    .unwrap();
    assert_eq!(verify(&b, &public_key(&SEED)).unwrap().requires, 0);
    // a set naming a rule of a pack the bundle lacks matches nothing
    let b = compiled(
        "policies:\n  - { name: example-api, mode: enforce, rule_sets: [ { match: { ids: [999999] }, action: off } ] }\n",
    )
    .unwrap();
    assert_eq!(verify(&b, &public_key(&SEED)).unwrap().requires, 0);
}

#[test]
fn refusals() {
    for (doc, want) in [
        // a rule the bundle does not have
        (
            "policies:\n  - { name: example-api, mode: enforce, rule_overrides: [ { rule: 999999, action: off } ] }\n",
            "not in the bundle",
        ),
        // a set matching everything
        (
            "policies:\n  - { name: example-api, mode: enforce, rule_sets: [ { match: {}, action: off } ] }\n",
            "needs sources",
        ),
        // twice the same rule
        (
            "policies:\n  - { name: example-api, mode: enforce, rule_overrides: [ { rule: 942901, action: off }, { rule: 942901, action: log } ] }\n",
            "twice",
        ),
        // an unknown action (schema)
        (
            "policies:\n  - { name: example-api, mode: enforce, rule_overrides: [ { rule: 942901, action: allow } ] }\n",
            "",
        ),
    ] {
        let err = compiled(doc)
            .err()
            .unwrap_or_else(|| panic!("accepted: {doc}"));
        assert!(err.contains(want), "{doc}: {err}");
    }
    // filters need the rules' metadata
    let doc = from_yaml(RULES).unwrap();
    let rules = rules_from_ir(&doc).unwrap();
    let pol = policies_from(&from_yaml(POLICIES).unwrap(), std::path::Path::new(".")).unwrap();
    let err = compile(
        &rules,
        &pol,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )
    .unwrap_err();
    assert!(err.contains("metadata"), "{err}");
}
