//! RV-S-01: rules of the signature pack (Sigma, ET Open, bot lists) never
//! block in a policy left at the default (`signatures: shadow`), even in
//! enforce: they are reported with an Event ID. `enforce` lets them block,
//! `off` skips them. The core pack (CRS, protocol, virtual patches, the
//! organization's rules) is not affected.

use std::sync::Arc;

use libstrata::bundle::{Signatures, public_key};
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_LOG, Verdict};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [9; 32];

// one rule per source, each blocks alone
const RULES: &str = r#"
ir_version: 1
ruleset: { name: signature-pack-test, version: "1" }
rules:
  - { id: 400901, name: et-open web shell, layer: managed, stage: request_headers, score: 100,
      action_mode: block_alone, severity: critical,
      match: { all: [ { targets: [ { var: path } ], operator: { type: ends_with, value: /c99.php } } ] },
      metadata: { source: et-open, license: BSD-3-Clause, upstream_id: "2000001", upstream_version: "1", author: Example ET Author } }
  - { id: 400902, name: sigma scanner, layer: managed, stage: request_headers, score: 100,
      action_mode: block_alone, severity: critical,
      match: { all: [ { targets: [ { var: path } ], operator: { type: ends_with, value: /.git/config } } ] },
      metadata: { source: sigma, license: DRL-1.1, upstream_id: example-uuid, upstream_version: r2026-09, author: Example Sigma Author } }
  - { id: 500901, name: bot list, layer: managed, stage: request_headers, score: 100,
      action_mode: block_alone, severity: notice,
      match: { all: [ { targets: [ { var: request_headers, key: User-Agent } ], operator: { type: pm, value: [examplebot] } } ] },
      metadata: { source: crawler-user-agents, license: MIT, upstream_id: examplebot, upstream_version: "1", author: Example List Author } }
  - { id: 700901, name: virtual patch, layer: managed, stage: request_headers, score: 100,
      action_mode: block_alone, severity: critical,
      match: { all: [ { targets: [ { var: path } ], operator: { type: ends_with, value: /vuln.cgi } } ] },
      metadata: { source: strata, license: Apache-2.0 } }
"#;

const POLICIES: &str = "policies:
  - { name: example-default, mode: enforce }
  - { name: example-sig-shadow, mode: enforce, signatures: shadow }
  - { name: example-sig-enforce, mode: enforce, signatures: enforce }
  - { name: example-sig-off, mode: enforce, signatures: off }
";

fn engine() -> Arc<Engine> {
    let rules = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(&from_yaml(POLICIES).unwrap(), std::path::Path::new(".")).unwrap();
    let b = compile(
        &rules,
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

fn run(e: &Arc<Engine>, policy: &str, path: &str, ua: &str) -> Verdict {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_client_addr(b"192.0.2.1");
    t.set_policy(policy.as_bytes());
    t.request_line(b"GET", path.as_bytes(), path.as_bytes(), b"", b"HTTP/1.1");
    t.request_headers(&[(b"User-Agent", ua.as_bytes())]);
    t.verdict()
}

fn id(v: &Verdict) -> String {
    String::from_utf8_lossy(&v.id.unwrap_or_default()).into_owned()
}

fn rules(v: &Verdict) -> Vec<u32> {
    v.rules[..v.n_rules as usize].to_vec()
}

#[test]
fn signature_rules_are_flagged_by_source() {
    let e = engine();
    let flagged: Vec<(u32, bool)> = (0..e.n_rules())
        .map(|i| e.rule(i).unwrap())
        .map(|r| (r.id, r.signature))
        .collect();
    assert_eq!(
        flagged,
        [
            (400901, true),
            (400902, true),
            (500901, true),
            (700901, false)
        ]
    );
    let p = |n: &[u8]| e.policy(n).unwrap().signatures;
    assert_eq!(p(b"example-default"), Signatures::Shadow);
    assert_eq!(p(b"example-sig-enforce"), Signatures::Enforce);
    assert_eq!(p(b"example-sig-off"), Signatures::Off);
}

// "Xong khi": a default enforce policy has no signature rule that blocks
#[test]
fn default_enforce_policy_never_blocks_on_signatures() {
    let e = engine();
    for policy in ["example-default", "example-sig-shadow"] {
        for (path, ua, rule) in [
            ("/c99.php", "curl", 400901),
            ("/.git/config", "curl", 400902),
            ("/", "ExampleBot/2", 500901),
        ] {
            let v = run(&e, policy, path, ua);
            assert_eq!(v.action, ACTION_LOG, "{policy} {path} {ua}");
            assert_eq!(rules(&v), [rule]);
            assert!(id(&v).starts_with("EVT-"), "{policy}: {}", id(&v));
            assert_eq!(v.score, 0, "signature scores stay out of the block score");
        }
        // the core pack still blocks
        let v = run(&e, policy, "/vuln.cgi", "curl");
        assert_eq!((v.action, v.status), (ACTION_BLOCK, 403));
        assert!(id(&v).starts_with("STR-"));
        // both: the core rule blocks, the signature one is listed too
        let v = run(&e, policy, "/vuln.cgi", "ExampleBot/2");
        assert_eq!(v.action, ACTION_BLOCK);
        let mut r = rules(&v);
        r.sort();
        assert_eq!(r, [500901, 700901]);
    }
}

#[test]
fn enforce_and_off() {
    let e = engine();
    let v = run(&e, "example-sig-enforce", "/c99.php", "curl");
    assert_eq!((v.action, v.status), (ACTION_BLOCK, 403));
    assert!(id(&v).starts_with("STR-"));

    let v = run(&e, "example-sig-off", "/c99.php", "ExampleBot/2");
    assert_eq!(v.action, ACTION_ALLOW);
    assert!(
        rules(&v).is_empty(),
        "signature rules skipped: {:?}",
        rules(&v)
    );
    let v = run(&e, "example-sig-off", "/vuln.cgi", "curl");
    assert_eq!(v.action, ACTION_BLOCK, "core pack unaffected");
}

#[test]
fn bad_signatures_value_is_refused() {
    let doc = from_yaml("policies: [{ name: a, mode: enforce, signatures: block }]").unwrap();
    assert!(policies_from(&doc, std::path::Path::new(".")).is_err());
}
