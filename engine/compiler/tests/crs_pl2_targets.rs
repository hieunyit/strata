//! W17-S-01: the target `basename` (REQUEST_BASENAME) and the
//! transformation `escape_seq_decode` (t:escapeSeqDecode), compiled.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::OK;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [14; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: example-targets, version: "1" }
rules:
  - id: 920901
    name: basename
    layer: managed
    stage: request_headers
    match: { all: [ { targets: [{ var: basename }], operator: { type: streq, value: x.php } } ] }
    score: 100
    severity: critical
    metadata: { source: strata, license: Apache-2.0, attack_type: protocol }
  - id: 932901
    name: escape sequences
    layer: managed
    stage: request_headers
    match: { all: [ { targets: [{ var: args }], transforms: [escape_seq_decode], operator: { type: contains, value: "cat /etc" } } ] }
    score: 100
    severity: critical
    metadata: { source: strata, license: Apache-2.0, attack_type: command-injection }
"#;

fn engine() -> Arc<Engine> {
    let rules = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        Path::new("."),
    )
    .unwrap();
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

fn rules(e: &Arc<Engine>, path: &[u8], args: &[u8]) -> Vec<u32> {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-api");
    assert_eq!(t.request_line(b"GET", path, path, args, b"HTTP/1.1"), OK);
    assert_eq!(t.request_headers(&[(b"Host", b"api.example.test")]), OK);
    let v = t.verdict();
    v.rules[..v.n_rules as usize].to_vec()
}

#[test]
fn basename_is_the_last_path_segment() {
    let e = engine();
    assert_eq!(rules(&e, b"/a/b/x.php", b"q=1"), vec![920901]);
    assert_eq!(rules(&e, b"/x.php", b""), vec![920901]);
    assert!(rules(&e, b"/x.php/", b"").is_empty());
    assert!(rules(&e, b"/a/x.php.bak", b"").is_empty());
}

#[test]
fn escape_sequences_are_decoded() {
    let e = engine();
    // \x63at \057etc: "cat /etc" once decoded
    assert_eq!(rules(&e, b"/", b"q=%5Cx63at%20%5C057etc"), vec![932901]);
    assert!(rules(&e, b"/", b"q=dog%20%5C057etc").is_empty());
}
