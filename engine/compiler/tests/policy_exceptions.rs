use libstrata::{
    bundle,
    engine::Engine,
    tx::Tx,
    verdict::{ACTION_ALLOW, ACTION_BLOCK},
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const RULES: &str = r#"
ir_version: 1
ruleset: {name: example, version: '1'}
rules:
  - id: 700011
    name: example SQLi
    layer: managed
    stage: request_headers
    score: 100
    severity: critical
    match:
      all:
        - targets: [{var: args}, {var: request_headers}]
          operator: {type: detect_sqli}
    metadata: {source: organization, license: Apache-2.0}
"#;
fn entry() -> Value {
    json!({"id":"exc-0123456789abcdef0123456789abcdef", "rule_id":700011,
        "method":"GET", "host":"api.example.test", "path":"/search",
        "field":"ARGS:Name", "expires_unix_ms":4000000000000u64,
        "reason":"example application query", "source_block_id":"STR-0000-0000-0000-0001"})
}
fn doc(entry: Value) -> Value {
    json!({"policies":[{"name":"example-api","mode":"enforce", "exceptions":[entry]},
        {"name":"example-web","mode":"enforce"}]})
}
fn build(doc: &Value, rules: &str) -> Result<Vec<u8>, String> {
    compile(
        &rules_from_ir(&from_yaml(rules)?)?,
        &policies_from(doc, Path::new("."))?,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &[7; 32],
    )
}
fn action(e: &Arc<Engine>, policy: &[u8], query: &[u8]) -> u32 {
    let mut tx = Tx::new(Some(e.clone()), b"example-node", 0);
    tx.set_policy(policy);
    tx.request_line(b"GET", b"/search", b"/search", query, b"HTTP/1.1");
    tx.request_headers(&[(b"Host", b"api.example.test")]);
    tx.verdict().action
}
#[test]
fn signed_compiler_artifact_filters_only_the_selected_policy_field() {
    let d = doc(entry());
    let b = build(&d, RULES).unwrap();
    assert_eq!(
        b,
        build(&serde_json::from_str(&d.to_string()).unwrap(), RULES).unwrap()
    );
    let e = Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &bundle::public_key(&[7; 32]),
        )
        .unwrap(),
    );
    assert_eq!(action(&e, b"example-api", b"Name=1+OR+1%3D1"), ACTION_ALLOW);
    assert_eq!(
        action(&e, b"example-api", b"Name=1+OR+1%3D1&other=1+OR+1%3D1"),
        ACTION_BLOCK
    );
    assert_eq!(action(&e, b"example-web", b"Name=1+OR+1%3D1"), ACTION_BLOCK);
    let mut no = d.clone();
    no["policies"][0]
        .as_object_mut()
        .unwrap()
        .remove("exceptions");
    let no = build(&no, RULES).unwrap();
    let no = Engine::map(
        Box::new(strata_hs::AlignedBuf::from_bytes(&no)),
        &bundle::public_key(&[7; 32]),
    )
    .unwrap();
    assert!(no.exceptions(0).is_empty());
}
#[test]
fn invalid_broad_or_unknown_exceptions_are_rejected_before_signing() {
    for (key, value) in [
        ("field", json!("ARGS:*")),
        ("field", json!("REQUEST_BODY")),
        ("field", json!("REQUEST_HEADERS:X Example")),
        ("path", json!("/search*")),
        ("method", json!("get")),
        ("host", json!("*.example.test")),
        ("expires_unix_ms", json!(0)),
        ("expires_unix_ms", json!(9223372036854775808u64)),
        ("rule_id", json!(999999)),
        ("rule_id", json!(0)),
        ("rule_id", json!(4294967296u64)),
        ("id", json!("duplicate")),
        ("reason", json!("  ")),
    ] {
        let mut e = entry();
        e[key] = value;
        assert!(build(&doc(e.clone()), RULES).is_err(), "{key}={e}");
    }
    let d = doc(entry());
    assert!(build(&d, &RULES.replace("layer: managed", "layer: override")).is_err());
    let mut d = doc(entry());
    d["policies"][0]["exceptions"] = json!(vec![entry(); 129]);
    assert!(build(&d, RULES).is_err());
    d["policies"][0]["exceptions"] = json!([entry(), entry()]);
    assert!(build(&d, RULES).is_err(), "duplicate IDs");
    let mut e = entry();
    e.as_object_mut().unwrap().remove("expires_unix_ms");
    assert!(build(&doc(e), RULES).is_err());
}
