//! Review of W07-R-03: values reached through chains, JSON bodies and keyless
//! targets must not carry secrets into the event.
use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use std::sync::Arc;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

fn engine(rules: &str) -> Arc<Engine> {
    let seed = [5u8; 32];
    let defs = rules_from_ir(&from_yaml(rules).unwrap()).unwrap();
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        std::path::Path::new("."),
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
        &seed,
    )
    .unwrap();
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&seed),
        )
        .unwrap(),
    )
}
fn has(ev: &[u8], s: &[u8]) -> bool {
    ev.windows(s.len()).any(|w| w == s)
}

#[test]
fn matched_vars_chain_on_password() {
    let e = engine(
        r#"
ir_version: 1
ruleset: { name: p, version: "1" }
rules:
  - { id: 800501, name: chain, layer: managed, stage: request_headers, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: args } ], operator: { type: rx, value: "OR" } },
                      { targets: [ { var: matched_vars } ], operator: { type: rx, value: "1" } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#,
    );
    let mut t = Tx::new(Some(e), b"node", 0);
    t.set_policy(b"example-api");
    t.request_line(
        b"GET",
        b"/l?password=SECRETPW%20OR%201",
        b"/l",
        b"password=SECRETPW%20OR%201",
        b"HTTP/1.1",
    );
    t.request_headers(&[(b"Host", b"a")]);
    let ev = t.encode_event().expect("event");
    assert!(!has(&ev, b"SECRETPW"), "password via matched_vars in event");
}

#[test]
fn json_body_password() {
    let e = engine(
        r#"
ir_version: 1
ruleset: { name: p, version: "1" }
rules:
  - { id: 800502, name: sqli, layer: managed, stage: request_body, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: args } ], operator: { type: detect_sqli } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#,
    );
    let mut t = Tx::new(Some(e), b"node", 0);
    t.set_policy(b"example-api");
    t.request_line(b"POST", b"/l", b"/l", b"", b"HTTP/1.1");
    t.request_headers(&[(b"Host", b"a"), (b"Content-Type", b"application/json")]);
    t.request_body_chunk(br#"{"user":{"password":"SECRETPW' OR '1'='1"}}"#, true);
    let ev = t.encode_event().expect("event");
    assert!(!has(&ev, b"SECRETPW"), "json password in event");
}

#[test]
fn keyless_headers_cookie_value() {
    let e = engine(
        r#"
ir_version: 1
ruleset: { name: p, version: "1" }
rules:
  - { id: 800503, name: hdr, layer: managed, stage: request_headers, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: request_headers } ], operator: { type: contains, value: "SECRET" } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#,
    );
    let mut t = Tx::new(Some(e), b"node", 0);
    t.set_policy(b"example-api");
    t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1");
    t.request_headers(&[(b"Host", b"a"), (b"Cookie", b"sid=SECRETSESSION")]);
    let ev = t.encode_event().expect("event");
    assert!(
        !has(&ev, b"SECRETSESSION"),
        "cookie via keyless request_headers"
    );
}

#[test]
fn authorization_with_control_char() {
    let e = engine("ir_version: 1\nruleset: { name: p, version: '1' }\nrules: []\n");
    let mut t = Tx::new(Some(e), b"node", 0);
    t.set_policy(b"example-api");
    t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1");
    t.request_headers(&[
        (b"Host", b"a"),
        (b"Authorization", b"Bearer SECRETTOKEN\x01x"),
    ]);
    if let Some(ev) = t.encode_event() {
        assert!(!has(&ev, b"SECRETTOKEN"), "authorization value in event");
    }
}
