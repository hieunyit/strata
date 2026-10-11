use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

/// A rule on args without a key (the usual CRS form) must not put a password in the event.
#[test]
#[allow(clippy::unnecessary_min_or_max)]
fn password_in_keyless_args_target_is_not_in_the_event() {
    let rules = r#"
ir_version: 1
ruleset: { name: leaks, version: "1" }
rules:
  - { id: 800401, name: sqli in args, layer: managed, stage: request_headers, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: args } ], operator: { type: detect_sqli } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;
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
    let e = Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&seed),
        )
        .unwrap(),
    );
    let mut t = Tx::new(Some(e), b"node", 0);
    t.set_policy(b"example-api");
    t.request_line(
        b"GET",
        b"/login?user=a&password=x' OR '1'='1",
        b"/login",
        b"user=a&password=x' OR '1'='1",
        b"HTTP/1.1",
    );
    t.request_headers(&[(b"Host", b"api.example.test")]);
    let ev = t.encode_event().expect("a blocked request has an event");
    assert!(
        !ev.windows(6).any(|w| w == b"OR '1'"),
        "password value present in the event"
    );
    assert!(
        ev.windows(14)
            .any(|w| w == b"ARGS:password"[..14.min(13)].as_ref())
            || ev.windows(13).any(|w| w == b"ARGS:password"),
        "the field names the argument"
    );
}

/// A rule with [method, args] must record ARGS:..., not REQUEST_METHOD in match details.
#[test]
fn rule_with_method_and_args_prefers_args_field() {
    let rules = r#"
ir_version: 1
ruleset: { name: test, version: "1" }
rules:
  - { id: 800501, name: method and args, layer: managed, stage: request_headers, score: 100, severity: critical,
      match: { all: [
        { targets: [ { var: method } ], operator: { type: rx, value: "^GET$" } },
        { targets: [ { var: args } ], operator: { type: detect_sqli } }
      ] },
      metadata: { source: organization, license: Apache-2.0 } }

"#;
    let seed = [6u8; 32];
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
    let e = Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&seed),
        )
        .unwrap(),
    );
    let mut t = Tx::new(Some(e), b"node", 0);
    t.set_policy(b"example-api");
    t.request_line(
        b"GET",
        b"/test?q=1' OR '1'='1",
        b"/test",
        b"q=1' OR '1'='1",
        b"HTTP/1.1",
    );
    t.request_headers(&[(b"Host", b"api.example.test")]);
    let ev = t.encode_event().expect("blocked request has an event");
    assert!(ev.windows(6).any(|w| w == b"ARGS:q"), "field is ARGS:q");
    assert!(
        !ev.windows(14).any(|w| w == b"REQUEST_METHOD"),
        "field is not REQUEST_METHOD"
    );
}
