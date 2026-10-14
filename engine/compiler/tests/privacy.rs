//! P-01 §1: a policy's privacy settings reach the events. Its field names
//! keep no snippet and their headers no value; its patterns are masked in
//! snippets and headers, after the built-in masks. And the invariant: no
//! event datagram holds a card number, a CCCD, a JWT or a value matching
//! the policy's patterns.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [46; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: privacy, version: "1" }
rules:
  - id: 930101
    name: marker in an argument
    layer: managed
    stage: request_headers
    score: 5
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args } ]
          operator: { type: contains, value: "attack" }
    metadata: { source: organization, license: Apache-2.0 }
"#;

fn engine(policies: &str) -> Result<Arc<Engine>, String> {
    engine_with_key(policies, None)
}

fn engine_with_key(policies: &str, key: Option<[u8; 32]>) -> Result<Arc<Engine>, String> {
    let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let mut pol = policies_from(&from_yaml(policies).unwrap(), Path::new("."))?;
    pol.identity_key = key;
    let b = compile(
        &defs,
        &pol,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )?;
    Engine::map(
        Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
        &public_key(&SEED),
    )
    .map(Arc::new)
    .map_err(|e| e.1.to_string())
}

const POLICY: &str = "policies:\n  - name: example-api\n    mode: enforce\n    max_snippet_size: 2048\n    privacy:\n      sensitive_fields: [ma_khach_hang, X-Customer-Id]\n      mask_patterns: ['KH[0-9]{8}', 'HD-[0-9]{6}']\n  - { name: example-web, mode: enforce }";

fn event(e: &Arc<Engine>, policy: &[u8], query: &str, headers: &[(&[u8], &[u8])]) -> Vec<u8> {
    event_as(e, policy, b"", query, headers)
}

fn event_as(
    e: &Arc<Engine>,
    policy: &[u8],
    identity: &[u8],
    query: &str,
    headers: &[(&[u8], &[u8])],
) -> Vec<u8> {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_identity(identity);
    t.set_policy(policy);
    t.set_client_addr(b"192.0.2.10");
    let uri = format!("/search?{query}");
    t.request_line(
        b"GET",
        uri.as_bytes(),
        b"/search",
        query.as_bytes(),
        b"HTTP/1.1",
    );
    t.request_headers(headers);
    t.encode_event().expect("blocked: an event")
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn settings_reach_the_events() {
    let e = engine(POLICY).unwrap();
    let headers: [(&[u8], &[u8]); 4] = [
        (b"Host", b"api.example.test"),
        (b"X-Customer-Id", b"KH00001111"),
        (b"X-Note", b"contract HD-123456 for KH87654321"),
        (b"User-Agent", b"agent KH55556666"),
    ];
    let q = "q=attack+KH12345678+card+4111111111111111+cccd+001203012345&ma_khach_hang=attack-KH11112222";
    let ev = event(&e, b"example-api", q, &headers);
    for secret in [
        &b"KH11112222"[..],
        b"KH12345678",
        b"KH00001111",
        b"KH87654321",
        b"HD-123456",
        b"KH55556666",
        b"4111111111111111",
        b"001203012345",
    ] {
        assert!(
            !has(&ev, secret),
            "{} in the event",
            String::from_utf8_lossy(secret)
        );
    }
    // still useful: the masked shape, the header names, the other text
    assert!(has(&ev, b"X-Customer-Id") && has(&ev, b"[MASKED]"));
    assert!(has(&ev, b"contract ********* for **********"));
    assert!(has(&ev, b"attack ********** card"));

    // a field of the policy's list keeps no snippet at all
    let ev2 = event(
        &e,
        b"example-api",
        "ma_khach_hang=attack-secret-value",
        &headers,
    );
    assert!(!has(&ev2, b"attack-secret-value"));
    assert!(has(&ev2, b"ARGS:ma_khach_hang"), "the field name stays");

    // another policy of the same bundle: built-in masks only
    let ev = event(&e, b"example-web", q, &headers);
    assert!(
        has(&ev, b"KH00001111"),
        "example-web has no privacy settings"
    );
    assert!(!has(&ev, b"4111111111111111"));
}

#[test]
fn bad_settings_are_refused_by_the_compiler() {
    for bad in [
        "mask_patterns: ['a*']",     // matches the empty string
        "mask_patterns: ['(a)\\1']", // backreference
        "sensitive_fields: ['has space']",
        "identity: hashed", // only plain or hmac
    ] {
        let p =
            format!("policies:\n  - name: example-api\n    mode: shadow\n    privacy: {{ {bad} }}");
        assert!(engine(&p).is_err(), "{bad} accepted");
    }
}

/// identity: hmac (P-01 §1): events carry `hmac:` and 32 hex digits, the
/// same for the same client and key, never the identity itself; another
/// key gives another value; without a key the bundle is not built.
#[test]
fn identity_hmac() {
    let p = "policies:\n  - { name: example-api, mode: enforce, privacy: { identity: hmac } }\n  - { name: example-web, mode: enforce }";
    let err = engine(p).expect_err("no key: no bundle");
    assert!(err.contains("identity key"), "{err}");
    let key = [7u8; 32];
    let e = engine_with_key(p, Some(key)).unwrap();
    let id = b"user@example.test";
    let a = event_as(&e, b"example-api", id, "q=attack", &[]);
    let b = event_as(&e, b"example-api", id, "q=attack-again", &[]);
    assert!(!has(&a, id), "the identity left the node");
    let mac = |ev: &[u8]| -> Vec<u8> {
        let at = ev
            .windows(5)
            .position(|w| w == b"hmac:")
            .expect("hmac: in the event");
        ev[at..at + 37].to_vec()
    };
    assert_eq!(mac(&a), mac(&b), "same client, same value");
    assert!(mac(&a)[5..].iter().all(|c| c.is_ascii_hexdigit()));
    let other = engine_with_key(p, Some([8u8; 32])).unwrap();
    assert_ne!(
        mac(&event_as(&other, b"example-api", id, "q=attack", &[])),
        mac(&a),
        "another key"
    );
    // the policy without the setting keeps the identity
    assert!(has(&event_as(&e, b"example-web", id, "q=attack", &[]), id));
}

/// strata-compile --identity-key: 32 raw bytes or 64 hex digits.
#[test]
fn identity_key_file_formats() {
    use strata_compiler::read_identity_key;
    let hex = "ab".repeat(32);
    assert_eq!(read_identity_key(hex.as_bytes()).unwrap(), [0xab; 32]);
    assert_eq!(
        read_identity_key(format!("{hex}\n").as_bytes()).unwrap(),
        [0xab; 32]
    );
    assert_eq!(read_identity_key(&[7u8; 32]).unwrap(), [7; 32]);
    for bad in [
        &b""[..],
        b"abcd",
        &[0u8; 32],
        "zz".repeat(32).as_bytes(),
        "00".repeat(32).as_bytes(),
    ] {
        assert!(read_identity_key(bad).is_err(), "{bad:?}");
    }
}
