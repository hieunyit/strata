//! docs/decisions/base64-args.md: an argument or cookie that looks
//! base64-encoded is inspected decoded too, under its name with `|base64`.
//! Every rule on ARGS or REQUEST_COOKIES sees it without a base64_decode
//! transform; a keyed rule and an exclusion read it under its own name; a
//! sensitive field keeps no snippet, decoded or not (review 15/10/2026).

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [47; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: base64-args, version: "1" }
rules:
  - id: 930201
    name: script tag in an argument
    layer: managed
    stage: request_headers
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args }, { var: request_cookies } ]
          transforms: [ lowercase ]
          operator: { type: contains, value: "<script" }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 930202
    name: union select in the q argument
    layer: managed
    stage: request_headers
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args, key: q } ]
          transforms: [ lowercase ]
          operator: { type: contains, value: "union select" }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 930203
    name: marker outside the excluded argument
    layer: managed
    stage: request_headers
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args, exclude: [ note ] } ]
          operator: { type: contains, value: "evil-marker" }
    metadata: { source: organization, license: Apache-2.0 }
"#;

fn engine() -> Arc<Engine> {
    let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce, max_snippet_size: 2048 }]")
            .unwrap(),
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
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

fn b64(s: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in s.chunks(3) {
        let x = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            o.push(A[(x >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    // no padding, '+' and '/' percent-encoded, as GoTestWAF's Base64Flat
    o.replace('+', "%2B").replace('/', "%2F")
}

fn tx(e: &Arc<Engine>, query: &str, cookie: Option<&str>) -> Tx {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-api");
    t.set_client_addr(b"192.0.2.10");
    let uri = format!("/search?{query}");
    t.request_line(
        b"GET",
        uri.as_bytes(),
        b"/search",
        query.as_bytes(),
        b"HTTP/1.1",
    );
    let mut h: Vec<(&[u8], &[u8])> = vec![(b"Host", b"api.example.test")];
    if let Some(c) = cookie {
        h.push((b"Cookie", c.as_bytes()));
    }
    t.request_headers(&h);
    t
}

fn rules(t: &Tx) -> Vec<u32> {
    let v = t.verdict();
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort_unstable();
    r
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn encoded_payloads_are_inspected_decoded() {
    let e = engine();
    let xss = b64(b"<script>alert(1)</script>");
    let t = tx(&e, &format!("x={xss}"), None);
    assert_eq!(rules(&t), [930201]);
    let ev = t.encode_event().unwrap();
    assert!(has(&ev, b"ARGS:x|base64"), "the field says it was decoded");
    assert!(has(&ev, b"<script>"), "the snippet is the decoded text");

    // a cookie, and binary padding after the payload
    let mut padded = b"<script>alert(1)</script>".to_vec();
    padded.extend_from_slice(&[0, 0xff, 0xfe, 1, 2, 3, 0x80, 0x81, 0x82]);
    let t = tx(
        &e,
        "a=1",
        Some(&format!(
            "pref={}",
            b64(&padded).replace("%2B", "+").replace("%2F", "/")
        )),
    );
    assert_eq!(rules(&t), [930201]);

    // the same text, not encoded, matches as before; ordinary values do not
    assert_eq!(rules(&tx(&e, "x=%3Cscript%3E", None)), [930201]);
    for q in [
        "x=password",
        "x=d41d8cd98f00b204e9800998ecf8427e",
        "x=SGVsbG8gd29ybGQ",
    ] {
        assert!(rules(&tx(&e, q, None)).is_empty(), "{q}");
    }
}

#[test]
fn keyed_rules_and_exclusions_read_the_name_it_came_with() {
    let e = engine();
    let t = tx(
        &e,
        &format!("q={}", b64(b"1 UNION SELECT password FROM users")),
        None,
    );
    assert_eq!(rules(&t), [930202]);
    let ev = t.encode_event().unwrap();
    assert!(
        has(&ev, b"ARGS:q|base64"),
        "review 15/10/2026: the suffix stays under a keyed target"
    );

    assert_eq!(
        rules(&tx(
            &e,
            &format!("other={}", b64(b"1 union select 1")),
            None
        )),
        Vec::<u32>::new()
    );
    assert!(
        rules(&tx(
            &e,
            &format!("note={}", b64(b"an evil-marker here")),
            None
        ))
        .is_empty()
    );
    assert_eq!(
        rules(&tx(
            &e,
            &format!("body={}", b64(b"an evil-marker here")),
            None
        )),
        [930203]
    );
}

/// Review 15/10/2026: a sensitive field (built-in list) keeps no snippet
/// when its value is inspected decoded either.
#[test]
fn sensitive_fields_keep_no_snippet_decoded() {
    let e = engine();
    let secret = b"<script>hunter2-secret-value</script>";
    let t = tx(&e, &format!("password={}", b64(secret)), None);
    assert_eq!(rules(&t), [930201]);
    let ev = t.encode_event().unwrap();
    assert!(has(&ev, b"ARGS:password|base64"));
    assert!(
        !has(&ev, b"hunter2-secret-value"),
        "the decoded secret left the node"
    );
}
