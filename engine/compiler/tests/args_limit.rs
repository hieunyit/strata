//! #28 (option B, PO 15/10/2026): a policy inspects at most `max_args`
//! arguments (query fields, then body fields), 1024 when it sets none. A
//! request with more is not inspected silently in part any more: rule
//! 100021 blocks it alone when the policy's `oversize` is `block`, or is
//! recorded with the event's inspection PARTIAL when it is `pass`.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [48; 32];
const ARGS_OVER_LIMIT: u32 = 100_021;

const RULES: &str = r#"
ir_version: 1
ruleset: { name: args-limit, version: "1" }
rules:
  - id: 930301
    name: marker in an argument
    layer: managed
    stage: request_body
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args } ]
          operator: { type: contains, value: "evil-marker" }
    metadata: { source: organization, license: Apache-2.0 }
"#;

const POLICIES: &str = "policies:
  - { name: example-api, mode: enforce, max_args: 8 }
  - { name: example-strict, mode: enforce, oversize: block, max_args: 4 }
  - { name: example-web, mode: enforce }";

fn engine(policies: &str) -> Result<Arc<Engine>, String> {
    let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(&from_yaml(policies).unwrap(), Path::new("."))?;
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

fn post(e: &Arc<Engine>, policy: &[u8], query: &str, ct: &str, body: &str) -> Tx {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(policy);
    t.set_client_addr(b"192.0.2.10");
    let uri = if query.is_empty() {
        "/submit".to_string()
    } else {
        format!("/submit?{query}")
    };
    t.request_line(
        b"POST",
        uri.as_bytes(),
        b"/submit",
        query.as_bytes(),
        b"HTTP/1.1",
    );
    let len = body.len().to_string();
    t.request_headers(&[
        (b"Host", b"api.example.test"),
        (b"Content-Type", ct.as_bytes()),
        (b"Content-Length", len.as_bytes()),
    ]);
    t.request_body_chunk(body.as_bytes(), true);
    t
}

fn form(n: usize, marker_at: Option<usize>) -> String {
    (0..n)
        .map(|i| {
            if Some(i) == marker_at {
                format!("f{i}=evil-marker")
            } else {
                format!("f{i}=ok")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

const FORM: &str = "application/x-www-form-urlencoded";

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
fn within_the_limit_every_argument_is_inspected() {
    let e = engine(POLICIES).unwrap();
    let t = post(&e, b"example-api", "", FORM, &form(8, Some(7)));
    assert_eq!(rules(&t), [930301], "the 8th argument is inspected");
    let t = post(&e, b"example-api", "", FORM, &form(8, None));
    assert!(rules(&t).is_empty());
}

#[test]
fn over_the_limit_with_oversize_pass_is_recorded_partial() {
    let e = engine(POLICIES).unwrap();
    // 3 in the query + 6 in the body = 9 > 8; the marker is the 9th
    let t = post(&e, b"example-api", "a=1&b=2&c=3", FORM, &form(6, Some(5)));
    assert_eq!(
        rules(&t),
        [ARGS_OVER_LIMIT],
        "recorded; the 9th not inspected"
    );
    assert_eq!(t.verdict().action, 0, "oversize pass: allowed");
    // recorded only: no event for an allowed request, so look at a request
    // that also matches, with the inspection field of its event
    let t = post(&e, b"example-api", "", FORM, &form(12, Some(0)));
    assert_eq!(rules(&t), [ARGS_OVER_LIMIT, 930301]);
    let ev = t.encode_event().unwrap();
    assert!(has(&ev, &[0xa0, 0x01, 0x02]), "inspection PARTIAL");
}

#[test]
fn over_the_limit_with_oversize_block_blocks() {
    let e = engine(POLICIES).unwrap();
    let t = post(&e, b"example-strict", "", FORM, &form(5, None));
    assert_eq!(rules(&t), [ARGS_OVER_LIMIT]);
    assert_ne!(t.verdict().action, 0, "oversize block: blocked alone");
    // exactly at the limit: nothing
    let t = post(&e, b"example-strict", "", FORM, &form(4, None));
    assert!(rules(&t).is_empty());
}

/// Before #28 the 1025th argument was dropped without a sign: a payload
/// after 1024 harmless fields went through uninspected and unreported.
#[test]
fn the_default_limit_is_reported_too() {
    let e = engine(POLICIES).unwrap();
    let t = post(&e, b"example-web", "", FORM, &form(1030, Some(1029)));
    assert_eq!(rules(&t), [ARGS_OVER_LIMIT]);
    let t = post(&e, b"example-web", "", FORM, &form(1024, Some(1023)));
    assert_eq!(rules(&t), [930301], "the 1024th is inspected");
}

#[test]
fn json_and_multipart_bodies_count_their_fields() {
    let e = engine(POLICIES).unwrap();
    let json = |n: usize| {
        let items: Vec<String> = (0..n).map(|i| format!("\"k{i}\":\"ok\"")).collect();
        format!("{{{}}}", items.join(","))
    };
    let t = post(&e, b"example-api", "", "application/json", &json(8));
    assert!(rules(&t).is_empty());
    let t = post(&e, b"example-api", "", "application/json", &json(9));
    assert_eq!(rules(&t), [ARGS_OVER_LIMIT]);

    let multipart = |n: usize| {
        let mut b = String::new();
        for i in 0..n {
            b.push_str(&format!(
                "--xyz\r\nContent-Disposition: form-data; name=\"p{i}\"\r\n\r\nok\r\n"
            ));
        }
        b.push_str("--xyz--\r\n");
        b
    };
    let ct = "multipart/form-data; boundary=xyz";
    assert!(rules(&post(&e, b"example-api", "", ct, &multipart(8))).is_empty());
    assert_eq!(
        rules(&post(&e, b"example-api", "", ct, &multipart(9))),
        [ARGS_OVER_LIMIT]
    );
}

#[test]
fn bad_values_are_refused_and_values_round_up_to_four() {
    for bad in ["0", "1021", "-1", "\"many\"", "2.5"] {
        let p = format!("policies:\n  - {{ name: example-api, mode: shadow, max_args: {bad} }}");
        assert!(engine(&p).is_err(), "max_args {bad} accepted");
    }
    // 5 is kept as 8: the 6th to 8th are inspected, the 9th is over
    let e = engine("policies:\n  - { name: example-api, mode: enforce, max_args: 5 }").unwrap();
    assert_eq!(
        rules(&post(&e, b"example-api", "", FORM, &form(8, Some(7)))),
        [930301]
    );
    assert_eq!(
        rules(&post(&e, b"example-api", "", FORM, &form(9, None))),
        [ARGS_OVER_LIMIT]
    );
}
