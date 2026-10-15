//! #97: a request body that does not parse to its end (JSON damaged,
//! nested deeper than 64 or followed by more data; XML tag or comment that
//! does not end; multipart without its delimiters or with a broken part)
//! raises rule 100022, which the policy's `oversize` makes block alone or
//! recorded, with the event's inspection PARTIAL. Before, what followed
//! the damage was not inspected and nothing said so.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [49; 32];
const BODY_UNPARSED: u32 = 100_022;
const ARGS_OVER_LIMIT: u32 = 100_021;

const RULES: &str = r#"
ir_version: 1
ruleset: { name: body-unparsed, version: "1" }
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
  - { name: example-api, mode: enforce }
  - { name: example-strict, mode: enforce, oversize: block }";

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

fn rules(t: &Tx) -> Vec<u32> {
    let v = t.verdict();
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort_unstable();
    r
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

const JSON: &str = "application/json";
const XML: &str = "application/xml";
const MULTIPART: &str = "multipart/form-data; boundary=xyz";

/// #97: a payload after the place where the body stops parsing used to go
/// through uninspected and unreported. Now rule 100022 is recorded
/// (oversize pass, inspection PARTIAL) or blocks alone (oversize block).
#[test]
fn damaged_bodies_raise_100022() {
    let e = engine(POLICIES).unwrap();
    let deep = format!("{}1{}", "[".repeat(65), "]".repeat(65));
    for (ct, body) in [
        // a comma missing, then the payload
        (JSON, r#"{"a": "ok" "b": "evil-marker"}"#.to_string()),
        // 65 levels of nesting (MAX_DEPTH is 64)
        (JSON, deep.clone()),
        // trailing data after the document
        (JSON, r#"{"a": "ok"} {"b": "evil-marker"}"#.to_string()),
        // a comment that does not end hides the rest
        (XML, "<a>ok</a><!-- <b>evil-marker</b>".to_string()),
        // no close delimiter: the last part does not end
        (
            MULTIPART,
            "--xyz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nevil-marker".to_string(),
        ),
        // a part without the empty line after its headers
        (
            MULTIPART,
            "--xyz\r\nContent-Disposition: form-data; name=\"a\"\r\nevil-marker\r\n--xyz--\r\n"
                .to_string(),
        ),
    ] {
        let t = post(&e, b"example-api", "", ct, &body);
        assert_eq!(rules(&t), [BODY_UNPARSED], "{ct}: {body:.60}");
        assert_eq!(t.verdict().action, 0, "oversize pass: recorded only");
        let t = post(&e, b"example-strict", "", ct, &body);
        assert!(rules(&t).contains(&BODY_UNPARSED));
        assert_ne!(
            t.verdict().action,
            0,
            "oversize block: blocked alone ({ct})"
        );
    }
    // the event says the request was not fully inspected
    let t = post(
        &e,
        b"example-api",
        "x=evil-marker",
        JSON,
        r#"{"a": "ok" "b": 1}"#,
    );
    assert_eq!(rules(&t), [BODY_UNPARSED, 930301]);
    assert!(
        has(&t.encode_event().unwrap(), &[0xa0, 0x01, 0x02]),
        "inspection PARTIAL"
    );
}

/// Bodies that parse to their end raise nothing, a byte order mark and
/// trailing whitespace included; the argument count stays 100021's.
#[test]
fn whole_bodies_raise_nothing() {
    let e = engine(POLICIES).unwrap();
    let ok_deep = format!("{}1{}", "[".repeat(64), "]".repeat(64));
    for (ct, body) in [
        (JSON, r#"{"a": "ok", "b": [1, 2, {"c": null}]}"#.to_string()),
        (JSON, "\u{feff}{\"a\": \"ok\"}\r\n".to_string()),
        (JSON, "\"just a string\"".to_string()),
        (JSON, ok_deep),
        (
            XML,
            "<?xml version=\"1.0\"?><!-- c --><a x=\"1\"><![CDATA[t]]></a>\n".to_string(),
        ),
        (
            MULTIPART,
            "--xyz\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nok\r\n--xyz--\r\n"
                .to_string(),
        ),
    ] {
        let t = post(&e, b"example-api", "", ct, &body);
        assert!(rules(&t).is_empty(), "{ct}: {body:.60}: {:?}", rules(&t));
    }
    // more parts than MULTIPART's MAX_PARTS: the rest is left out, 100021
    let mut b = String::new();
    for i in 0..1100 {
        b.push_str(&format!(
            "--xyz\r\nContent-Disposition: form-data; name=\"p{i}\"\r\n\r\nok\r\n"
        ));
    }
    b.push_str("--xyz--\r\n");
    let r = rules(&post(&e, b"example-api", "", MULTIPART, &b));
    assert!(
        r.contains(&ARGS_OVER_LIMIT) && !r.contains(&BODY_UNPARSED),
        "{r:?}"
    );
}

/// A body the connector cut at its limit (100020) never parses to its end:
/// 100022 is not added on top.
#[test]
fn a_body_cut_at_the_limit_is_100020_only() {
    let e = engine(POLICIES).unwrap();
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-api");
    t.request_line(b"POST", b"/submit", b"/submit", b"", b"HTTP/1.1");
    t.request_headers(&[
        (b"Host", b"api.example.test"),
        (b"Content-Type", JSON.as_bytes()),
    ]);
    t.request_body_skipped(4096);
    t.request_body_chunk(br#"{"a": "ok", "b": "#, true);
    let r = rules(&t);
    assert!(r.contains(&100_020) && !r.contains(&BODY_UNPARSED), "{r:?}");
}
