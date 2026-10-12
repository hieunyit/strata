//! W08 review: the multipart_part_headers target (ModSecurity's
//! MULTIPART_PART_HEADERS) through a compiled bundle: each header line of
//! each part, keyed by the part name; counted; and chained to matched_vars
//! as the CRS 922110 import does.

use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [9; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: multipart-headers-test, version: "1" }
rules:
  - { id: 922120, name: content-transfer-encoding in a part, layer: managed, stage: request_body, score: 5,
      severity: critical,
      match: { all: [ { targets: [ { var: multipart_part_headers } ], transforms: [ lowercase ],
                        operator: { type: rx, value: "content-transfer-encoding:(.*)" } } ] },
      metadata: { source: strata, license: Apache-2.0 } }
  - { id: 922100, name: charset field with a charset not allowed, layer: managed, stage: request_body, score: 5,
      severity: critical,
      match: { all: [
        { targets: [ { var: multipart_part_headers, key: _charset_, count: true } ], operator: { type: gt, value: 0 } },
        { targets: [ { var: args, key: _charset_ } ], transforms: [ lowercase ],
          operator: { type: rx, value: "^(?:utf-8|iso-8859-1)$", negate: true } } ] },
      metadata: { source: strata, license: Apache-2.0 } }
  - { id: 922110, name: part content type not allowed, layer: managed, stage: request_body, score: 5,
      severity: critical,
      match: { all: [
        { targets: [ { var: multipart_part_headers } ], transforms: [ lowercase ],
          operator: { type: rx, value: "^content-type\\s*:\\s*(.*)$" } },
        { targets: [ { var: matched_vars } ],
          operator: { type: rx, value: "^content-type\\s*:\\s*(?:text/plain|image/png)$", negate: true } } ] },
      metadata: { source: strata, license: Apache-2.0 } }
"#;

fn engine() -> Arc<Engine> {
    let rules = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(
        &from_yaml("policies: []").unwrap(),
        std::path::Path::new("."),
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

fn matched(e: &Arc<Engine>, parts: &[(&str, &str, &str)]) -> Vec<u32> {
    let mut body = String::new();
    for (name, extra, content) in parts {
        body += &format!(
            "--B\r\nContent-Disposition: form-data; name=\"{name}\"\r\n{extra}\r\n{content}\r\n"
        );
    }
    body += "--B--\r\n";
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.request_line(b"POST", b"/upload", b"/upload", b"", b"HTTP/1.1");
    let len = body.len().to_string();
    t.request_headers(&[
        (b"Content-Type", b"multipart/form-data; boundary=B"),
        (b"Content-Length", len.as_bytes()),
    ]);
    t.request_body_chunk(body.as_bytes(), true);
    let v = t.verdict();
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort();
    r
}

#[test]
fn part_header_lines_are_a_target() {
    let e = engine();
    assert_eq!(
        matched(&e, &[("a", "", "x")]),
        Vec::<u32>::new(),
        "plain fields"
    );
    assert_eq!(
        matched(
            &e,
            &[("a", "Content-Transfer-Encoding: base64\r\n", "eA==")]
        ),
        [922120]
    );
    // an allowed content type passes; another is caught on its own line only
    assert_eq!(
        matched(&e, &[("f", "Content-Type: text/plain\r\n", "x")]),
        Vec::<u32>::new()
    );
    assert_eq!(
        matched(&e, &[("f", "Content-Type: application/x-evil\r\n", "x")]),
        [922110]
    );
    // the _charset_ part: keyed count, then its value
    assert_eq!(
        matched(&e, &[("_charset_", "", "UTF-8")]),
        Vec::<u32>::new()
    );
    assert_eq!(matched(&e, &[("_charset_", "", "utf-7")]), [922100]);
}
