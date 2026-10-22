//! 22/10/2026: detect_nosql IR -> signed bundle -> evaluator: query, form
//! and JSON carriers, benign values, opcode and cost.
use std::{collections::BTreeSet, path::Path, sync::Arc};

use libstrata::{
    bundle::public_key,
    engine::Engine,
    rules,
    tx::Tx,
    verdict::{ACTION_ALLOW, ACTION_BLOCK, OK},
};
use strata_compiler::{Build, compile, from_yaml, policies_from, rule_costs, rules_from_ir};

const SEED: [u8; 32] = [19; 32];
const IR: &str = r#"
ir_version: 1
ruleset: { name: example-nosql-test, version: "1" }
rules:
  - id: 800819
    name: Example NoSQL detector fixture
    layer: managed
    stage: request_body
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [{ var: user_input }]
          transforms: [url_decode_uni]
          operator: { type: detect_nosql }
    metadata: { source: organization, license: Apache-2.0 }
"#;

fn engine() -> Arc<Engine> {
    let defs = rules_from_ir(&from_yaml(IR).unwrap()).unwrap();
    let policies = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        Path::new("."),
    )
    .unwrap();
    let bytes = compile(
        &defs,
        &policies,
        &Build {
            version: 19,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )
    .unwrap();
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&bytes)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

fn verdict(e: &Arc<Engine>, method: &[u8], uri: &[u8], ct: &[u8], body: &[u8]) -> (u32, Vec<u32>) {
    let (path, query) = match uri.iter().position(|&c| c == b'?') {
        Some(i) => (&uri[..i], &uri[i + 1..]),
        None => (uri, &b""[..]),
    };
    let mut tx = Tx::new(Some(Arc::clone(e)), b"example-node", 0);
    tx.set_policy(b"example-api");
    assert_eq!(tx.request_line(method, uri, path, query, b"HTTP/1.1"), OK);
    assert_eq!(
        tx.request_headers(&[(b"Host", b"api.example.test"), (b"Content-Type", ct)]),
        OK
    );
    assert_eq!(tx.request_body_chunk(body, true), OK);
    let v = tx.verdict();
    (v.action, v.rules[..v.n_rules as usize].to_vec())
}

#[test]
fn nosql_injection_is_blocked_where_it_is_sent() {
    let e = engine();
    let form = b"application/x-www-form-urlencoded".as_slice();
    let json = b"application/json".as_slice();
    for (method, uri, ct, body) in [
        (
            b"GET".as_slice(),
            b"/login?user%5B%24ne%5D=x&pass%5B%24ne%5D=x".as_slice(),
            form,
            b"".as_slice(),
        ),
        (
            b"GET",
            b"/items?q=true%2C+%24where%3A+%2799+%3D%3D+88%27",
            form,
            b"",
        ),
        (
            b"POST",
            b"/login",
            json,
            br#"{"user": {"$ne": null}, "pass": {"$ne": null}}"#,
        ),
        (
            b"POST",
            b"/items",
            form,
            b"q=%3Bvar+d%3Dnew+Date()%3B+do%7Bx%3Dnew+Date()%3B%7Dwhile(x-d%3C10000)",
        ),
        (b"POST", b"/items", json, br#"{"q": "db.users.find({})"}"#),
        // percent-encoded once more inside JSON: the rule's url_decode_uni
        (
            b"POST",
            b"/items",
            json,
            br#"{"q": "admin%27%20%7C%7C%20%27a%27%3D%3D%27a"}"#,
        ),
    ] {
        let (action, rules) = verdict(&e, method, uri, ct, body);
        assert_eq!(
            action,
            ACTION_BLOCK,
            "{} {}",
            uri.escape_ascii(),
            body.escape_ascii()
        );
        assert!(rules.contains(&800819));
    }
    for (uri, body) in [
        (b"/pricing?q=save+%2410+or+more".as_slice(), b"".as_slice()),
        (b"/docs?q=%24where+is+a+keyword", b""),
        (b"/help?q=do+it+while+you+can", b""),
        (
            b"/items",
            br#"{"name": "rock & roll || jazz", "city": "Hanoi"}"#,
        ),
    ] {
        let (action, _) = verdict(
            &e,
            if body.is_empty() { b"GET" } else { b"POST" },
            uri,
            json,
            body,
        );
        assert_eq!(
            action,
            ACTION_ALLOW,
            "{} {}",
            uri.escape_ascii(),
            body.escape_ascii()
        );
    }
}

#[test]
fn opcode_and_cost() {
    assert_eq!(rules::code(rules::OPERATORS, "detect_cmdi"), Some(19));
    assert_eq!(rules::code(rules::OPERATORS, "detect_nosql"), Some(20));
    assert!(libstrata::eval::supported().0.contains(&"detect_nosql"));
    let defs = rules_from_ir(&from_yaml(IR).unwrap()).unwrap();
    // user_input: 11 targets; collections weigh 4, path and keyed headers 1
    assert!(rule_costs(&defs, &BTreeSet::new())[0].cost > 100);
}
