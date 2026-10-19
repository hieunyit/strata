//! W17-R-01: IR -> signed bundle -> evaluator; no default rule activation.
use std::{collections::BTreeSet, path::Path, sync::Arc};

use libstrata::{
    bundle::public_key,
    engine::Engine,
    rules,
    tx::Tx,
    verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_LOG, OK},
};
use strata_compiler::{Build, compile, from_yaml, policies_from, rule_costs, rules_from_ir};

const SEED: [u8; 32] = [17; 32];
const IR: &str = include_str!("../examples/ssti-test.yaml");

fn engine(ir: &str) -> Arc<Engine> {
    let defs = rules_from_ir(&from_yaml(ir).unwrap()).unwrap();
    let policies = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }, { name: example-shadow, mode: shadow }]").unwrap(),
        Path::new("."),
    ).unwrap();
    let bytes = compile(
        &defs,
        &policies,
        &Build {
            version: 17,
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

fn request(engine: &Arc<Engine>, policy: &[u8], query: &[u8], body: Option<&[u8]>) -> Tx {
    let mut tx = Tx::new(Some(Arc::clone(engine)), b"example-node", 0);
    tx.set_policy(policy);
    let method: &[u8] = if body.is_some() { b"POST" } else { b"GET" };
    assert_eq!(
        tx.request_line(method, b"/render", b"/render", query, b"HTTP/1.1"),
        OK
    );
    assert_eq!(
        tx.request_headers(&[
            (b"Host", b"api.example.test"),
            (b"Content-Type", b"application/x-www-form-urlencoded")
        ]),
        OK
    );
    assert_eq!(tx.request_body_chunk(body.unwrap_or_default(), true), OK);
    tx
}

#[test]
fn signed_ssti_rules_block_query_and_form_but_keep_shadow_and_benign() {
    let engine = engine(IR);
    for (query, body) in [
        (b"tpl=%7B%7B7*7%7D%7D".as_slice(), None),
        (b"", Some(b"tpl=%24%7B7*7%7D".as_slice())),
        (b"tpl=%3C%25%3D7*7%25%3E", None),
        (b"tpl=%FF%7B%7B__class__%7D%7D%00", None),
    ] {
        for policy in [b"example-api".as_slice(), b"example-shadow"] {
            let tx = request(&engine, policy, query, body);
            let v = tx.verdict();
            assert_eq!(v.rules[..v.n_rules as usize], [800817]);
            assert_eq!(v.score, 100);
            assert_eq!(
                v.action,
                if policy == b"example-api" {
                    ACTION_BLOCK
                } else {
                    ACTION_LOG
                }
            );
        }
    }
    for query in [
        b"tpl=Hello+%7B%7Bname%7D%7D".as_slice(),
        b"tpl=hello",
        b"",
        b"tpl=%FF%00",
    ] {
        let tx = request(&engine, b"example-api", query, None);
        assert_eq!(tx.verdict().action, ACTION_ALLOW);
        assert_eq!(tx.verdict().n_rules, 0);
    }
    let mut query = b"tpl=".to_vec();
    query.extend_from_slice(&b"${".repeat(4096));
    assert_eq!(
        request(&engine, b"example-api", &query, None)
            .verdict()
            .action,
        ACTION_ALLOW
    );
    query.extend_from_slice(b"${7*7}");
    assert_eq!(
        request(&engine, b"example-api", &query, None)
            .verdict()
            .action,
        ACTION_BLOCK
    );
}

#[test]
fn schema_rejects_values_and_unknown_operator() {
    for op in [
        "type: detect_ssti, value: x",
        "type: detect_ssti, value: 1",
        "type: detect_ssti, value: []",
        "type: detect_ssti_unknown",
    ] {
        assert!(
            rules_from_ir(&from_yaml(&IR.replace("type: detect_ssti", op)).unwrap()).is_err(),
            "{op}"
        );
    }
    assert!(rules_from_ir(&from_yaml(IR).unwrap()).is_ok());
}

#[test]
fn old_opcodes_are_stable_and_semantic_cost_is_charged() {
    let legacy = [
        "rx",
        "pm",
        "contains",
        "begins_with",
        "ends_with",
        "streq",
        "eq",
        "ne",
        "gt",
        "ge",
        "lt",
        "le",
        "detect_sqli",
        "detect_xss",
        "validate_byte_range",
        "validate_url_encoding",
        "validate_utf8_encoding",
        "ip_match",
    ];
    for (index, name) in legacy.iter().enumerate() {
        assert_eq!(rules::code(rules::OPERATORS, name), Some(index as u8));
    }
    assert!(libstrata::eval::supported().0.contains(&"detect_ssti"));
    let defs = rules_from_ir(&from_yaml(IR).unwrap()).unwrap();
    assert_eq!(rule_costs(&defs, &BTreeSet::new())[0].cost, 41);
}

#[test]
fn negation_does_not_match_missing_target() {
    let ir = IR
        .replace("{ var: args }", "{ var: request_headers, key: X-Template }")
        .replace("type: detect_ssti", "type: detect_ssti, negate: true");
    let engine = engine(&ir);
    assert_eq!(
        request(&engine, b"example-api", b"", None)
            .verdict()
            .n_rules,
        0
    );
}
