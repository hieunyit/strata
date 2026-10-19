//! W17-R-01: CMDi IR -> signed bundle -> evaluator, on fixed vectors and on
//! the repository corpus; no default rule activation.
use std::{collections::BTreeSet, path::Path, sync::Arc};

use libstrata::{
    bundle::public_key,
    engine::Engine,
    rules,
    tx::Tx,
    verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_LOG, OK},
};
use serde_json::Value;
use strata_compiler::{Build, compile, from_yaml, policies_from, rule_costs, rules_from_ir};

const SEED: [u8; 32] = [18; 32];
const IR: &str = include_str!("../examples/cmdi-test.yaml");

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
            version: 18,
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

fn send(
    engine: &Arc<Engine>,
    policy: &[u8],
    method: &[u8],
    uri: &[u8],
    headers: &[(&[u8], &[u8])],
    body: &[u8],
) -> Tx {
    let (path, query) = match uri.iter().position(|&c| c == b'?') {
        Some(i) => (&uri[..i], &uri[i + 1..]),
        None => (uri, &b""[..]),
    };
    let mut tx = Tx::new(Some(Arc::clone(engine)), b"example-node", 0);
    tx.set_policy(policy);
    assert_eq!(tx.request_line(method, uri, path, query, b"HTTP/1.1"), OK);
    assert_eq!(tx.request_headers(headers), OK);
    assert_eq!(tx.request_body_chunk(body, true), OK);
    tx
}

fn request(engine: &Arc<Engine>, policy: &[u8], query: &[u8], body: Option<&[u8]>) -> Tx {
    let mut uri = b"/ping".to_vec();
    if !query.is_empty() {
        uri.push(b'?');
        uri.extend_from_slice(query);
    }
    let method: &[u8] = if body.is_some() { b"POST" } else { b"GET" };
    send(
        engine,
        policy,
        method,
        &uri,
        &[
            (b"Host", b"api.example.test"),
            (b"Content-Type", b"application/x-www-form-urlencoded"),
        ],
        body.unwrap_or_default(),
    )
}

#[test]
fn signed_cmdi_rules_block_query_and_form_but_keep_shadow_and_benign() {
    let engine = engine(IR);
    for (query, body) in [
        (b"host=127.0.0.1%3Bcat+%2Fetc%2Fpasswd".as_slice(), None),
        (b"", Some(b"host=127.0.0.1%7C%7Cwhoami".as_slice())),
        (b"host=%24%28uname+-a%29", None),
        (b"host=x%0Aping+-c+3+192.0.2.8", None),
        // double encoded: the rule's url_decode_uni transform
        (b"host=x%253Bid", None),
        (b"host=%FFx%60id%60", None),
    ] {
        for policy in [b"example-api".as_slice(), b"example-shadow"] {
            let tx = request(&engine, policy, query, body);
            let v = tx.verdict();
            // double encoding and NUL bytes also match built-in protocol
            // rules (1000xx); no other rule exists in this bundle
            let matched = &v.rules[..v.n_rules as usize];
            assert!(
                matched.contains(&800818),
                "{} {matched:?}",
                query.escape_ascii()
            );
            assert!(matched.iter().all(|&r| r == 800818 || r / 100 == 1000));
            assert!(v.score >= 100);
            let want = if policy == b"example-api" {
                ACTION_BLOCK
            } else {
                ACTION_LOG
            };
            assert_eq!(v.action, want);
        }
    }
    for query in [
        b"host=api.example.test".as_slice(),
        b"pkg=net%2Fhttp",
        b"note=Thanks%3B+more+details+later",
        b"note=see+you%0Afind+me+at+the+desk",
        b"",
        b"host=%FFabc",
    ] {
        let tx = request(&engine, b"example-api", query, None);
        assert_eq!(
            tx.verdict().action,
            ACTION_ALLOW,
            "{}",
            query.escape_ascii()
        );
        assert_eq!(tx.verdict().n_rules, 0);
    }
    let mut query = b"host=".to_vec();
    query.extend_from_slice(&b"%24%28".repeat(2048));
    assert_eq!(
        request(&engine, b"example-api", &query, None)
            .verdict()
            .action,
        ACTION_ALLOW
    );
    query.extend_from_slice(b"id%29");
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
        "type: detect_cmdi, value: x",
        "type: detect_cmdi, value: 1",
        "type: detect_cmdi, value: []",
        "type: detect_cmdi_unknown",
    ] {
        assert!(
            rules_from_ir(&from_yaml(&IR.replace("type: detect_cmdi", op)).unwrap()).is_err(),
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
        "detect_ssti",
    ];
    for (index, name) in legacy.iter().enumerate() {
        assert_eq!(rules::code(rules::OPERATORS, name), Some(index as u8));
    }
    assert_eq!(rules::code(rules::OPERATORS, "detect_cmdi"), Some(19));
    assert!(libstrata::eval::supported().0.contains(&"detect_cmdi"));
    let defs = rules_from_ir(&from_yaml(IR).unwrap()).unwrap();
    // 1 + args (4) x (1 + one transform) x semantic weight 10
    assert_eq!(rule_costs(&defs, &BTreeSet::new())[0].cost, 81);
}

#[test]
fn negation_does_not_match_missing_target() {
    let ir = IR
        .replace("{ var: args }", "{ var: request_headers, key: X-Command }")
        .replace("type: detect_cmdi", "type: detect_cmdi, negate: true");
    let engine = engine(&ir);
    assert_eq!(
        request(&engine, b"example-api", b"", None)
            .verdict()
            .n_rules,
        0
    );
}

fn repo() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The repository corpus: no benign request may match; most command
/// injection payloads must (in a query parameter and in a form field).
#[test]
fn corpus_has_no_false_positive_and_keeps_recall() {
    let engine = engine(IR);
    let mut benign = 0;
    let mut flagged = vec![];
    for file in ["corpus/benign/synthetic.jsonl", "corpus/benign/pilot.jsonl"] {
        for line in std::fs::read_to_string(repo().join(file)).unwrap().lines() {
            let b: Value = serde_json::from_str(line).unwrap();
            let headers: Vec<(String, String)> = b["headers"]
                .as_object()
                .map(|h| {
                    h.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let hs: Vec<(&[u8], &[u8])> = headers
                .iter()
                .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
                .collect();
            let tx = send(
                &engine,
                b"example-api",
                b["method"].as_str().unwrap_or("GET").as_bytes(),
                b["uri"].as_str().unwrap_or("/").as_bytes(),
                &hs,
                b["body"].as_str().unwrap_or("").as_bytes(),
            );
            benign += 1;
            if tx.verdict().n_rules != 0 {
                flagged.push(b["id"].as_str().unwrap_or("").to_string());
            }
        }
    }
    assert_eq!(benign, 3000);
    assert!(flagged.is_empty(), "benign requests flagged: {flagged:?}");

    let (mut total, mut detected) = (0, 0);
    for line in std::fs::read_to_string(repo().join("corpus/attack/command-injection.jsonl"))
        .unwrap()
        .lines()
    {
        let p: Value = serde_json::from_str(line).unwrap();
        let q = query_escape(p["payload"].as_str().unwrap());
        for (query, body) in [
            (format!("host={q}"), None),
            (String::new(), Some(format!("host={q}"))),
        ] {
            total += 1;
            let tx = request(
                &engine,
                b"example-api",
                query.as_bytes(),
                body.as_deref().map(str::as_bytes),
            );
            if tx.verdict().action == ACTION_BLOCK {
                detected += 1;
            }
        }
    }
    eprintln!("detect_cmdi corpus recall: {detected}/{total}");
    assert_eq!(total, 958);
    // 930/958 when added (W17-R-01). The 14 payloads missed carry a literal
    // backslash-n ("\nid\n", ";id\n"), which a shell reads as the letter n,
    // or are PHP code (";system('id')"): left to the CRS 932/933 rules
    assert!(detected >= 930, "recall {detected}/{total}");
}
