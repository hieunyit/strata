//! 22/10/2026: a segment of the path that looks base64-encoded is inspected
//! decoded, as an argument of the query named `REQUEST_FILENAME|base64`
//! (docs/decisions/base64-args.md §7). GoTestWAF's URLPath placeholder
//! with the Base64Flat encoder passed every payload before.
use std::sync::Arc;

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use libstrata::engine::Engine;
use libstrata::rules::{
    CondDef, LAYERS, OPERATORS, RuleDef, STAGES, TargetDef, VARS, Value, code, encode,
};
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK};

fn rule(id: u32, var: &str, key: Option<&[u8]>) -> RuleDef {
    RuleDef {
        id,
        name: format!("rule {id}"),
        layer: code(LAYERS, "managed").unwrap(),
        stage: code(STAGES, "request_body").unwrap(),
        severity: 0,
        score: 100,
        paranoia: 1,
        any: false,
        block_alone: false,
        signature: false,
        exclusion: None,
        scoped: false,
        conditions: vec![CondDef {
            targets: vec![TargetDef {
                var: code(VARS, var).unwrap(),
                key: key.map(<[u8]>::to_vec),
                exclude: vec![],
                count: false,
            }],
            transforms: vec![],
            op: code(OPERATORS, "rx").unwrap(),
            negate: false,
            multi_match: false,
            value: Value::Str(b"attack-marker".to_vec()),
        }],
    }
}

fn engine(rules: &[RuleDef]) -> Arc<Engine> {
    let encoded = encode(rules, None);
    let refs: Vec<(u32, &[u8])> = encoded.iter().map(|(k, b)| (*k, &b[..])).collect();
    let spec = Spec {
        version: 1,
        created_at_ms: 0,
        flags: 0,
        policies: &[PolicySpec::new(
            "example-api",
            Mode::Enforce,
            Oversize::Block,
        )],
        sections: &refs,
    };
    let seed = [7u8; 32];
    let bundle = build(&spec, &seed).unwrap();
    Arc::new(Engine::map(Box::new(bundle), &public_key(&seed)).unwrap())
}

fn run(e: &Arc<Engine>, path: &[u8], args: &[u8]) -> (u32, Vec<u32>) {
    let mut tx = Tx::new(Some(e.clone()), b"node", 0);
    tx.set_policy(b"example-api");
    tx.request_line(b"GET", path, path, args, b"HTTP/1.1");
    tx.request_headers(&[(b"Host", b"api.example.test")]);
    tx.request_body_chunk(b"", true);
    let v = tx.verdict();
    (v.action, v.rules[..v.n_rules as usize].to_vec())
}

/// URL-safe base64 without padding, as GoTestWAF's Base64Flat.
fn b64url(s: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = String::new();
    for c in s.chunks(3) {
        let x = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            o.push(A[(x >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    o
}

#[test]
fn encoded_path_segment_is_an_argument_of_the_query() {
    let e = engine(&[
        rule(800001, "args", None),
        rule(800002, "args_get", None),
        rule(800003, "args_post", None),
        rule(800004, "args", Some(b"REQUEST_FILENAME")),
    ]);
    let seg = b64url(b"<p>attack-marker</p>");
    for path in [format!("/{seg}"), format!("/v1/items/{seg}/details")] {
        let (action, rules) = run(&e, path.as_bytes(), b"");
        assert_eq!(action, ACTION_BLOCK, "{path}");
        assert_eq!(
            rules,
            [800001, 800002, 800004],
            "{path}: not a body argument"
        );
    }
}

#[test]
fn ordinary_paths_are_not_decoded() {
    let e = engine(&[rule(800001, "args", None)]);
    for path in [
        &b"/v1/users/4f9c2b7e1a/orders"[..],
        b"/docs/getting-started",
        b"/attack-marker-is-not-encoded",
        b"/",
        b"",
    ] {
        assert_eq!(run(&e, path, b"").0, ACTION_ALLOW, "{path:?}");
    }
    // encoded text without the marker: decoded, nothing matches
    let path = format!("/node/{}", b64url(b"User:12345678"));
    assert_eq!(run(&e, path.as_bytes(), b"").0, ACTION_ALLOW);
}

#[test]
fn path_segments_share_the_request_cap() {
    let e = engine(&[rule(800001, "args", None)]);
    // 32 encoded query values use up the share: the encoded segment past
    // it is reported (rule 100021), not dropped
    let text = b64url(b"hello world, this is text");
    let q: String = (0..32).map(|i| format!("x{i}={text}&")).collect();
    let path = format!("/{}", b64url(b"attack-marker in the path"));
    let (action, rules) = run(&e, path.as_bytes(), q.trim_end_matches('&').as_bytes());
    assert!(
        rules.contains(&libstrata::detectors::protocol::ARGS_OVER_LIMIT),
        "{rules:?}"
    );
    assert_eq!(action, ACTION_BLOCK);
}
