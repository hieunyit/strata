//! Audit 22/10/2026 (A-02): the 257th cookie, the 33rd base64-encoded
//! argument and the 1,025th XML attribute were dropped without a signal: a
//! payload there passed even a policy with `oversize: block`. Every cap now
//! raises rule 100021, which the policy's oversize decides.
use std::sync::Arc;

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use libstrata::detectors::protocol::ARGS_OVER_LIMIT;
use libstrata::engine::Engine;
use libstrata::rules::{
    CondDef, LAYERS, OPERATORS, RuleDef, STAGES, TargetDef, VARS, Value, code, encode,
};
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_BLOCK, ACTION_LOG};

fn rule(id: u32, stage: &str, var: &str) -> RuleDef {
    RuleDef {
        id,
        name: format!("rule {id}"),
        layer: code(LAYERS, "managed").unwrap(),
        stage: code(STAGES, stage).unwrap(),
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
                key: None,
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

fn engine() -> Arc<Engine> {
    let rules = vec![
        rule(800001, "request_headers", "request_cookies"),
        rule(800002, "request_headers", "args"),
        rule(800003, "request_body", "xml_attributes"),
    ];
    let encoded = encode(&rules, None);
    let refs: Vec<(u32, &[u8])> = encoded.iter().map(|(k, b)| (*k, &b[..])).collect();
    let spec = Spec {
        version: 1,
        created_at_ms: 0,
        flags: 0,
        policies: &[
            PolicySpec::new("example-api", Mode::Enforce, Oversize::Block),
            PolicySpec::new("example-web", Mode::Enforce, Oversize::Pass),
        ],
        sections: &refs,
    };
    let seed = [7u8; 32];
    let bundle = build(&spec, &seed).unwrap();
    Arc::new(Engine::map(Box::new(bundle), &public_key(&seed)).unwrap())
}

fn run(policy: &[u8], args: &[u8], headers: &[(&[u8], &[u8])], body: &[u8]) -> (u32, Vec<u32>) {
    let mut tx = Tx::new(Some(engine()), b"node", 0);
    tx.set_policy(policy);
    tx.request_line(b"POST", b"/p", b"/p", args, b"HTTP/1.1");
    tx.request_headers(headers);
    tx.request_body_chunk(body, true);
    let v = tx.verdict();
    (v.action, v.rules[..v.n_rules as usize].to_vec())
}

fn b64(s: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in s.chunks(3) {
        let x = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            o.push(if i <= c.len() {
                A[(x >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    o
}

const HOST: (&[u8], &[u8]) = (b"Host", b"api.example.test");

#[test]
fn cookie_past_the_cap() {
    let mut cookie: Vec<u8> = (0..256)
        .flat_map(|i| format!("c{i}=1; ").into_bytes())
        .collect();
    cookie.extend_from_slice(b"q=attack-marker");
    let h = [HOST, (&b"Cookie"[..], &cookie[..])];
    let (action, rules) = run(b"example-api", b"", &h, b"");
    assert!(rules.contains(&ARGS_OVER_LIMIT), "{rules:?}");
    assert_eq!(action, ACTION_BLOCK);
    let (action, rules) = run(b"example-web", b"", &h, b"");
    assert!(rules.contains(&ARGS_OVER_LIMIT));
    assert_ne!(action, ACTION_BLOCK, "recorded only on oversize: pass");
    // 256 cookies are all inspected: no 100021
    let (_, rules) = run(
        b"example-api",
        b"",
        &[HOST, (b"Cookie", b"a=1; q=attack-marker")],
        b"",
    );
    assert!(rules.contains(&800001) && !rules.contains(&ARGS_OVER_LIMIT));
}

#[test]
fn base64_argument_past_the_cap() {
    let text = b64(b"hello world, this is text");
    let marker = b64(b"attack-marker in the 33rd value");
    let mut q: String = (0..32).map(|i| format!("x{i}={text}&")).collect();
    q.push_str(&format!("d={marker}"));
    let (action, rules) = run(b"example-api", q.as_bytes(), &[HOST], b"");
    assert!(rules.contains(&ARGS_OVER_LIMIT), "{rules:?}");
    assert_eq!(action, ACTION_BLOCK);
}

#[test]
fn xml_attribute_past_the_cap() {
    let attrs: String = (0..1024).map(|i| format!("a{i}=\"x\" ")).collect();
    let body = format!("<r {attrs}q=\"attack-marker\"/>");
    let h = [HOST, (&b"Content-Type"[..], &b"application/xml"[..])];
    let (action, rules) = run(b"example-api", b"", &h, body.as_bytes());
    assert!(rules.contains(&ARGS_OVER_LIMIT), "{rules:?}");
    assert_eq!(action, ACTION_BLOCK);
    let (action, _) = run(b"example-web", b"", &h, body.as_bytes());
    assert!(action == ACTION_LOG || action == 0);
}
