//! A transaction with a body of any format, in chunks, through rules on
//! every body target (args, files, xml, matched_vars chains, multi_match,
//! length): never panics, the verdict stays consistent.
#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use libstrata::engine::Engine;
use libstrata::rules::{
    CondDef, LAYERS, OPERATORS, RuleDef, STAGES, TRANSFORMS, TargetDef, VARS, Value, code, encode,
};
use libstrata::tx::Tx;

fn target(var: &str) -> TargetDef {
    TargetDef { var: code(VARS, var).unwrap(), key: None, exclude: vec![], count: false }
}

fn cond(vars: &[&str], tr: &[&str], op: &str, value: Value, multi: bool) -> CondDef {
    CondDef {
        targets: vars.iter().map(|v| target(v)).collect(),
        transforms: tr.iter().map(|t| code(TRANSFORMS, t).unwrap()).collect(),
        op: code(OPERATORS, op).unwrap(),
        negate: false,
        multi_match: multi,
        value,
    }
}

fn rule(id: u32, conditions: Vec<CondDef>) -> RuleDef {
    RuleDef {
        id,
        name: format!("fuzz {id}"),
        layer: code(LAYERS, "managed").unwrap(),
        stage: code(STAGES, "request_body").unwrap(),
        severity: 0,
        score: 5,
        paranoia: 1,
        any: false,
        block_alone: false,
        conditions,
    }
}

fn engine() -> Arc<Engine> {
    static E: OnceLock<Arc<Engine>> = OnceLock::new();
    E.get_or_init(|| {
        let all = ["args", "args_names", "files", "files_names", "xml", "xml_attributes", "request_body"];
        let decode = ["url_decode_uni", "html_entity_decode", "js_decode", "lowercase"];
        let rules = vec![
            rule(800901, vec![cond(&all, &decode, "detect_sqli", Value::None, true)]),
            rule(800902, vec![cond(&all, &decode, "detect_xss", Value::None, false)]),
            rule(800903, vec![
                cond(&all, &["lowercase"], "detect_xss", Value::None, false),
                cond(&["matched_vars"], &["remove_whitespace"], "detect_sqli", Value::None, true),
            ]),
            rule(800904, vec![cond(&all, &["length"], "gt", Value::Int(64), false)]),
            rule(800905, vec![cond(&all, &decode, "validate_byte_range", Value::Str(b"1-255".to_vec()), false)]),
            rule(800906, vec![cond(&all, &[], "validate_utf8_encoding", Value::None, false)]),
            rule(800907, vec![cond(&all, &[], "ip_match", Value::List(vec![b"10.0.0.0/8".to_vec(), b"192.168.0.0/16".to_vec(), b"2001:db8::/32".to_vec()]), false)]),
        ];
        let sections = encode(&rules, None);
        let refs: Vec<(u32, &[u8])> = sections.iter().map(|(k, b)| (*k, &b[..])).collect();
        let p = PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass);
        let spec = Spec { version: 1, created_at_ms: 0, flags: 0, policies: &[p], sections: &refs };
        let b = build(&spec, &[2; 32]).unwrap();
        Arc::new(Engine::map(Box::new(b), &public_key(&[2; 32])).unwrap())
    })
    .clone()
}

const TYPES: [&[u8]; 6] = [
    b"application/x-www-form-urlencoded",
    b"application/json",
    b"text/xml",
    b"multipart/form-data; boundary=B",
    b"multipart/form-data; boundary=\"--x\"",
    b"text/plain",
];

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let ct = TYPES[data[0] as usize % TYPES.len()];
    let step = 1 + data[1] as usize % 256;
    let body = &data[2..];

    let mut t = Tx::new(Some(engine()), b"web-01", 0);
    t.set_policy(b"example-api");
    t.request_line(b"POST", b"/a?q=1", b"/a", b"q=1", b"HTTP/1.1");
    t.request_headers(&[(b"Host", b"api.example.test"), (b"Content-Type", ct)]);
    let mut chunks = body.chunks(step).peekable();
    if chunks.peek().is_none() {
        t.request_body_chunk(b"", true);
    }
    while let Some(c) = chunks.next() {
        t.request_body_chunk(c, chunks.peek().is_none());
    }
    let v = t.verdict();
    assert!(v.n_rules as usize <= v.rules.len());
    assert!(v.rules[..v.n_rules as usize].iter().all(|r| *r < 800000 || (800901..=800907).contains(r)));
});
