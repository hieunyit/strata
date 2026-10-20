//! Fuzz target for CPU budget evaluation: feeds arbitrary input chunks
//! under randomized CPU budgets (from 0 to 5000 µs) and degraded settings.
//! Invariants: never panics, terminates cleanly, and on budget exhaustion
//! correctly asserts verdict consistency (ACTION_ALLOW, status 0, EVT- id).
#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use libstrata::engine::Engine;
use libstrata::rules::{
    CondDef, LAYERS, OPERATORS, RuleDef, STAGES, TRANSFORMS, TargetDef, VARS, Value, code, encode,
};
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, E_BUDGET};

fn target(var: &str) -> TargetDef {
    TargetDef {
        var: code(VARS, var).unwrap(),
        key: None,
        exclude: vec![],
        count: false,
    }
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
        signature: false,
        exclusion: None,
        conditions,
    }
}

fn engine() -> Arc<Engine> {
    static E: OnceLock<Arc<Engine>> = OnceLock::new();
    E.get_or_init(|| {
        let all = [
            "args",
            "args_names",
            "files",
            "files_names",
            "xml",
            "xml_attributes",
            "request_body",
        ];
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
            rule(800907, vec![cond(&all, &[], "ip_match", Value::List(vec![b"10.0.0.0/8".to_vec(), b"192.168.0.0/16".to_vec()]), false)]),
        ];
        let encoded = encode(&rules, None);
        let refs: Vec<(u32, &[u8])> = encoded.iter().map(|(k, b)| (*k, &b[..])).collect();
        let spec = Spec {
            version: 1,
            created_at_ms: 0,
            flags: 0,
            policies: &[PolicySpec::new(
                "example-api",
                Mode::Enforce,
                Oversize::Pass,
            )],
            sections: &refs,
        };
        let seed = [6u8; 32];
        let bundle = build(&spec, &seed).unwrap();
        Arc::new(Engine::map(Box::new(bundle), &public_key(&seed)).unwrap())
    })
    .clone()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let budget_us = u16::from_le_bytes([data[0], data[1]]) as u64 % 5000;
    let degraded = (data[2] & 1) != 0;
    let content_type_choice = data[3] % 4;
    let rest = &data[4..];

    let mut tx = Tx::new(Some(engine()), b"fuzz-node", 0);
    tx.set_policy(b"example-api");
    tx.set_budget(budget_us);
    tx.set_degraded(degraded);

    let uri = if rest.len() > 64 { &rest[..64] } else { rest };
    let _ = tx.request_line(b"POST", uri, uri, b"", b"HTTP/1.1");

    let ct = match content_type_choice {
        0 => b"application/x-www-form-urlencoded".as_slice(),
        1 => b"application/json".as_slice(),
        2 => b"text/xml".as_slice(),
        _ => b"multipart/form-data; boundary=B".as_slice(),
    };

    let _ = tx.request_headers(&[
        (b"content-type", ct),
        (b"x-fuzz-header", rest.get(..32).unwrap_or(rest)),
    ]);

    // Feed body in chunks of 512 bytes
    for chunk in rest.chunks(512) {
        let rc = tx.request_body_chunk(chunk, false);
        if rc == E_BUDGET {
            break;
        }
    }
    let _ = tx.request_body_chunk(b"", true);

    let v = tx.verdict();
    if v.error == E_BUDGET {
        assert_eq!(v.action, ACTION_ALLOW);
        assert_eq!(v.status, 0);
        let id = v.id.unwrap();
        assert!(id.starts_with(b"EVT-"));
    }
});
