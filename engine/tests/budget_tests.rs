use std::sync::Arc;

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use libstrata::detectors::injection::sqli;
use libstrata::detectors::injection::xss;
use libstrata::detectors::protocol;
use libstrata::engine::Engine;
use libstrata::json;
use libstrata::multipart;
use libstrata::rules::{
    CondDef, LAYERS, OPERATORS, RuleDef, STAGES, TRANSFORMS, TargetDef, VARS, Value, code, encode,
};
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, E_BUDGET, OK};

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
        name: format!("rule {id}"),
        layer: code(LAYERS, "managed").unwrap(),
        stage: code(STAGES, "request_headers").unwrap(),
        severity: 0,
        score: 100,
        paranoia: 1,
        any: false,
        block_alone: false,
        signature: false,
        conditions,
    }
}

fn test_engine() -> Arc<Engine> {
    let rules = vec![
        rule(
            800001,
            vec![cond(
                &["remote_addr"],
                &[],
                "ip_match",
                Value::List(vec![b"192.0.2.1".to_vec()]),
                false,
            )],
        ),
        rule(
            800002,
            vec![cond(
                &["args"],
                &[],
                "rx",
                Value::Str(b"malicious_string".to_vec()),
                false,
            )],
        ),
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
    let seed = [7u8; 32];
    let bundle = build(&spec, &seed).unwrap();
    Arc::new(Engine::map(Box::new(bundle), &public_key(&seed)).unwrap())
}

#[test]
fn budget_exhaustion_sets_error_and_event_id() {
    let engine = test_engine();
    let mut tx = Tx::new(Some(engine), b"node-01", 0);
    tx.set_policy(b"example-api");
    // Set 1 microsecond budget
    tx.set_budget(1);

    assert_eq!(
        tx.request_line(b"GET", b"/test", b"/test", b"foo=bar", b"HTTP/1.1"),
        OK
    );

    // Artificially enter and exhaust budget
    assert!(tx.budget_enter().is_ok());
    std::thread::sleep(std::time::Duration::from_millis(1));
    tx.budget_exit();

    let rc = tx.request_headers(&[(b"User-Agent", b"TestAgent")]);
    assert_eq!(
        rc, E_BUDGET,
        "request_headers should return E_BUDGET on timeout"
    );

    let v = tx.verdict();
    assert_eq!(v.error, E_BUDGET);
    assert_eq!(
        v.action, ACTION_ALLOW,
        "budget exhaustion should not block in engine"
    );
    assert_eq!(v.status, 0);
    assert!(
        v.id.is_some(),
        "Event ID must be present on budget exhaustion"
    );
    let id_bytes = v.id.unwrap();
    let id_str = String::from_utf8_lossy(&id_bytes);
    assert!(
        id_str.starts_with("EVT-"),
        "Event ID must start with EVT- prefix, got {}",
        id_str
    );
}

#[test]
fn budget_sticky_error() {
    let engine = test_engine();
    let mut tx = Tx::new(Some(engine), b"node-01", 0);
    tx.set_policy(b"example-api");
    tx.set_budget(1);

    assert_eq!(
        tx.request_line(b"POST", b"/api", b"/api", b"", b"HTTP/1.1"),
        OK
    );

    assert!(tx.budget_enter().is_ok());
    std::thread::sleep(std::time::Duration::from_millis(1));
    tx.budget_exit();

    let rc = tx.request_headers(&[(b"Content-Length", b"10")]);
    assert_eq!(rc, E_BUDGET);

    // Subsequent body chunk must return sticky E_BUDGET
    let rc_chunk = tx.request_body_chunk(b"1234567890", true);
    assert_eq!(
        rc_chunk, E_BUDGET,
        "subsequent request chunk must return sticky E_BUDGET"
    );
}

#[test]
fn degraded_mode_filtering() {
    let engine = test_engine();

    // 1. In degraded mode, pure ip_match rule runs and matches client 192.0.2.1
    let mut tx = Tx::new(Some(engine.clone()), b"node-01", 0);
    tx.set_policy(b"example-api");
    tx.set_client_addr(b"192.0.2.1");
    tx.set_degraded(true);

    assert_eq!(
        tx.request_line(b"GET", b"/test", b"/test", b"", b"HTTP/1.1"),
        OK
    );
    assert_eq!(tx.request_headers(&[]), OK);
    let v = tx.verdict();
    assert_eq!(v.score, 100, "ip_match rule must execute in degraded mode");

    // 2. In degraded mode, managed rx rule (id 800002) is skipped
    let mut tx2 = Tx::new(Some(engine), b"node-01", 0);
    tx2.set_policy(b"example-api");
    tx2.set_client_addr(b"10.0.0.1");
    tx2.set_degraded(true);

    assert_eq!(
        tx2.request_line(
            b"GET",
            b"/test",
            b"/test",
            b"q=malicious_string",
            b"HTTP/1.1"
        ),
        OK
    );
    assert_eq!(tx2.request_headers(&[]), OK);
    let v2 = tx2.verdict();
    assert_eq!(
        v2.score, 0,
        "non-ip_match managed rule must be skipped in degraded mode"
    );
}

#[test]
fn single_1mb_token_windowing() {
    // 1 MB payload of repetition without delimiters
    let huge = vec![b'a'; 1024 * 1024];

    // 1. check_uri with 1 MB URI without '?'
    let mut uri_violations = Vec::new();
    protocol::check_uri(&huge, &mut |v| uri_violations.push(v.rule));

    // 2. JSON args with 1 MB unquoted string without delimiter
    let json_args = json::args(&huge, 10);
    assert!(json_args.len() <= 1);

    // 3. Multipart with 1 MB body without boundary
    let parts = multipart::parts(&huge, b"test-boundary");
    assert!(parts.is_empty());

    // 4. SQLi detect on 1 MB input
    let sqli_res = sqli::detect(&huge);
    assert!(sqli_res.is_none());

    // 5. XSS detect on 1 MB input
    let xss_res = xss::detect(&huge);
    assert!(!xss_res);
}
