use libstrata::bundle::{self, Mode, Oversize, PolicySpec, Spec};
use libstrata::exceptions::Exception;
use libstrata::rules::{self, CondDef, RuleDef, TargetDef, Value, code};

pub fn exception(field: &str, expires: u64) -> Exception {
    Exception {
        policy_index: 0,
        rule_id: 700011,
        expires_unix_ms: expires,
        method: "POST".into(),
        host: "api.example.test".into(),
        path: "/v1/login".into(),
        field: field.into(),
    }
}
pub fn image(entries: &[Exception], flagged: bool) -> Vec<u8> {
    let rule = RuleDef {
        id: 700011,
        name: "example SQLi".into(),
        layer: code(rules::LAYERS, "managed").unwrap(),
        stage: code(rules::STAGES, "request_body").unwrap(),
        severity: 0,
        score: 100,
        paranoia: 1,
        any: false,
        block_alone: false,
        signature: false,
        exclusion: None,
        scoped: false,
        conditions: vec![CondDef {
            targets: vec![
                TargetDef {
                    var: code(rules::VARS, "args").unwrap(),
                    key: None,
                    exclude: vec![],
                    count: false,
                },
                TargetDef {
                    var: code(rules::VARS, "request_headers").unwrap(),
                    key: None,
                    exclude: vec![],
                    count: false,
                },
            ],
            transforms: vec![code(rules::TRANSFORMS, "url_decode_uni").unwrap()],
            op: code(rules::OPERATORS, "detect_sqli").unwrap(),
            negate: false,
            multi_match: true,
            value: Value::None,
        }],
    };
    let mut sections = rules::encode(&[rule], None);
    let exceptions = libstrata::exceptions::encode(entries, 1).unwrap();
    if !exceptions.is_empty() {
        sections.push((bundle::kind::EXCEPTIONS, exceptions));
    }
    let refs: Vec<_> = sections
        .iter()
        .map(|(kind, bytes)| (*kind, bytes.as_slice()))
        .collect();
    let policies = [PolicySpec {
        exceptions: flagged,
        ..PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass)
    }];
    bundle::build(
        &Spec {
            version: 1,
            created_at_ms: 0,
            flags: 0,
            policies: &policies,
            sections: &refs,
        },
        &[7; 32],
    )
    .unwrap()
}
