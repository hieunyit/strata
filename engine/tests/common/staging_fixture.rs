use libstrata::{
    bundle::{self, Mode, Oversize, PolicySpec, Spec},
    rules::{self, CondDef, RuleDef, TargetDef, Value, code},
    staging::Entry,
};

pub fn image(ids: &[u32], flagged: bool) -> Vec<u8> {
    image_with_kind(ids, flagged, "managed", "request_headers")
}
pub fn image_with_kind(ids: &[u32], flagged: bool, layer: &str, stage: &str) -> Vec<u8> {
    let rules: Vec<_> = [
        (700011, b"first".as_slice(), 60, false),
        (700012, b"second", 60, false),
        (700013, b"alone", 0, true),
    ]
    .into_iter()
    .map(|(id, value, score, block_alone)| RuleDef {
        id,
        name: format!("example {id}"),
        layer: code(rules::LAYERS, layer).unwrap(),
        stage: code(rules::STAGES, stage).unwrap(),
        severity: 0,
        score,
        paranoia: 1,
        any: false,
        block_alone,
        signature: false,
        conditions: vec![CondDef {
            targets: vec![TargetDef {
                var: code(rules::VARS, "request_headers").unwrap(),
                key: Some([b"X-Example-".as_slice(), value].concat()),
                exclude: vec![],
                count: false,
            }],
            transforms: vec![],
            op: code(rules::OPERATORS, "eq").unwrap(),
            negate: false,
            multi_match: false,
            value: Value::Int(1),
        }],
    })
    .collect();
    let mut sections = rules::encode(&rules, None);
    let entries: Vec<_> = ids
        .iter()
        .map(|&rule_id| Entry {
            policy_index: 0,
            rule_id,
        })
        .collect();
    let staging = libstrata::staging::encode(&entries, 2).unwrap();
    if !staging.is_empty() {
        sections.push((bundle::kind::STAGING, staging));
    }
    let refs: Vec<_> = sections.iter().map(|(k, b)| (*k, b.as_slice())).collect();
    let policies = [
        PolicySpec {
            staging: flagged,
            fail_on_findings: true,
            ..PolicySpec::new("example-api", Mode::Enforce, Oversize::Block)
        },
        PolicySpec::new("example-web", Mode::Enforce, Oversize::Block),
    ];
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

// Numeric conditions keep this hand-built fixture independent of compiler-
// generated Hyperscan images. The caller chooses fixed synthetic headers.
pub fn headers(flags: &[u8]) -> Vec<(&'static [u8], &'static [u8])> {
    let mut out = vec![(b"Host".as_slice(), b"api.example.test".as_slice())];
    for (name, key) in [
        (b"first".as_slice(), b"X-Example-first".as_slice()),
        (b"second", b"X-Example-second"),
        (b"alone", b"X-Example-alone"),
    ] {
        if flags.split(|b| *b == b' ').any(|flag| flag == name) {
            out.push((key, b"1"));
        }
    }
    out
}

// Fault injection preserves the signature so loader semantic checks are tested.
pub fn patch_rule(mut bytes: Vec<u8>, index: usize, offset: usize, word: u32) -> Vec<u8> {
    let info = bundle::verify(&bytes, &bundle::public_key(&[7; 32])).unwrap();
    let at = info.sections[bundle::kind::RULES as usize].0 + 8 + index * 32 + offset;
    bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
    bytes.truncate(bytes.len() - bundle::SIG_LEN);
    bundle::sign(bytes, &[7; 32])
}
