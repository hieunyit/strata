//! Equal raw values may share scan/transform work, but target scope,
//! transform chains, match attribution and byte identity must remain distinct.
use std::path::Path;
use std::sync::Arc;

use libstrata::{bundle::public_key, engine::Engine, tx::Tx};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const RULES: &str = r#"
ir_version: 1
ruleset: { name: example, version: '1' }
rules:
 - { id: 800721, name: selected body field, layer: managed, stage: request_body, score: 100, severity: notice,
     match: { all: [{ targets: [{ var: args_post, key: json.include }], transforms: [lowercase], operator: { type: streq, value: marker } }] },
     metadata: { source: organization, license: Apache-2.0 } }
 - { id: 800722, name: encoded body field, layer: managed, stage: request_body, score: 100, severity: notice,
     match: { all: [{ targets: [{ var: args_post, key: json.encoded }], transforms: [url_decode, lowercase], operator: { type: streq, value: marker } }] },
     metadata: { source: organization, license: Apache-2.0 } }
 - { id: 800723, name: raw header, layer: managed, stage: request_body, score: 100, severity: notice,
     match: { all: [{ targets: [{ var: request_headers, key: X-Example }], operator: { type: streq, value: marker } }] },
     metadata: { source: organization, license: Apache-2.0 } }
 - { id: 800724, name: exclude one body field, layer: managed, stage: request_body, score: 100, severity: notice,
     match: { all: [{ targets: [{ var: args_post, exclude: [json.ignore] }], transforms: [lowercase], operator: { type: streq, value: evil } }] },
     metadata: { source: organization, license: Apache-2.0 } }
 - { id: 800725, name: intermediate transform match, layer: managed, stage: request_body, score: 100, severity: notice,
     match: { all: [{ targets: [{ var: args_post, key: json.multi }], transforms: [lowercase, remove_whitespace], multi_match: true, operator: { type: streq, value: 'mark er' } }] },
     metadata: { source: organization, license: Apache-2.0 } }
"#;

#[test]
fn shared_bytes_keep_field_scope_transforms_and_match_attribution() {
    let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let policies = policies_from(
        &from_yaml("policies: [{name: example-api, mode: shadow}]").unwrap(),
        Path::new("."),
    )
    .unwrap();
    let seed = [3; 32];
    let bundle = compile(
        &defs,
        &policies,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &seed,
    )
    .unwrap();
    let map = || {
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&bundle)),
            &public_key(&seed),
        )
        .unwrap()
    };
    let fast = Arc::new(map());
    let mut reference = map();
    reference.disable_prefilter();
    let reference = Arc::new(reference);
    // Repetition at distinct addresses, same raw bytes across target sets,
    // empty/NUL values, unequal lengths and transform intermediate results.
    let cases = [
        (
            "MARKER",
            "MARKER",
            "MARKER",
            "evil",
            "MARK ER",
            vec![800721, 800722, 800725],
        ),
        (
            "marker",
            "%4dARKER",
            "marker",
            "evil",
            "mark er",
            vec![800721, 800722, 800723, 800725],
        ),
        ("", "", "", "evil", "", vec![]),
        ("evil", "evil", "evil", "evil", "evil", vec![800724]),
        ("marker\0", "marker\0", "other", "evil", "mark er\0", vec![]),
        (
            "markers",
            "%4dARKERs",
            "markers",
            "evil",
            "mark ers",
            vec![],
        ),
    ];
    for (include, encoded, header, ignore, multi, want) in cases {
        let mut body =
            serde_json::json!({"include":include,"encoded":encoded,"ignore":ignore,"multi":multi});
        for i in 0..80 {
            body[format!("repeat{i}")] = serde_json::json!(include);
        }
        let body = serde_json::to_vec(&body).unwrap();
        for engine in [&reference, &fast] {
            let mut tx = Tx::new(Some(engine.clone()), b"example-node", 0);
            tx.set_policy(b"example-api");
            tx.request_line(b"POST", b"/items", b"/items", b"", b"HTTP/1.1");
            tx.request_headers(&[
                (b"Host", b"api.example.test"),
                (b"Content-Type", b"application/json"),
                (b"X-Example", header.as_bytes()),
            ]);
            tx.request_body_chunk(&body, true);
            let verdict = tx.verdict();
            let mut found = verdict.rules[..verdict.n_rules as usize].to_vec();
            found.sort_unstable();
            assert_eq!(
                found, want,
                "include={include:?} encoded={encoded:?} header={header:?}"
            );
            assert_eq!(verdict.error, 0);
            if found.contains(&800721) {
                let event = tx.encode_event().unwrap();
                assert!(
                    event
                        .windows(b"ARGS_POST:json.include".len())
                        .any(|w| w == b"ARGS_POST:json.include"),
                    "lost selected field attribution"
                );
            }
        }
    }
}
