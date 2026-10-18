use libstrata::{
    bundle,
    engine::Engine,
    rules,
    tx::Tx,
    verdict::{ACTION_BLOCK, ACTION_LOG, OK},
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};
const RULES: &str = r#"
ir_version: 1
ruleset: {name: example, version: '1'}
rules:
 - id: 700011
   name: example SQLi
   layer: managed
   stage: request_headers
   score: 100
   severity: critical
   match:
     all:
      - targets: [{var: args}]
        operator: {type: detect_sqli}
   metadata: {source: organization, license: Apache-2.0}
"#;
fn doc(ids: Value) -> Value {
    json!({"policies":[{"name":"example-api","mode":"enforce","staged_rules":ids},{"name":"example-web","mode":"enforce"}]})
}
fn build(doc: &Value) -> Result<Vec<u8>, String> {
    compile(
        &rules_from_ir(&from_yaml(RULES)?)?,
        &policies_from(doc, Path::new("."))?,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &[7; 32],
    )
}
#[test]
fn signed_staging_artifact_is_policy_scoped_and_default_absent() {
    let d = doc(json!([700011]));
    let bytes = build(&d).unwrap();
    assert_eq!(
        bytes,
        build(&serde_json::from_str(&d.to_string()).unwrap()).unwrap()
    );
    let info = bundle::verify(&bytes, &bundle::public_key(&[7; 32])).unwrap();
    assert!(!info.section(&bytes, bundle::kind::STAGING).is_empty());
    assert_eq!(bytes[bundle::HEADER_LEN + 62] & 32, 32);
    let engine = Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&bytes)),
            &bundle::public_key(&[7; 32]),
        )
        .unwrap(),
    );
    for (name, action) in [
        (b"example-api".as_slice(), ACTION_LOG),
        (b"example-web", ACTION_BLOCK),
    ] {
        let mut tx = Tx::new(Some(engine.clone()), b"example-node", 0);
        tx.set_policy(name);
        assert_eq!(
            tx.request_line(b"GET", b"/", b"/", b"q=1+OR+1%3D1", b"HTTP/1.1"),
            OK
        );
        assert_eq!(tx.request_headers(&[(b"Host", b"api.example.test")]), OK);
        assert_eq!(tx.verdict().action, action);
        assert!(tx.encode_event().is_some());
    }
    let empty = build(&doc(json!([]))).unwrap();
    let mut absent = doc(json!([]));
    absent["policies"][0]
        .as_object_mut()
        .unwrap()
        .remove("staged_rules");
    assert_eq!(empty, build(&absent).unwrap());
    assert!(
        bundle::verify(&empty, &bundle::public_key(&[7; 32]))
            .unwrap()
            .section(&empty, bundle::kind::STAGING)
            .is_empty()
    );
}
#[test]
fn staging_schema_and_compiler_reject_invalid_overlays() {
    for ids in [
        json!([0]),
        json!([-1]),
        json!([4294967296u64]),
        json!([700011, 700011]),
        json!(["700011"]),
        json!((1..=17).collect::<Vec<u32>>()),
    ] {
        assert!(policies_from(&doc(ids), Path::new(".")).is_err());
    }
    assert!(build(&doc(json!([42]))).unwrap_err().contains("staging"));
    let policies = policies_from(&doc(json!([700011])), Path::new(".")).unwrap();
    let base = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    for variant in 0..5 {
        let mut rs = base.clone();
        match variant {
            0 => rs[0].layer = rules::code(rules::LAYERS, "protocol").unwrap(),
            1 => rs[0].stage = rules::code(rules::STAGES, "response_body").unwrap(),
            2 => rs[0].score = -1,
            3 => rs[0].score = 1001,
            _ => rs.push(rs[0].clone()),
        }
        let err = compile(
            &rs,
            &policies,
            &Build {
                version: 1,
                created_at_ms: 0,
                rollback: false,
            },
            &[7; 32],
        )
        .unwrap_err();
        if variant == 4 {
            assert!(err.contains("duplicate rule id"), "{err}");
        } else {
            assert!(err.contains("staging"), "{err}");
        }
    }
}
