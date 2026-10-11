//! W04-R-01: the ten sample rules compile into a bundle the engine maps;
//! one modified byte breaks the signature; YAML and JSON are the same model.

use std::path::{Path, PathBuf};

use libstrata::bundle::{Mode, public_key};
use libstrata::engine::Engine;
use strata_compiler::{Build, compile, from_yaml, load, policies_from, rules_from_ir};

const SEED: [u8; 32] = [5; 32];

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples")
}

fn sample_bundle() -> Vec<u8> {
    let rules = rules_from_ir(&load(&examples().join("rules.yaml")).unwrap()).unwrap();
    let pol = policies_from(
        &load(&examples().join("policies.yaml")).unwrap(),
        &examples(),
    )
    .unwrap();
    let build = Build {
        version: 7,
        created_at_ms: 1_760_000_000_000,
        rollback: false,
    };
    compile(&rules, &pol, &build, &SEED).unwrap()
}

/// Bundles are mapped at page-aligned addresses; the Hyperscan image needs
/// that alignment, so tests use an aligned copy.
fn map(b: Vec<u8>) -> Result<Engine, (i32, &'static str)> {
    Engine::map(
        Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
        &public_key(&SEED),
    )
}

#[test]
fn ten_sample_rules_load() {
    let e = map(sample_bundle()).unwrap();
    assert_eq!(e.info().version, 7);
    assert_eq!(e.n_rules(), 10);
    let ids: Vec<u32> = (0..10).map(|i| e.rule(i).unwrap().id).collect();
    assert_eq!(
        ids,
        [
            100011, 100013, 920170, 942100, 941100, 932160, 400100, 500100, 800001, 800002
        ]
    );
    let r = e.rule(8).unwrap();
    assert_eq!(
        (r.name, r.score, r.cond_count, r.any),
        (&b"Admin path outside the office network"[..], 100, 2, false)
    );
    assert!(e.rule(1).unwrap().any);

    let (html, contact) = e.block_page().unwrap();
    assert_eq!(html, std::fs::read(examples().join("block.html")).unwrap());
    assert_eq!(contact, b"Support: support@example.test");

    let p = |n: &[u8]| e.policy(n).map(|p| (p.index, p.mode));
    assert_eq!(p(b"example-api"), Some((0, Mode::Enforce)));
    assert_eq!(p(b"example-web"), Some((2, Mode::Shadow)));
}

#[test]
fn any_modified_byte_is_rejected() {
    let b = sample_bundle();
    for off in (0..b.len()).step_by(b.len() / 97 + 1) {
        let mut t = b.clone();
        t[off] ^= 0x01;
        assert!(map(t).is_err(), "byte {off} modified but accepted");
    }
}

#[test]
fn compilation_is_deterministic() {
    assert_eq!(sample_bundle(), sample_bundle());
}

#[test]
fn yaml_and_json_are_the_same_model() {
    let yaml_doc = load(&examples().join("rules.yaml")).unwrap();
    let json_path = std::env::temp_dir().join(format!("strata-rules-{}.json", std::process::id()));
    std::fs::write(&json_path, serde_json::to_vec_pretty(&yaml_doc).unwrap()).unwrap();
    let json_doc = load(&json_path).unwrap();
    std::fs::remove_file(&json_path).unwrap();
    assert_eq!(
        rules_from_ir(&yaml_doc).unwrap(),
        rules_from_ir(&json_doc).unwrap()
    );
}

fn ir(rule_yaml: &str) -> Result<Vec<libstrata::rules::RuleDef>, String> {
    let doc = format!("ir_version: 1\nruleset: {{ name: t, version: '1' }}\nrules:\n{rule_yaml}");
    rules_from_ir(&from_yaml(&doc)?)
}

const OK_RULE: &str =
    "  - { id: 800010, name: n, layer: managed, stage: request_headers, score: 1, severity: notice,
      match: { all: [ { targets: [ { var: path } ], operator: { type: contains, value: x } } ] },
      metadata: { source: organization, license: Apache-2.0 } }\n";

#[test]
fn schema_errors_are_reported() {
    assert!(ir(OK_RULE).is_ok());
    let no_license = OK_RULE.replace(", license: Apache-2.0", "");
    assert!(ir(&no_license).unwrap_err().contains("license"));
    let bad_var = OK_RULE.replace("var: path", "var: nowhere");
    assert!(
        ir(&bad_var)
            .unwrap_err()
            .contains("does not follow its schema")
    );
    let backtracking = OK_RULE.replace("type: contains", "type: pcre");
    assert!(ir(&backtracking).is_err());
}

#[test]
fn duplicate_rule_ids_are_refused() {
    let rules = ir(&format!("{OK_RULE}{OK_RULE}")).unwrap();
    let pol = policies_from(&from_yaml("policies: []").unwrap(), Path::new(".")).unwrap();
    let build = Build {
        version: 1,
        created_at_ms: 0,
        rollback: false,
    };
    assert_eq!(
        compile(&rules, &pol, &build, &SEED).unwrap_err(),
        "duplicate rule id 800010"
    );
}

#[test]
fn policies_are_checked() {
    let dup =
        from_yaml("policies: [{ name: a, mode: shadow }, { name: a, mode: enforce }]").unwrap();
    assert!(
        policies_from(&dup, Path::new("."))
            .unwrap_err()
            .contains("duplicate policy")
    );
    let bad_mode = from_yaml("policies: [{ name: a, mode: block }]").unwrap();
    assert!(policies_from(&bad_mode, Path::new(".")).is_err());
    let both = from_yaml("policies: []\nblock_page: { html: x, html_file: y }").unwrap();
    assert!(policies_from(&both, Path::new(".")).is_err());
}

#[test]
fn response_layer_flags() {
    use libstrata::bundle::Response;
    let doc = from_yaml(
        "policies:\n\
         - { name: a, mode: enforce, response: { allowed_codes_check: true, data_guard: [cccd, jwt] } }\n\
         - { name: b, mode: shadow, response: { db_errors: true } }\n\
         - { name: c, mode: shadow }",
    )
    .unwrap();
    let got: Vec<u8> = policies_from(&doc, Path::new("."))
        .unwrap()
        .policies
        .iter()
        .map(|p| p.3.0)
        .collect();
    assert_eq!(
        got,
        [
            Response::STATUS | Response::GUARD_CCCD | Response::GUARD_JWT,
            Response::DB_ERRORS,
            0
        ]
    );
    for bad in [
        "policies: [{ name: a, mode: shadow, response: { data_guard: [ssn] } }]",
        "policies: [{ name: a, mode: shadow, response: { data_guard: [jwt, jwt] } }]",
        "policies: [{ name: a, mode: shadow, response: { block: true } }]",
    ] {
        assert!(
            policies_from(&from_yaml(bad).unwrap(), Path::new(".")).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn operator_validation_in_compiler() {
    let good_byte_range = "
    - id: 800100
      name: test byte range
      layer: managed
      stage: request_headers
      match:
        all:
          - targets: [{ var: path }]
            operator: { type: validate_byte_range, value: '10,20-30,40' }
      score: 5
      severity: warning
      metadata: { source: organization, license: Apache-2.0 }
    ";
    assert!(ir(good_byte_range).is_ok());

    let bad_byte_range = "
    - id: 800101
      name: test bad byte range
      layer: managed
      stage: request_headers
      match:
        all:
          - targets: [{ var: path }]
            operator: { type: validate_byte_range, value: '30-20' }
      score: 5
      severity: warning
      metadata: { source: organization, license: Apache-2.0 }
    ";
    let err = ir(bad_byte_range).unwrap_err();
    assert!(err.contains("rule 800101: validate_byte_range: byte range inverted 30-20"));

    let bad_byte_range_type = "
    - id: 800102
      name: test bad byte range type
      layer: managed
      stage: request_headers
      match:
        all:
          - targets: [{ var: path }]
            operator: { type: validate_byte_range, value: 123 }
      score: 5
      severity: warning
      metadata: { source: organization, license: Apache-2.0 }
    ";
    let err = ir(bad_byte_range_type).unwrap_err();
    assert!(err.contains("rule 800102: validate_byte_range requires a string value"));

    let good_ip_match = "
    - id: 800103
      name: test ip match
      layer: managed
      stage: request_headers
      match:
        all:
          - targets: [{ var: remote_addr }]
            operator: { type: ip_match, value: ['10.0.0.0/8', '2001:db8::/32'] }
      score: 5
      severity: warning
      metadata: { source: organization, license: Apache-2.0 }
    ";
    assert!(ir(good_ip_match).is_ok());

    let bad_ip_match = "
    - id: 800104
      name: test bad ip match
      layer: managed
      stage: request_headers
      match:
        all:
          - targets: [{ var: remote_addr }]
            operator: { type: ip_match, value: ['10.0.0.999'] }
      score: 5
      severity: warning
      metadata: { source: organization, license: Apache-2.0 }
    ";
    let err = ir(bad_ip_match).unwrap_err();
    assert!(err.contains("rule 800104: ip_match: invalid IPv4 address"));
}
