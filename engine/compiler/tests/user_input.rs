//! 22/10/2026: IR target user_input is expanded by the compiler to every
//! place the client fills in (strata_compiler::USER_INPUT).
use libstrata::rules::{VARS, code};
use strata_compiler::{USER_INPUT, from_yaml, rules_from_ir};

fn rule(targets: &str) -> Result<Vec<libstrata::rules::RuleDef>, String> {
    rules_from_ir(&from_yaml(&format!(
        r#"
ir_version: 1
ruleset: {{ name: user_input, version: "1" }}
rules:
  - id: 930010
    name: marker anywhere the client writes
    layer: managed
    stage: request_body
    score: 5
    severity: critical
    match:
      all:
        - targets: {targets}
          operator: {{ type: contains, value: "marker" }}
    metadata: {{ source: organization, license: Apache-2.0 }}
"#
    ))?)
}

#[test]
fn user_input_expands_to_the_client_fields() {
    let r = rule("[ { var: user_input, exclude: [ csrf ] }, { var: uri_raw } ]").unwrap();
    let t = &r[0].conditions[0].targets;
    assert_eq!(t.len(), USER_INPUT.len() + 1);
    for (got, &(var, key)) in t.iter().zip(USER_INPUT) {
        assert_eq!(got.var, code(VARS, var).unwrap(), "{var}");
        assert_eq!(got.key.as_deref(), key.map(str::as_bytes));
        // the excluded name holds where a target has names, not on a keyed header
        let want: Vec<Vec<u8>> = if key.is_some() {
            vec![]
        } else {
            vec![b"csrf".to_vec()]
        };
        assert_eq!(got.exclude, want, "{var}");
    }
    assert_eq!(t[USER_INPUT.len()].var, code(VARS, "uri_raw").unwrap());
}

#[test]
fn user_input_takes_no_key_or_count() {
    assert!(rule("[ { var: user_input, key: q } ]").is_err());
    assert!(rule("[ { var: user_input, count: true } ]").is_err());
}
