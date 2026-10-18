//! W03-R-02: docs/spec/ir.schema.json accepts every examples/ir/valid-*.json
//! and rejects every examples/ir/invalid-*.json.
//! W08-R-02: the authoring schema (rules/schema/rule.schema.json) requires
//! action_mode even though the IR keeps it optional.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    for base in [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."),
        PathBuf::from("/workspace"),
        PathBuf::from("."),
        PathBuf::from(".."),
    ] {
        if base.join("docs/spec/ir.schema.json").exists() {
            return base;
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn spec_dir() -> PathBuf {
    repo_root().join("docs/spec")
}

fn load(path: &PathBuf) -> serde_json::Value {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn examples_follow_the_ir_schema() {
    let schema = load(&spec_dir().join("ir.schema.json"));
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");

    let (mut valid, mut invalid) = (0, 0);
    let mut entries: Vec<_> = fs::read_dir(spec_dir().join("examples/ir"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();

    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let doc = load(&path);
        let errors: Vec<String> = validator.iter_errors(&doc).map(|e| e.to_string()).collect();
        if name.starts_with("valid-") {
            assert!(errors.is_empty(), "{name} should be valid: {errors:?}");
            valid += 1;
        } else if name.starts_with("invalid-") {
            assert!(!errors.is_empty(), "{name} should be rejected");
            invalid += 1;
        }
    }
    assert!(
        valid >= 2 && invalid >= 5,
        "examples missing: {valid} valid, {invalid} invalid"
    );
}

/// action_mode is optional in the IR but the authoring schema
/// (rules/schema/rule.schema.json) requires it, so the linter flags a rule
/// that omits it. The IR schema is loaded here and the authoring
/// constraint is applied the same way the file does: `allOf` the IR rule
/// definition with `required: [action_mode]`. The real file wires this
/// across two documents by $id; the Go linter maps those ids to these same
/// files (tools/strata-rules/internal/lint/lint.go).
#[test]
fn authoring_schema_requires_action_mode() {
    let ir_schema = load(&spec_dir().join("ir.schema.json"));
    // the IR alone accepts a rule with or without action_mode
    let ir_validator = jsonschema::validator_for(&ir_schema).expect("ir schema compiles");
    // a one-rule IR document, action_mode optional
    let ir_doc = |action_mode: Option<&str>| {
        serde_json::json!({
            "ir_version": 1,
            "ruleset": { "name": "x", "version": "1" },
            "rules": [ rule(action_mode) ]
        })
    };
    assert!(
        ir_validator.is_valid(&ir_doc(None)),
        "IR keeps action_mode optional"
    );
    assert!(ir_validator.is_valid(&ir_doc(Some("score"))));

    // the authoring requirement: the IR rule, plus required action_mode
    let mut authoring = serde_json::json!({
        "allOf": [ { "$ref": "#/$defs/rule" }, { "required": ["action_mode"] } ]
    });
    authoring["$defs"] = ir_schema["$defs"].clone();
    // guard against drift: the real authoring file must encode this same
    // constraint (an allOf with required: [action_mode])
    let rule_schema = load(&repo_root().join("rules/schema/rule.schema.json"));
    assert!(
        rule_schema["properties"]["rule"]["allOf"]
            .as_array()
            .is_some_and(|a| a.iter().any(|s| s["required"]
                .as_array()
                .is_some_and(|r| r.iter().any(|v| v == "action_mode")))),
        "rules/schema/rule.schema.json must require action_mode"
    );

    let validator = jsonschema::validator_for(&authoring).expect("authoring schema compiles");
    assert!(
        !validator.is_valid(&rule(None)),
        "a rule without action_mode should be rejected"
    );
    let errors: Vec<String> = validator
        .iter_errors(&rule(Some("block_alone")))
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "a rule with action_mode should pass: {errors:?}"
    );
}

fn rule(action_mode: Option<&str>) -> serde_json::Value {
    let mut r = serde_json::json!({
        "id": 100101,
        "name": "trace method",
        "layer": "protocol",
        "stage": "request_headers",
        "match": { "all": [ { "targets": [ { "var": "method" } ],
                              "operator": { "type": "rx", "value": "^TRACE$" } } ] },
        "score": 40,
        "severity": "warning",
        "metadata": { "source": "strata", "license": "Apache-2.0" }
    });
    if let Some(m) = action_mode {
        r["action_mode"] = serde_json::Value::String(m.to_string());
    }
    r
}
