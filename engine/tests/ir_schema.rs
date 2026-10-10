//! W03-R-02: docs/spec/ir.schema.json accepts every examples/ir/valid-*.json
//! and rejects every examples/ir/invalid-*.json.

use std::fs;
use std::path::PathBuf;

fn spec_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/spec")
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
