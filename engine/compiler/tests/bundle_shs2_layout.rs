//! Bundle SHS2 layout test (W07-R-01):
//! Validates that compiled bundles contain section HYPERSCAN with magic "SHS2",
//! valid n_patterns, cond_index, db_off % 4096 == 0, and database image loads via MappedDb::validate.

use libstrata::bundle::{kind, public_key, verify};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};
use strata_hs::MappedDb;

const SEED: [u8; 32] = [44; 32];

#[test]
fn bundle_hyperscan_shs2_layout_verified() {
    let yaml = r#"
ir_version: 1
ruleset: { name: test_shs2, version: "1" }
rules:
  - id: 920001
    name: test_shs2_rule_1
    layer: managed
    stage: request_headers
    score: 50
    severity: warning
    match:
      all:
        - targets: [ { var: uri } ]
          operator: { type: contains, value: "shs2_needle_one" }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 920002
    name: test_shs2_rule_2
    layer: managed
    stage: request_headers
    score: 50
    severity: warning
    match:
      all:
        - targets: [ { var: uri } ]
          operator: { type: contains, value: "shs2_needle_two" }
    metadata: { source: organization, license: Apache-2.0 }
"#;

    let doc = from_yaml(yaml).unwrap();
    let defs = rules_from_ir(&doc).unwrap();
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        std::path::Path::new("."),
    )
    .unwrap();

    let bundle_bytes = compile(
        &defs,
        &pol,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )
    .expect("compile bundle");
    let aligned = strata_hs::AlignedBuf::from_bytes(&bundle_bytes);

    let pubkey = public_key(&SEED);
    let info = verify(aligned.as_ref(), &pubkey).expect("verify bundle");
    let hs_sec = info.section(aligned.as_ref(), kind::HYPERSCAN);
    assert!(!hs_sec.is_empty(), "HYPERSCAN section must be present");

    // 1. Magic must be SHS2
    assert_eq!(&hs_sec[0..4], b"SHS2", "magic must be SHS2");

    // 2. n_patterns
    let n_patterns = u32::from_le_bytes(hs_sec[4..8].try_into().unwrap()) as usize;
    assert_eq!(n_patterns, 2, "must have 2 patterns in cond_index");

    // 3. Version string check
    let hs_version_bytes = &hs_sec[8..40];
    let hs_version_str = std::str::from_utf8(hs_version_bytes)
        .unwrap()
        .trim_end_matches('\0');
    assert_eq!(
        hs_version_str,
        strata_hs::version(),
        "version string must match strata_hs::version()"
    );

    // 4. db_off must be multiple of 4096
    let db_off = u32::from_le_bytes(hs_sec[40..44].try_into().unwrap()) as usize;
    assert_eq!(db_off % 4096, 0, "db_off must be a multiple of 4096");

    let db_len = u32::from_le_bytes(hs_sec[44..48].try_into().unwrap()) as usize;
    assert!(db_len > 0, "db_len must be positive");
    assert!(
        db_off + db_len <= hs_sec.len(),
        "db must fit within section"
    );

    // 5. cond_index table
    let cond_index_bytes = &hs_sec[56..56 + n_patterns * 4];
    for (idx, chunk) in cond_index_bytes.as_chunks::<4>().0.iter().enumerate() {
        let cond_id = u32::from_le_bytes(*chunk);
        assert_eq!(cond_id, idx as u32, "cond_index mapping must be ordered");
    }

    // 6. DB image loads and validates via MappedDb::validate
    let db_image = &hs_sec[db_off..db_off + db_len];
    let mapped =
        MappedDb::validate(db_image).expect("MappedDb::validate must succeed on serialized image");
    assert!(mapped.id() > 0, "MappedDb must have valid ID");
}
