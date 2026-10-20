//! W20-R-01: the semantic detectors' rules of the CRS pack match no benign
//! request of the corpus, no hand-written look-alike value and no binary
//! upload, and still find at least what they find today on the attack
//! corpus (a tuning that loses recall fails here).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, from_yaml, load, policies_from, rules_from_ir};
use strata_replay::corpus::{corpus_labelled, query_sample, upload_samples, value_samples};
use strata_replay::semantic::{self, is_benign};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const SEED: [u8; 32] = [11; 32];

// the CRS pack, paranoia level 1 enforced and 2 in shadow (the templates'
// default since W17-S-01)
fn engine() -> Arc<Engine> {
    let mut files: Vec<_> = std::fs::read_dir(repo().join("rules/crs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    files.sort();
    let mut rules = vec![];
    for f in files {
        rules.extend(rules_from_ir(&load(&f).unwrap()).unwrap());
    }
    let pol = policies_from(
        &from_yaml("policies:\n  - { name: example-api, mode: enforce, crs_paranoia: 1, crs_paranoia_shadow: 2 }\n").unwrap(),
        Path::new("."),
    )
    .unwrap();
    let b = compile(
        &rules,
        &pol,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )
    .unwrap();
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

#[test]
fn finds_the_semantic_rules() {
    let r = semantic::semantic_rules(&engine());
    assert_eq!(r.get(&942100), Some(&"sqli"));
    assert_eq!(r.get(&942101), Some(&"sqli"));
    assert_eq!(r.get(&941100), Some(&"xss"));
    assert_eq!(r.get(&941101), Some(&"xss"));
    assert!(!r.contains_key(&942120), "a regex rule is not semantic");
}

#[test]
fn no_false_positive_and_recall_kept() {
    let mut labelled = corpus_labelled(&repo().join("corpus"), &["pilot", "synthetic"]).unwrap();
    for (label, f) in [
        ("benign-sqli", "corpus/fp/semantic/sqli-benign.txt"),
        ("benign-xss", "corpus/fp/semantic/xss-benign.txt"),
    ] {
        let v = value_samples(label, &repo().join(f)).unwrap();
        assert!(v.len() >= 30, "{f}: {} values", v.len());
        labelled.extend(v);
    }
    labelled.extend(upload_samples(300));
    let r = semantic::run(engine(), &labelled, &[], None, 4).unwrap();
    assert_eq!(r.samples["benign"], 3000);
    assert_eq!(r.samples["benign-upload"], 300);
    for (name, d) in &r.detectors {
        for (label, c) in &d.labels {
            assert!(
                !is_benign(label) || c.samples == 0,
                "{name} on {label}: {c:?} {:?}",
                d.examples
            );
        }
    }
    // detection rate on the attack corpus, 20/10/2026: SQLi 357/807,
    // XSS 314/529; a point of slack for corpus changes
    let rate = |det: &str, label: &str| {
        let n = r.detectors[det].labels.get(label).map_or(0, |c| c.samples);
        100.0 * n as f64 / r.samples[label] as f64
    };
    assert!(
        rate("sqli", "sql-injection") >= 43.0,
        "{}",
        rate("sqli", "sql-injection")
    );
    assert!(rate("xss", "xss") >= 58.0, "{}", rate("xss", "xss"));
}

#[test]
fn reports_fingerprints_and_examples_of_benign_labels() {
    let e = engine();
    let labelled = vec![
        (
            "benign-test".to_string(),
            query_sample("1' or '1'='1", "allow"),
        ),
        (
            "sql-injection".to_string(),
            query_sample("1' or '1'='1", "block"),
        ),
    ];
    let r = semantic::run(e.clone(), &labelled, &[], None, 1).unwrap();
    let d = &r.detectors["sqli"];
    let c = &d.labels["benign-test"];
    assert_eq!(c.samples, 1);
    assert_eq!(c.rules.get(&942100), Some(&1));
    assert_eq!(c.fields.keys().collect::<Vec<_>>(), ["MATCHED_VARS:q"]);
    assert_eq!(c.fingerprints.len(), 1, "{c:?}");
    // examples of benign labels only
    assert_eq!(d.examples.len(), 1);
    assert_eq!(d.examples[0].label, "benign-test");
    assert_eq!(d.examples[0].value, "1' or '1'='1");
    assert!(!d.examples[0].fingerprint.is_empty());
    assert!(r.markdown("t").contains("benign-test"));

    // values are kept only when asked
    let mut t = Tx::new(Some(e), b"n", 0);
    t.set_policy(b"example-api");
    t.request_line(
        b"GET",
        b"/s?q=1'+or+'1'='1",
        b"/s",
        b"q=1'+or+'1'='1",
        b"HTTP/1.1",
    );
    t.request_headers(&[(b"Host".as_slice(), b"api.example.test".as_slice())]);
    t.request_body_chunk(b"", true);
    assert!(t.verdict().n_rules > 0);
    assert!(t.match_values().is_empty());
}
