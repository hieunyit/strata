//! W12-R-02 on compiled rules (CRS 942100, libinjection SQLi): disabling
//! the rule removes it from the verdict and from the score; the other rules
//! keep matching.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, from_yaml, load, policies_from, rules_from_ir};

const SEED: [u8; 32] = [12; 32];

fn engine() -> Arc<Engine> {
    let ex = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    let rules = rules_from_ir(&load(&ex.join("rules.yaml")).unwrap()).unwrap();
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
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

fn rules(e: &Arc<Engine>) -> (Vec<u32>, i32) {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-api");
    let args = b"id=1' OR '1'='1&x=<script>alert(1)</script>";
    t.request_line(b"GET", b"/q", b"/q", args, b"HTTP/1.1");
    t.request_headers(&[(b"Host", b"api.example.test")]);
    t.request_body_chunk(b"", true); // 942100, 941100 run at request_body
    let v = t.verdict();
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort();
    (r, v.score)
}

#[test]
fn a_disabled_compiled_rule_no_longer_matches() {
    let e = engine();
    let (all, score) = rules(&e);
    assert!(all.contains(&942100) && all.contains(&941100), "{all:?}");
    e.set_disabled_rules(&[942100]).unwrap();
    let (some, less) = rules(&e);
    assert!(
        !some.contains(&942100) && some.contains(&941100),
        "{some:?}"
    );
    assert!(less < score, "{less} < {score}");
    e.set_disabled_rules(&[]).unwrap();
    assert_eq!(rules(&e), (all, score));
}
