//! W17-S-01: exclusion rules (CRS plugins), compiled. Their conditions run
//! first at their stage; when they match, the rules or targets they name
//! are taken away for the rest of the request, only for the policies that
//! list their plugin in crs_plugins.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::OK;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [15; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: example-crs, version: "1" }
rules:
  - id: 942901
    name: args
    layer: managed
    stage: request_headers
    match: { all: [ { targets: [{ var: args }], operator: { type: contains, value: evil } } ] }
    score: 100
    severity: critical
    metadata: { source: strata, license: Apache-2.0, attack_type: sql-injection }
  - id: 942902
    name: header
    layer: managed
    stage: request_headers
    match: { all: [ { targets: [{ var: request_headers }], operator: { type: contains, value: evil } } ] }
    score: 100
    severity: critical
    metadata: { source: strata, license: Apache-2.0, attack_type: sql-injection }
  - id: 942903
    name: body args
    layer: managed
    stage: request_body
    match: { all: [ { targets: [{ var: args }], operator: { type: contains, value: worse } } ] }
    score: 100
    severity: critical
    metadata: { source: strata, license: Apache-2.0, attack_type: sql-injection }
  - id: 9500100
    name: login form
    layer: pre
    stage: request_headers
    match: { all: [ { targets: [{ var: path }], operator: { type: ends_with, value: /wp-login.php } } ] }
    score: 0
    severity: notice
    exclude:
      - { rules: [942901], target: { var: args, key: pwd } }
      - { rule_ranges: [[942903, 942903]], target: { var: args, key: pwd } }
      - { rules: [942902], target: { var: request_headers, key: X-Comment } }
    metadata: { source: strata, license: Apache-2.0, plugin: example-cms }
  - id: 9500101
    name: admin
    layer: pre
    stage: request_headers
    match: { all: [ { targets: [{ var: path }], operator: { type: streq, value: /admin } } ] }
    score: 0
    severity: notice
    exclude:
      - { rules: [942902] }
    metadata: { source: strata, license: Apache-2.0, plugin: example-cms }
  - id: 9500200
    name: other plugin
    layer: pre
    stage: request_headers
    match: { all: [ { targets: [{ var: path }], operator: { type: begins_with, value: / } } ] }
    score: 0
    severity: notice
    exclude:
      - { rules: [942901, 942902, 942903] }
    metadata: { source: strata, license: Apache-2.0, plugin: example-other }
"#;

const POLICIES: &str = "policies:
  - { name: example-cms, mode: enforce, crs_plugins: [example-cms] }
  - { name: example-none, mode: enforce }";

fn bundle(policies: &str) -> Result<Vec<u8>, String> {
    let rules = rules_from_ir(&from_yaml(RULES).unwrap()).map_err(|e| e.to_string())?;
    let pol =
        policies_from(&from_yaml(policies).unwrap(), Path::new(".")).map_err(|e| e.to_string())?;
    compile(
        &rules,
        &pol,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )
    .map_err(|e| e.to_string())
}

fn engine() -> Arc<Engine> {
    let b = bundle(POLICIES).unwrap();
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

/// Rules in the verdict, sorted.
fn run(
    e: &Arc<Engine>,
    policy: &[u8],
    path: &[u8],
    args: &[u8],
    headers: &[(&[u8], &[u8])],
    body: &[u8],
) -> Vec<u32> {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(policy);
    assert_eq!(t.request_line(b"POST", path, path, args, b"HTTP/1.1"), OK);
    let mut h: Vec<(&[u8], &[u8])> = vec![
        (b"Host", b"api.example.test"),
        (b"Content-Type", b"application/x-www-form-urlencoded"),
    ];
    h.extend_from_slice(headers);
    assert_eq!(t.request_headers(&h), OK);
    t.request_body_chunk(body, true);
    let v = t.verdict();
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort();
    r
}

#[test]
fn targets_and_rules_are_taken_away_for_the_policies_running_the_plugin() {
    let e = engine();
    let (cms, none) = (&b"example-cms"[..], &b"example-none"[..]);
    // the key the exclusion names, on its path, for its policy only
    assert!(run(&e, cms, b"/wp-login.php", b"pwd=evil", &[], b"").is_empty());
    assert_eq!(
        run(&e, none, b"/wp-login.php", b"pwd=evil", &[], b""),
        vec![942901]
    );
    assert_eq!(
        run(&e, cms, b"/wp-login.php", b"user=evil", &[], b""),
        vec![942901]
    );
    assert_eq!(
        run(&e, cms, b"/wp-login.php", b"Pwd=evil", &[], b""),
        vec![942901]
    );
    assert_eq!(run(&e, cms, b"/other", b"pwd=evil", &[], b""), vec![942901]);
    // a removal matched at request_headers holds at request_body
    assert!(run(&e, cms, b"/wp-login.php", b"", &[], b"pwd=worse").is_empty());
    assert_eq!(
        run(&e, cms, b"/wp-login.php", b"", &[], b"name=worse"),
        vec![942903]
    );
    assert_eq!(
        run(&e, none, b"/wp-login.php", b"", &[], b"pwd=worse"),
        vec![942903]
    );
    // header keys ignore ASCII case
    assert!(
        run(
            &e,
            cms,
            b"/wp-login.php",
            b"",
            &[(b"x-comment", b"evil")],
            b""
        )
        .is_empty()
    );
    assert_eq!(
        run(
            &e,
            cms,
            b"/wp-login.php",
            b"",
            &[(b"X-Other", b"evil")],
            b""
        ),
        vec![942902]
    );
    // the whole rule
    assert!(run(&e, cms, b"/admin", b"", &[(b"X-Other", b"evil")], b"").is_empty());
    assert_eq!(
        run(&e, cms, b"/admin", b"q=evil", &[(b"X-Other", b"evil")], b""),
        vec![942901]
    );
    assert_eq!(
        run(&e, none, b"/admin", b"", &[(b"X-Other", b"evil")], b""),
        vec![942902]
    );
}

#[test]
fn plugins_no_policy_runs_are_left_out() {
    let none = bundle("policies: [{ name: example-api, mode: enforce }]").unwrap();
    let cms =
        bundle("policies: [{ name: example-api, mode: enforce, crs_plugins: [example-cms] }]")
            .unwrap();
    let has = |b: &[u8], id: u32| b.windows(4).any(|w| w == id.to_le_bytes());
    assert!(!has(&none, 9_500_100) && !none.windows(4).any(|w| w == b"SXC1"));
    assert!(has(&cms, 9_500_100) && has(&cms, 9_500_101) && !has(&cms, 9_500_200));
    assert!(cms.windows(4).any(|w| w == b"SXC1"));
}

#[test]
fn bad_plugins_and_exclusions_are_refused() {
    for p in [
        "policies: [{ name: example-api, mode: enforce, crs_plugins: [no-such-plugin] }]",
        "policies: [{ name: example-api, mode: enforce, crs_plugins: [Example] }]",
        "policies: [{ name: example-api, mode: enforce, crs_plugins: [example-cms, example-cms] }]",
    ] {
        assert!(bundle(p).is_err(), "{p}");
    }
    let one = |rule: &str| {
        let doc = format!(
            "ir_version: 1\nruleset: {{ name: example-x, version: \"1\" }}\nrules:\n{rule}"
        );
        rules_from_ir(&from_yaml(&doc).unwrap())
    };
    let base = "  - id: ID
    name: x
    layer: pre
    stage: request_headers
    match: { all: [ { targets: [{ var: path }], operator: { type: streq, value: /x } } ] }
    score: SCORE
    severity: notice
    EXCLUDE
    metadata: { source: strata, license: Apache-2.0 PLUGIN }";
    let make = |id: &str, score: &str, exclude: &str, plugin: &str| {
        base.replace("ID", id)
            .replace("SCORE", score)
            .replace("EXCLUDE", exclude)
            .replace("PLUGIN", plugin)
    };
    let ok = make(
        "9500300",
        "0",
        "exclude: [{ rules: [942901] }]",
        ", plugin: example-cms",
    );
    assert!(one(&ok).is_ok(), "{:?}", one(&ok));
    for bad in [
        // a detection rule past 999999
        make("9500300", "0", "", ""),
        // an exclusion rule that scores, or without its plugin
        make(
            "9500300",
            "5",
            "exclude: [{ rules: [942901] }]",
            ", plugin: example-cms",
        ),
        make("9500300", "0", "exclude: [{ rules: [942901] }]", ""),
        // nothing to remove, a reversed range, an unknown target
        make(
            "9500300",
            "0",
            "exclude: [{ target: { var: args } }]",
            ", plugin: example-cms",
        ),
        make(
            "9500300",
            "0",
            "exclude: [{ rule_ranges: [[942999, 942100]] }]",
            ", plugin: example-cms",
        ),
        make(
            "9500300",
            "0",
            "exclude: [{ rules: [1], target: { var: tx } }]",
            ", plugin: example-cms",
        ),
    ] {
        assert!(one(&bad).is_err(), "{bad}");
    }
}
