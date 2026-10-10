//! W05-R-01: rule evaluation v0 (stage request_headers) through a real
//! compiled bundle with its Hyperscan section, driven like a connector.

use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, Verdict};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [6; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: eval-test, version: "1" }
rules:
  - { id: 800101, name: sqli in args, layer: managed, stage: request_headers, score: 40, severity: critical,
      match: { all: [ { targets: [ { var: args } ], transforms: [url_decode_uni, lowercase],
                        operator: { type: rx, value: 'union\s+select' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800102, name: scanner agent, layer: managed, stage: request_headers, score: 20, severity: warning,
      match: { all: [ { targets: [ { var: request_headers, key: User-Agent } ],
                        operator: { type: pm, value: [sqlmap, nikto] } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800103, name: admin outside office, layer: custom-post, stage: request_headers, score: 100, severity: error,
      match: { all: [ { targets: [ { var: path } ], operator: { type: begins_with, value: /admin } },
                      { targets: [ { var: remote_addr } ], operator: { type: ip_match, value: [10.0.0.0/8] }, } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800104, name: too many args, layer: managed, stage: request_headers, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: args, count: true } ], operator: { type: gt, value: 3 } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800105, name: debug cookie, layer: managed, stage: request_headers, score: 10, severity: notice,
      match: { all: [ { targets: [ { var: request_cookies, exclude: [session] } ],
                        operator: { type: streq, value: debug } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800106, name: php or asp, layer: managed, stage: request_headers, score: 15, severity: notice,
      match: { any: [ { targets: [ { var: path } ], operator: { type: ends_with, value: .php } },
                      { targets: [ { var: path } ], operator: { type: ends_with, value: .asp } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800107, name: js decode not implemented yet, layer: managed, stage: request_headers, score: 100, severity: error,
      match: { all: [ { targets: [ { var: args } ], transforms: [js_decode], operator: { type: contains, value: x } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800108, name: not a POST, layer: managed, stage: request_headers, score: 1, severity: notice,
      match: { all: [ { targets: [ { var: method } ], operator: { type: streq, value: POST, negate: true } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800109, name: body rule, layer: managed, stage: request_body, score: 100, severity: error,
      match: { all: [ { targets: [ { var: args } ], operator: { type: contains, value: a } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800110, name: same target and chain as 800101, layer: managed, stage: request_headers, score: 1, severity: notice,
      match: { all: [ { targets: [ { var: args } ], transforms: [url_decode_uni, lowercase],
                        operator: { type: contains, value: select } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;

fn engine() -> Arc<Engine> {
    let rules = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(
        &from_yaml("policies: []").unwrap(),
        std::path::Path::new("."),
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
    let mapped = strata_hs::AlignedBuf::from_bytes(&b);
    Arc::new(Engine::map(Box::new(mapped), &public_key(&SEED)).unwrap())
}

fn run(
    e: &Arc<Engine>,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    client: &str,
) -> Verdict {
    let (path, args) = uri.split_once('?').unwrap_or((uri, ""));
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_client_addr(client.as_bytes());
    t.request_line(
        method.as_bytes(),
        uri.as_bytes(),
        path.as_bytes(),
        args.as_bytes(),
        b"HTTP/1.1",
    );
    let h: Vec<(&[u8], &[u8])> = headers
        .iter()
        .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
        .collect();
    t.request_headers(&h);
    t.verdict()
}

fn rules(v: &Verdict) -> Vec<u32> {
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort();
    r
}

#[test]
fn clean_get_only_matches_the_negated_method_rule() {
    let e = engine();
    let v = run(
        &e,
        "GET",
        "/index.html?a=1",
        &[("Host", "api.example.test")],
        "192.0.2.1",
    );
    assert_eq!(rules(&v), [800108]);
    assert_eq!((v.score, v.action), (1, ACTION_ALLOW));
}

#[test]
fn regex_after_transformations_and_shared_scan() {
    let e = engine();
    let v = run(
        &e,
        "POST",
        "/search?q=UNION%20%20SeLeCt+1",
        &[],
        "192.0.2.1",
    );
    // 800101 and 800110 share target and chain: one scan serves both
    assert_eq!(rules(&v), [800101, 800110]);
    assert_eq!(v.score, 41);
}

#[test]
fn pm_on_one_header_is_caseless() {
    let e = engine();
    let v = run(
        &e,
        "POST",
        "/",
        &[("User-Agent", "Mozilla SQLMap/1.7"), ("X-Other", "nikto")],
        "192.0.2.1",
    );
    assert_eq!(rules(&v), [800102]);
}

#[test]
fn rule_with_an_unimplemented_operator_is_skipped() {
    // 800103 needs ip_match: skipped even though /admin matches
    let e = engine();
    let v = run(&e, "POST", "/admin/users", &[], "203.0.113.9");
    assert_eq!(rules(&v), Vec::<u32>::new());
}

#[test]
fn count_of_arguments() {
    let e = engine();
    assert_eq!(
        rules(&run(&e, "POST", "/x?a=1&b=2&c=3", &[], "")),
        Vec::<u32>::new()
    );
    assert_eq!(
        rules(&run(&e, "POST", "/x?a=1&b=2&c=3&d=4", &[], "")),
        [800104]
    );
}

#[test]
fn cookies_with_exclusion() {
    let e = engine();
    assert_eq!(
        rules(&run(&e, "POST", "/", &[("Cookie", "session=debug")], "")),
        Vec::<u32>::new()
    );
    assert_eq!(
        rules(&run(
            &e,
            "POST",
            "/",
            &[("Cookie", "session=x; mode=debug")],
            ""
        )),
        [800105]
    );
    assert_eq!(
        rules(&run(&e, "POST", "/", &[("Cookie", "mode=debugger")], "")),
        Vec::<u32>::new()
    );
}

#[test]
fn any_of_two_suffixes() {
    let e = engine();
    assert_eq!(rules(&run(&e, "POST", "/shop/item.asp", &[], "")), [800106]);
    assert_eq!(
        rules(&run(&e, "POST", "/item.php.txt", &[], "")),
        Vec::<u32>::new()
    );
}

#[test]
fn rules_of_other_stages_wait() {
    let e = engine();
    // 800109 is a request_body rule: not evaluated with the headers
    assert_eq!(
        rules(&run(&e, "POST", "/x?abc=1", &[], "")),
        Vec::<u32>::new()
    );
}

#[test]
fn scores_reach_the_block_threshold() {
    let e = engine();
    let v = run(
        &e,
        "GET",
        "/a.php?q=union+select&b=1&c=2&d=3",
        &[("User-Agent", "nikto"), ("Cookie", "mode=debug")],
        "",
    );
    assert_eq!(
        rules(&v),
        [800101, 800102, 800104, 800105, 800106, 800108, 800110]
    );
    assert_eq!(v.score, 40 + 20 + 5 + 10 + 15 + 1 + 1);
    assert_eq!(v.action, ACTION_ALLOW); // 92 < 100
    let v = run(
        &e,
        "GET",
        "/a.php?q=union+select&b=1&c=2&d=3&e=SELECT",
        &[("User-Agent", "nikto"), ("Cookie", "mode=debug")],
        "",
    );
    assert_eq!(v.score, 92);
    let v = run(
        &e,
        "GET",
        "/a.php?q=union+select&b=1&c=2&d=3",
        &[
            ("User-Agent", "nikto"),
            ("Cookie", "mode=debug"),
            ("Cookie", "x=debug"),
        ],
        "",
    );
    assert_eq!(v.score, 92); // each rule counts once
    let v = run(
        &e,
        "GET",
        "/a.php?q=union+select&b=1&c=2&d=3",
        &[("User-Agent", "nikto"), ("Cookie", "mode=debug")],
        "",
    );
    assert_ne!(v.action, ACTION_BLOCK);
}
