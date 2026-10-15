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
  - { id: 800111, name: sqli in a header, layer: managed, stage: request_headers, score: 50, severity: critical,
      match: { all: [ { targets: [ { var: request_headers, key: X-Probe } ], transforms: [url_decode_uni],
                        operator: { type: detect_sqli } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800112, name: xss in a header, layer: managed, stage: request_headers, score: 50, severity: critical,
      match: { all: [ { targets: [ { var: request_headers, key: X-Probe } ], transforms: [url_decode_uni],
                        operator: { type: detect_xss } } ] },
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

#[test]
fn libinjection_operators_after_transformations() {
    let e = engine();
    let probe = |v: &str| rules(&run(&e, "POST", "/", &[("X-Probe", v)], ""));
    assert_eq!(probe("1%27%20OR%20%271%27%3D%271"), [800111]);
    assert_eq!(probe("%3Cscript%3Ealert(1)%3C/script%3E"), [800112]);
    assert_eq!(probe("O%27Reilly%20%26%20Sons"), Vec::<u32>::new());
}

// Stage request_body: run once the body is complete, over the query, the
// form fields of the body and the raw body. A GET has an empty body and
// its query is checked then too.
mod body_stage {
    use super::*;

    const BODY_RULES: &str = r#"
ir_version: 1
ruleset: { name: body-test, version: "1" }
rules:
  - { id: 800201, name: sqli in args, layer: managed, stage: request_body, score: 5, severity: critical,
      match: { all: [ { targets: [ { var: args } ], transforms: [url_decode_uni], operator: { type: detect_sqli } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800202, name: marker in a body field, layer: managed, stage: request_body, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: args_post } ], operator: { type: streq, value: body-only } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800203, name: marker in the query, layer: managed, stage: request_body, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: args_get } ], operator: { type: streq, value: body-only } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800204, name: raw body, layer: managed, stage: request_body, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: request_body } ], operator: { type: contains, value: '"role":"admin"' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800205, name: user agent at the body stage, layer: managed, stage: request_body, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: request_headers, key: User-Agent } ], operator: { type: contains, value: probe } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;

    fn engine() -> Arc<Engine> {
        let rules = rules_from_ir(&from_yaml(BODY_RULES).unwrap()).unwrap();
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
        Arc::new(
            Engine::map(
                Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
                &public_key(&SEED),
            )
            .unwrap(),
        )
    }

    /// Request line and headers, then the body in `chunks` (none: an empty
    /// final chunk, as the connector sends for a GET).
    fn send(method: &str, uri: &str, headers: &[(&str, &str)], chunks: &[&str]) -> Verdict {
        let (path, args) = uri.split_once('?').unwrap_or((uri, ""));
        let mut t = Tx::new(Some(engine()), b"node", 0);
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
        let v = t.verdict();
        assert_eq!(
            rules(&v),
            Vec::<u32>::new(),
            "body rules ran with the headers"
        );
        assert!(v.need_body);
        if chunks.is_empty() {
            t.request_body_chunk(b"", true);
        }
        for (i, c) in chunks.iter().enumerate() {
            t.request_body_chunk(c.as_bytes(), i + 1 == chunks.len());
        }
        t.verdict()
    }

    const FORM: (&str, &str) = (
        "Content-Type",
        "application/x-www-form-urlencoded; charset=utf-8",
    );

    #[test]
    fn query_of_a_get_is_checked_at_the_body_stage() {
        let v = send("GET", "/users?id=1%27%20OR%201%3D1--", &[], &[]);
        assert_eq!(rules(&v), [800201]);
    }

    #[test]
    fn form_fields_split_across_chunks() {
        let v = send(
            "POST",
            "/login",
            &[FORM],
            &["user=x&pass=1' OR '1", "'='1&note=body-only"],
        );
        assert_eq!(rules(&v), [800201, 800202]);
    }

    #[test]
    fn args_get_and_args_post_are_kept_apart() {
        let v = send("POST", "/q?m=body-only", &[FORM], &["a=1"]);
        assert_eq!(rules(&v), [800203]);
        let v = send("POST", "/q?a=1", &[FORM], &["m=body-only"]);
        assert_eq!(rules(&v), [800202]);
    }

    #[test]
    fn a_json_body_has_no_form_fields_but_a_raw_body() {
        let v = send(
            "POST",
            "/v1/users",
            &[("Content-Type", "application/json")],
            &[r#"{"name":"x","role":"admin"}"#],
        );
        assert_eq!(rules(&v), [800204]);
        let v = send(
            "POST",
            "/v1/users",
            &[("Content-Type", "application/json")],
            &["note=body-only"],
        );
        assert_eq!(
            rules(&v),
            Vec::<u32>::new(),
            "a non-form body was parsed as form fields"
        );
    }

    #[test]
    fn headers_are_kept_for_the_body_stage() {
        let v = send("POST", "/", &[("User-Agent", "probe/1")], &["x"]);
        assert_eq!(rules(&v), [800205]);
    }

    /// Random requests driven like a connector (seeded, so failures
    /// reproduce): no panic, only known rules, and the verdict is final
    /// after the last chunk.
    #[test]
    fn random_requests_never_panic() {
        let e = engine();
        let mut x: u64 = 0x5eed_2026_1011;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let alphabet: &[u8] = b"aA0=&%'\"<>/?;:+ -_.~%2e%27%00\r\n\x80\xff";
        let bytes = |n: usize, next: &mut dyn FnMut() -> u64| -> Vec<u8> {
            (0..n)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect()
        };
        for _ in 0..20_000 {
            let uri_len = (next() % 200) as usize;
            let raw = [b"/".to_vec(), bytes(uri_len, &mut next)].concat();
            let split = raw.iter().position(|&c| c == b'?');
            let (path, args) = match split {
                Some(q) => (&raw[..q], &raw[q + 1..]),
                None => (&raw[..], &b""[..]),
            };
            let mut t = Tx::new(Some(e.clone()), b"node", 0);
            t.request_line(b"POST", &raw, path, args, b"HTTP/1.1");
            let ua = bytes((next() % 64) as usize, &mut next);
            let ct: &[u8] = if next() % 2 == 0 {
                b"application/x-www-form-urlencoded"
            } else {
                b"application/json"
            };
            t.request_headers(&[(b"User-Agent", &ua), (b"Content-Type", ct)]);
            let body = bytes((next() % 4096) as usize, &mut next);
            let mut rest = &body[..];
            while !rest.is_empty() {
                let n = 1 + (next() % 512) as usize;
                let n = n.min(rest.len());
                t.request_body_chunk(&rest[..n], false);
                rest = &rest[n..];
            }
            t.request_body_chunk(b"", true);
            let v = t.verdict();
            assert!(!v.need_body);
            for r in &v.rules[..v.n_rules as usize] {
                assert!(
                    (800201..=800205).contains(r) || (100000..200000).contains(r),
                    "unexpected rule {r}"
                );
            }
        }
    }

    /// Bodies are inspected up to 8 MiB; past that the engine keeps
    /// nothing more (the connector's strata_request_body_limit is lower).
    #[test]
    fn body_kept_up_to_its_limit() {
        let chunk = "x".repeat(1 << 20);
        let mut chunks: Vec<&str> = std::iter::repeat_n(chunk.as_str(), 8).collect();
        chunks.push(r#"{"role":"admin"}"#);
        let v = send(
            "POST",
            "/big",
            &[("Content-Type", "application/json")],
            &chunks,
        );
        assert_eq!(
            rules(&v),
            Vec::<u32>::new(),
            "matched past the inspection limit"
        );
        let v = send(
            "POST",
            "/big",
            &[("Content-Type", "application/json")],
            &[&chunk, r#"{"role":"admin"}"#],
        );
        // the body is not JSON (a megabyte of "x" first): 100022 says it
        // did not parse (#97), the raw-body rule still matches
        assert_eq!(rules(&v), [100022, 800204]);
    }
}

// Negation is per value, as in ModSecurity: an absent target never matches,
// a negated operator holds when one value fails it.
mod negation {
    use super::*;

    const RULES: &str = r#"
ir_version: 1
ruleset: { name: negation-test, version: "1" }
rules:
  - { id: 800301, name: content-length not numeric, layer: protocol, stage: request_headers, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: request_headers, key: Content-Length } ], operator: { type: rx, value: '^\d+$', negate: true } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800302, name: no host header, layer: protocol, stage: request_headers, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: request_headers, key: Host, count: true } ], operator: { type: eq, value: 0 } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800303, name: an arg that is not a number, layer: managed, stage: request_headers, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: args } ], operator: { type: rx, value: '^[0-9]+$', negate: true } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;

    fn run(uri: &str, headers: &[(&str, &str)]) -> Vec<u32> {
        let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
        let pol = policies_from(
            &from_yaml("policies: []").unwrap(),
            std::path::Path::new("."),
        )
        .unwrap();
        let b = compile(
            &defs,
            &pol,
            &Build {
                version: 1,
                created_at_ms: 0,
                rollback: false,
            },
            &SEED,
        )
        .unwrap();
        let e = Arc::new(
            Engine::map(
                Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
                &public_key(&SEED),
            )
            .unwrap(),
        );
        // built-in protocol checks (100002 for a bad Content-Length) are not under test
        rules(&super::run(&e, "GET", uri, headers, "192.0.2.1"))
            .into_iter()
            .filter(|id| *id >= 800000)
            .collect()
    }

    #[test]
    fn absent_target_never_matches() {
        assert_eq!(run("/", &[("Host", "api.example.test")]), Vec::<u32>::new());
        assert_eq!(
            run("/", &[("Host", "a"), ("Content-Length", "12")]),
            Vec::<u32>::new()
        );
        assert_eq!(
            run("/", &[("Host", "a"), ("Content-Length", "12a")]),
            [800301]
        );
    }

    #[test]
    fn absence_is_tested_with_a_count() {
        assert_eq!(run("/", &[]), [800302]);
    }

    #[test]
    fn negated_operator_holds_for_one_value() {
        assert_eq!(run("/q?a=1&b=2", &[("Host", "a")]), Vec::<u32>::new());
        assert_eq!(run("/q?a=1&b=x", &[("Host", "a")]), [800303]);
    }
}

// An rx pattern Hyperscan refuses (CRS 932230 is too large for it) is left
// out of the database and runs with the regex crate.
mod regex_fallback {
    use super::*;

    fn engine_932230() -> Arc<Engine> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules/crs/932-rce.yaml");
        let mut doc = from_yaml(&std::fs::read_to_string(path).unwrap()).unwrap();
        doc["rules"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["id"] == 932230);
        let defs = rules_from_ir(&doc).unwrap();
        assert_eq!(defs.len(), 1);
        let pol = policies_from(
            &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
            std::path::Path::new("."),
        )
        .unwrap();
        let b = compile(
            &defs,
            &pol,
            &Build {
                version: 1,
                created_at_ms: 0,
                rollback: false,
            },
            &SEED,
        )
        .unwrap();
        let e = Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap();
        assert_eq!(e.regexes().len(), 1, "932230 runs with the regex crate");
        Arc::new(e)
    }

    fn post(e: &Arc<Engine>, body: &str) -> Vec<u32> {
        let mut t = Tx::new(Some(e.clone()), b"node", 0);
        t.set_client_addr(b"192.0.2.1");
        t.request_line(b"POST", b"/post", b"/post", b"", b"HTTP/1.1");
        t.request_headers(&[
            (b"Host", b"api.example.test"),
            (b"Content-Type", b"application/x-www-form-urlencoded"),
        ]);
        t.request_body_chunk(body.as_bytes(), true);
        rules(&t.verdict())
    }

    /// #49: a rule evaluated on every request (932230 has no gate) gets its
    /// fallback regex compiled when the bundle is mapped, not by the first
    /// request; the regexes of gated rules stay lazy.
    #[test]
    fn hot_fallback_regexes_are_compiled_at_map() {
        assert_eq!(engine_932230().regexes().compiled_count(), 1);
        let gated = r#"
ir_version: 1
ruleset: { name: p, version: "1" }
rules:
  - { id: 800603, name: lazy-rx, layer: managed, stage: request_headers, score: 100, severity: critical,
      match: { all: [
        { targets: [ { var: args } ], operator: { type: contains, value: "zzgate" } },
        { targets: [ { var: args } ], operator: { type: rx, value: "w1x(?:a|b)+y" } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;
        let defs = rules_from_ir(&from_yaml(gated).unwrap()).unwrap();
        let pol = policies_from(
            &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
            std::path::Path::new("."),
        )
        .unwrap();
        let b = compile(
            &defs,
            &pol,
            &Build {
                version: 1,
                created_at_ms: 0,
                rollback: false,
            },
            &SEED,
        )
        .unwrap();
        let e = Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap();
        assert_eq!(e.regexes().len(), 1, "the secondary rx is a fallback regex");
        assert_eq!(
            e.regexes().compiled_count(),
            0,
            "a gated rule's regex stays lazy"
        );
    }

    #[test]
    fn too_large_for_hyperscan_still_matches() {
        let e = engine_932230();
        assert_eq!(
            post(&e, "arg2=()+{+:;};+/bin/sh+-c+\"sleep+6+&&+echo+vulnerable"),
            [932230]
        );
        assert_eq!(post(&e, "comment=see+you+at+six"), Vec::<u32>::new());
    }

    #[test]
    fn regex_has_the_meaning_of_hyperscan() {
        let re = libstrata::eval::fallback_regex(br"\x{bc}a(?i)B\s").unwrap();
        assert!(re.is_match(b"\xbcab\t"));
        assert!(
            libstrata::eval::fallback_regex(br"[\x{bc}-\x{be}]")
                .unwrap()
                .is_match(b"\xbd")
        );
        let one = libstrata::eval::fallback_regex(br"^\x{bc}$").unwrap();
        assert!(one.is_match(b"\xbc"));
        assert!(
            !one.is_match("\u{bc}".as_bytes()),
            "a byte, not a code point"
        );
        assert!(
            libstrata::eval::fallback_regex(br"(a)\1").is_err(),
            "no backreferences"
        );
    }
}

// matched_vars (MATCHED_VARS of chained CRS rules): the next condition sees
// the values, transformed, that the previous one matched.
mod matched_vars {
    use super::*;

    const RULES: &str = r#"
ir_version: 1
ruleset: { name: matched-vars-test, version: "1" }
rules:
  - { id: 800311, name: java class then a dangerous one, layer: managed, stage: request_headers, score: 100, severity: critical,
      match: { all: [
        { targets: [ { var: args }, { var: request_headers } ], transforms: [lowercase], operator: { type: pm, value: [java.lang] } },
        { targets: [ { var: matched_vars } ], operator: { type: rx, value: '(?:runtime|processbuilder)' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800312, name: request line, layer: protocol, stage: request_headers, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: request_line } ], operator: { type: rx, value: '^GET /line\?q=%41 HTTP/1\.1$' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800313, name: raw query, layer: protocol, stage: request_headers, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: query_string } ], operator: { type: contains, value: '%41' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;

    fn run(uri: &str, headers: &[(&str, &str)]) -> Vec<u32> {
        let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
        let pol = policies_from(
            &from_yaml("policies: []").unwrap(),
            std::path::Path::new("."),
        )
        .unwrap();
        let b = compile(
            &defs,
            &pol,
            &Build {
                version: 1,
                created_at_ms: 0,
                rollback: false,
            },
            &SEED,
        )
        .unwrap();
        let e = Arc::new(
            Engine::map(
                Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
                &public_key(&SEED),
            )
            .unwrap(),
        );
        rules(&super::run(&e, "GET", uri, headers, "192.0.2.1"))
            .into_iter()
            .filter(|id| *id >= 800000)
            .collect()
    }

    #[test]
    fn the_same_value_must_match_both_conditions() {
        // one value matches both, after the first condition's lowercase
        assert_eq!(run("/a?x=Java.Lang.RunTime", &[("Host", "a")]), [800311]);
        // each condition matched by a different value: no match
        assert_eq!(
            run("/a?x=java.lang.String&y=runtime", &[("Host", "a")]),
            Vec::<u32>::new()
        );
        assert_eq!(
            run(
                "/a",
                &[("Host", "a"), ("X-Class", "java.lang.ProcessBuilder")]
            ),
            [800311]
        );
    }

    #[test]
    fn request_line_and_raw_query() {
        assert_eq!(run("/line?q=%41", &[("Host", "a")]), [800312, 800313]);
    }

    #[test]
    fn matched_vars_needs_a_previous_condition() {
        for m in [
            "all: [ { targets: [ { var: matched_vars } ], operator: { type: rx, value: a } } ]",
            "any: [ { targets: [ { var: args } ], operator: { type: rx, value: a } }, { targets: [ { var: matched_vars } ], operator: { type: rx, value: a } } ]",
        ] {
            let doc = format!(
                "ir_version: 1\nruleset: {{ name: t, version: '1' }}\nrules:\n  - {{ id: 800314, name: t, layer: managed, stage: request_headers, score: 5, severity: notice, match: {{ {m} }}, metadata: {{ source: organization, license: Apache-2.0 }} }}\n"
            );
            let err = rules_from_ir(&from_yaml(&doc).unwrap()).unwrap_err();
            assert!(err.contains("matched_vars"), "{err}");
        }
    }
}

// multipart/form-data: files and files_names, fields in args_post.
mod multipart_body {
    use super::*;

    const RULES: &str = r#"
ir_version: 1
ruleset: { name: multipart-test, version: "1" }
rules:
  - { id: 800321, name: php upload, layer: managed, stage: request_body, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: files } ], transforms: [lowercase], operator: { type: ends_with, value: .php } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800322, name: upload field, layer: managed, stage: request_body, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: files_names } ], operator: { type: streq, value: avatar } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800323, name: field value, layer: managed, stage: request_body, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: args_post, key: title } ], operator: { type: contains, value: union select } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;

    fn post(ct: &str, body: &str) -> Vec<u32> {
        let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
        let pol = policies_from(
            &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
            std::path::Path::new("."),
        )
        .unwrap();
        let b = compile(
            &defs,
            &pol,
            &Build {
                version: 1,
                created_at_ms: 0,
                rollback: false,
            },
            &SEED,
        )
        .unwrap();
        let e = Arc::new(
            Engine::map(
                Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
                &public_key(&SEED),
            )
            .unwrap(),
        );
        let mut t = Tx::new(Some(e), b"node", 0);
        t.set_client_addr(b"192.0.2.1");
        t.request_line(b"POST", b"/upload", b"/upload", b"", b"HTTP/1.1");
        t.request_headers(&[
            (b"Host", b"api.example.test"),
            (b"Content-Type", ct.as_bytes()),
        ]);
        t.request_body_chunk(body.as_bytes(), true);
        rules(&t.verdict())
    }

    const BODY: &str = "--b1\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\n1 union select 2\r\n\
--b1\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"Shell.PHP\"\r\n\
Content-Type: image/png\r\n\r\n\x7fPNG\r\n--b1--\r\n";

    #[test]
    fn files_and_fields() {
        assert_eq!(
            post("multipart/form-data; boundary=b1", BODY),
            [800321, 800322, 800323]
        );
    }

    #[test]
    fn only_for_multipart() {
        assert_eq!(post("text/plain", BODY), Vec::<u32>::new());
        // a boundary the body does not use: nothing parses, 100022 (#97);
        // a WAF and a backend that disagree on the parts is a known bypass
        assert_eq!(post("multipart/form-data; boundary=other", BODY), [100022]);
    }
}

// JSON bodies give arguments, XML bodies the xml and xml_attributes targets.
mod json_and_xml_bodies {
    use super::*;

    const RULES: &str = r#"
ir_version: 1
ruleset: { name: body-formats-test, version: "1" }
rules:
  - { id: 800331, name: xss in args, layer: managed, stage: request_body, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: args } ], transforms: [html_entity_decode, lowercase], operator: { type: rx, value: 'javascript\s*:' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800332, name: json argument name, layer: managed, stage: request_body, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: args_names } ], operator: { type: streq, value: json.user.roles.1 } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800333, name: rfi in xml text, layer: managed, stage: request_body, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: xml } ], transforms: [url_decode_uni], operator: { type: contains, value: 'ftp://' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800334, name: xss in xml attribute, layer: managed, stage: request_body, score: 100, severity: critical,
      match: { all: [ { targets: [ { var: xml_attributes } ], operator: { type: detect_xss } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;

    fn post(ct: &str, body: &str) -> Vec<u32> {
        let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
        let pol = policies_from(
            &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
            std::path::Path::new("."),
        )
        .unwrap();
        let b = compile(
            &defs,
            &pol,
            &Build {
                version: 1,
                created_at_ms: 0,
                rollback: false,
            },
            &SEED,
        )
        .unwrap();
        let e = Arc::new(
            Engine::map(
                Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
                &public_key(&SEED),
            )
            .unwrap(),
        );
        let mut t = Tx::new(Some(e), b"node", 0);
        t.set_client_addr(b"192.0.2.1");
        t.request_line(b"POST", b"/api", b"/api", b"", b"HTTP/1.1");
        t.request_headers(&[
            (b"Host", b"api.example.test"),
            (b"Content-Type", ct.as_bytes()),
        ]);
        t.request_body_chunk(body.as_bytes(), true);
        rules(&t.verdict())
    }

    #[test]
    fn json_scalars_are_arguments() {
        assert_eq!(
            post("application/json", r#"{"url":"javascript&#10;:alert(7)"}"#),
            [800331]
        );
        assert_eq!(
            post(
                "application/json; charset=utf-8",
                r#"{"user": {"roles": ["a", "b"]}}"#
            ),
            [800332]
        );
        assert_eq!(
            post("text/plain", r#"{"url":"javascript:alert(7)"}"#),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn xml_text_and_attributes() {
        assert_eq!(
            post(
                "application/xml",
                r#"<?xml version="1.0"?><catalog><tag>ftp%3A%2F%2F192.0.2.1</tag></catalog>"#
            ),
            [800333]
        );
        assert_eq!(
            post(
                "text/xml",
                r#"<root><a probe="&lt;script&gt;alert(1)&lt;/script&gt;"/></root>"#
            ),
            [800334]
        );
        assert_eq!(
            post("application/xml", "<root><a probe=\"safe\">text</a></root>"),
            Vec::<u32>::new()
        );
    }
}

// multi_match: the operator runs before the transformations and after each.
mod multi_match {
    use super::*;

    fn rule(multi: bool) -> String {
        format!(
            r#"
ir_version: 1
ruleset: {{ name: multi-match-test, version: "1" }}
rules:
  - {{ id: 800341, name: dot dot backslash, layer: managed, stage: request_headers, score: 100, severity: critical,
      match: {{ all: [ {{ targets: [ {{ var: args }} ], transforms: [url_decode_uni, cmd_line], multi_match: {multi},
                        operator: {{ type: rx, value: '\.\.\\' }} }} ] }},
      metadata: {{ source: organization, license: Apache-2.0 }} }}
"#
        )
    }

    fn run(multi: bool, uri: &str) -> Vec<u32> {
        let defs = rules_from_ir(&from_yaml(&rule(multi)).unwrap()).unwrap();
        assert_eq!(defs[0].conditions[0].multi_match, multi);
        let pol = policies_from(
            &from_yaml("policies: []").unwrap(),
            std::path::Path::new("."),
        )
        .unwrap();
        let b = compile(
            &defs,
            &pol,
            &Build {
                version: 1,
                created_at_ms: 0,
                rollback: false,
            },
            &SEED,
        )
        .unwrap();
        let e = Arc::new(
            Engine::map(
                Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
                &public_key(&SEED),
            )
            .unwrap(),
        );
        rules(&super::run(&e, "GET", uri, &[("Host", "a")], "192.0.2.1"))
            .into_iter()
            .filter(|id| *id >= 800000)
            .collect()
    }

    #[test]
    fn matches_between_transformations() {
        // cmd_line removes the backslash: only the value before it matches
        assert_eq!(run(false, "/get?arg=..%5Cpineapple"), Vec::<u32>::new());
        assert_eq!(run(true, "/get?arg=..%5Cpineapple"), [800341]);
        assert_eq!(run(true, "/get?arg=pineapple"), Vec::<u32>::new());
    }
}

// Numeric operators run on the transformed value: with length, on the
// value's byte length.
mod length {
    use super::*;

    const RULES: &str = r#"
ir_version: 1
ruleset: { name: length-test, version: "1" }
rules:
  - { id: 800351, name: long argument, layer: protocol, stage: request_headers, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: args } ], transforms: [length], operator: { type: gt, value: 5 } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800352, name: long after decoding, layer: protocol, stage: request_headers, score: 5, severity: notice,
      match: { all: [ { targets: [ { var: uri_raw } ], transforms: [url_decode, length], operator: { type: le, value: 3 } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;

    fn run(uri: &str) -> Vec<u32> {
        let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
        let pol = policies_from(
            &from_yaml("policies: []").unwrap(),
            std::path::Path::new("."),
        )
        .unwrap();
        let b = compile(
            &defs,
            &pol,
            &Build {
                version: 1,
                created_at_ms: 0,
                rollback: false,
            },
            &SEED,
        )
        .unwrap();
        let e = Arc::new(
            Engine::map(
                Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
                &public_key(&SEED),
            )
            .unwrap(),
        );
        rules(&super::run(&e, "GET", uri, &[("Host", "a")], "192.0.2.1"))
            .into_iter()
            .filter(|id| *id >= 800000)
            .collect()
    }

    #[test]
    fn compares_the_length() {
        assert_eq!(run("/s?a=123456"), [800351]);
        assert_eq!(run("/s?a=12345&b=1"), Vec::<u32>::new());
        // "/%41" is 4 bytes raw, 2 decoded
        assert_eq!(run("/%41"), [800352]);
        assert_eq!(run("/abcd"), Vec::<u32>::new());
    }
}
