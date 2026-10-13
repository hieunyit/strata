//! W09-R-01: each case of the prefilter and of the lowering of secondary
//! conditions, on small rule sets, against the reference (compiled as
//! before W09, every rule evaluated on every request). The full-package
//! comparison on the corpora is tests/prefilter_differential.rs.

use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, compile_reference, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [3; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: prefilter-test, version: "1" }
rules:
  # any: either condition
  - { id: 800701, name: any of two, layer: managed, stage: request_headers, score: 1, severity: notice,
      match: { any: [ { targets: [ { var: args } ], operator: { type: contains, value: alpha-one } },
                      { targets: [ { var: request_headers, key: X-Probe } ], operator: { type: contains, value: beta-two } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  # all: a loose first condition, the selective one second (reordered, the loose one lowered)
  - { id: 800702, name: loose then selective, layer: managed, stage: request_headers, score: 1, severity: notice,
      match: { all: [ { targets: [ { var: args } ], operator: { type: rx, value: '^\w' } },
                      { targets: [ { var: path } ], operator: { type: contains, value: /gamma-three } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  # all: loose literal companions (contains "/", streq method) of a selective rx
  - { id: 800703, name: literal companions, layer: managed, stage: request_body, score: 1, severity: notice,
      match: { all: [ { targets: [ { var: method } ], operator: { type: streq, value: GET } },
                      { targets: [ { var: uri } ], operator: { type: contains, value: / } },
                      { targets: [ { var: args } ], operator: { type: rx, value: 'delta-[0-9]{3}' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  # a chain: the second condition reads what the first matched (order kept)
  - { id: 800704, name: chain on matched_vars, layer: managed, stage: request_headers, score: 1, severity: notice,
      match: { all: [ { targets: [ { var: request_headers, key: Content-Type } ], operator: { type: rx, value: '^[^;]+' } },
                      { targets: [ { var: matched_vars } ], operator: { type: rx, value: '^text/epsilon;' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  # a chain where the selective condition is in the middle and read by the
  # next: moving it first would hand the chain the first condition's values
  - { id: 800708, name: chain through the selective one, layer: managed, stage: request_headers, score: 1, severity: notice,
      match: { all: [ { targets: [ { var: args } ], operator: { type: rx, value: '^[0-9]' } },
                      { targets: [ { var: args } ], operator: { type: contains, value: kappa-six } },
                      { targets: [ { var: matched_vars } ], operator: { type: rx, value: 'kappa-six-ok' } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  # the only pattern condition is negated: not a gate, evaluated every time
  - { id: 800705, name: negated only, layer: managed, stage: request_headers, score: 1, severity: notice,
      match: { all: [ { targets: [ { var: request_headers, key: X-Zeta } ], operator: { type: streq, value: ok, negate: true } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  # no pattern at all (numeric): evaluated every time
  - { id: 800706, name: numeric only, layer: managed, stage: request_headers, score: 1, severity: notice,
      match: { all: [ { targets: [ { var: args, count: true } ], operator: { type: gt, value: 3 } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  # pm gate with a loose rx companion, transforms on both
  - { id: 800707, name: pm gate, layer: managed, stage: request_headers, score: 1, severity: notice,
      match: { all: [ { targets: [ { var: args } ], transforms: [ lowercase ], operator: { type: rx, value: '[a-z]' } },
                      { targets: [ { var: args } ], transforms: [ lowercase ], operator: { type: pm, value: [ eta-four, theta-five ] } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;

fn engines() -> (Arc<Engine>, Arc<Engine>) {
    let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: shadow }]").unwrap(),
        std::path::Path::new("."),
    )
    .unwrap();
    let build = Build {
        version: 1,
        created_at_ms: 0,
        rollback: false,
    };
    let map = |b: Vec<u8>| {
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap()
    };
    let mut reference = map(compile_reference(&defs, &pol, &build, &SEED).unwrap());
    reference.disable_prefilter();
    let fast = map(compile(&defs, &pol, &build, &SEED).unwrap());
    (Arc::new(reference), Arc::new(fast))
}

fn rules(e: &Arc<Engine>, uri: &str, headers: &[(&str, &str)]) -> Vec<u32> {
    let (path, args) = uri.split_once('?').unwrap_or((uri, ""));
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-api");
    t.request_line(
        b"GET",
        uri.as_bytes(),
        path.as_bytes(),
        args.as_bytes(),
        b"HTTP/1.1",
    );
    let mut h = vec![("Host", "api.example.test")];
    h.extend_from_slice(headers);
    let hs: Vec<(&[u8], &[u8])> = h
        .iter()
        .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
        .collect();
    t.request_headers(&hs);
    t.request_body_chunk(b"", true);
    let v = t.verdict();
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort_unstable();
    r
}

/// A request target, its headers, and the rules it must match.
type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a [u32]);

/// Each case checked on both engines.
fn check(cases: &[Case<'_>]) {
    let (reference, fast) = engines();
    for (uri, headers, want) in cases {
        let a = rules(&reference, uri, headers);
        let b = rules(&fast, uri, headers);
        assert_eq!(a, *want, "reference on {uri} {headers:?}");
        assert_eq!(b, *want, "prefilter on {uri} {headers:?}");
    }
}

const ZETA: (&str, &str) = ("X-Zeta", "ok");

#[test]
fn any_rule_matches_on_either_condition() {
    check(&[
        ("/a?x=alpha-one", &[ZETA], &[800701]),
        ("/a", &[ZETA, ("X-Probe", "beta-two")], &[800701]),
        ("/a?x=nothing", &[ZETA, ("X-Probe", "other")], &[]),
    ]);
}

#[test]
fn reordered_and_lowered_conditions_keep_the_rule() {
    check(&[
        ("/gamma-three?x=word", &[ZETA], &[800702]),
        ("/gamma-three?x=%20space", &[ZETA], &[]), // the loose condition fails
        ("/other?x=word", &[ZETA], &[]),           // the selective one fails
    ]);
}

#[test]
fn literal_companions_lowered() {
    check(&[
        ("/p?q=delta-123", &[ZETA], &[800703]),
        ("/p?q=delta-12", &[ZETA], &[]),
    ]);
}

#[test]
fn chains_on_matched_vars_keep_their_order() {
    check(&[
        (
            "/c",
            &[ZETA, ("Content-Type", "text/epsilon; charset=utf-8")],
            &[800704],
        ),
        (
            "/c",
            &[ZETA, ("Content-Type", "text/other; charset=utf-8")],
            &[],
        ),
        ("/c?x=kappa-six-ok&y=1", &[ZETA], &[800708]),
        ("/c?x=kappa-six-no&y=1", &[ZETA], &[]),
    ]);
}

#[test]
fn negated_and_numeric_rules_run_on_every_request() {
    check(&[
        ("/n", &[("X-Zeta", "no")], &[800705]),
        ("/n?a=1&b=2&c=3&d=4", &[ZETA], &[800706]),
        ("/n?a=1&b=2&c=3", &[ZETA], &[]),
    ]);
}

#[test]
fn pm_gate_with_transforms() {
    check(&[
        ("/m?x=THETA-FIVE", &[ZETA], &[800707]),
        ("/m?x=iota", &[ZETA], &[]),
    ]);
}

#[test]
fn the_selective_condition_is_the_gate() {
    // 800702's gate is its second condition, moved first: the prefilter
    // skips it on requests without /gamma-three even though ^\w holds
    let (_, fast) = engines();
    let (gated, groups) = fast.prefilter().stats();
    // 800705 and 800706 have no gate; the other six do
    assert_eq!(gated, 6, "gated rules");
    assert!(groups >= 4, "scan groups: {groups}");
}
