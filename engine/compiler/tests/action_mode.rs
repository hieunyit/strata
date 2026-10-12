//! W08-R-02: action_mode (block_alone | score) through a real compiled
//! bundle. A block_alone rule blocks as soon as it matches, even with a
//! score well under the threshold; a score rule only adds to the anomaly
//! total and blocks only once that total reaches BLOCK_THRESHOLD (100).

use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, Verdict};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [7; 32];

// All three rules add 10..=100 points. Only the mode differs.
const RULES: &str = r#"
ir_version: 1
ruleset: { name: action-mode-test, version: "1" }
rules:
  - { id: 700201, name: virtual patch (blocks alone), layer: managed, stage: request_headers, score: 10,
      action_mode: block_alone, severity: critical,
      match: { all: [ { targets: [ { var: request_headers, key: User-Agent } ],
                        operator: { type: pm, value: [badbot] } } ] },
      metadata: { source: strata, license: Apache-2.0 } }
  - { id: 800202, name: suspicious extension (score only), layer: managed, stage: request_headers, score: 10,
      action_mode: score, severity: notice,
      match: { all: [ { targets: [ { var: path } ], operator: { type: ends_with, value: .bak } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
  - { id: 800203, name: high-score scanner reaches threshold, layer: managed, stage: request_headers, score: 100,
      action_mode: score, severity: error,
      match: { all: [ { targets: [ { var: path } ], operator: { type: ends_with, value: .evil } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#;

fn engine() -> Arc<Engine> {
    let rules = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(&from_yaml("policies: []").unwrap(), std::path::Path::new(".")).unwrap();
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

fn run(e: &Arc<Engine>, uri: &str, headers: &[(&str, &str)]) -> Verdict {
    let (path, args) = uri.split_once('?').unwrap_or((uri, ""));
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_client_addr(b"192.0.2.1");
    t.request_line(b"GET", uri.as_bytes(), path.as_bytes(), args.as_bytes(), b"HTTP/1.1");
    let h: Vec<(&[u8], &[u8])> = headers.iter().map(|(k, v)| (k.as_bytes(), v.as_bytes())).collect();
    t.request_headers(&h);
    t.verdict()
}

fn rules(v: &Verdict) -> Vec<u32> {
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort();
    r
}

#[test]
fn block_alone_rule_blocks_below_threshold() {
    let e = engine();
    let v = run(&e, "/index.html", &[("User-Agent", "BadBot/1.0")]);
    assert_eq!(rules(&v), [700201]);
    // score is only 10, far below the threshold of 100, yet it blocks
    assert_eq!((v.score, v.action), (10, ACTION_BLOCK));
    assert_eq!(v.status, 403);
}

#[test]
fn score_rule_below_threshold_does_not_block() {
    let e = engine();
    let v = run(&e, "/backup.bak", &[("User-Agent", "example-client/1.0")]);
    assert_eq!(rules(&v), [800202]);
    // the same score (10) only accumulates; the request is allowed
    assert_eq!((v.score, v.action), (10, ACTION_ALLOW));
}

#[test]
fn score_rule_still_blocks_at_threshold() {
    let e = engine();
    let v = run(&e, "/shell.evil", &[("User-Agent", "example-client/1.0")]);
    assert_eq!(rules(&v), [800203]);
    assert_eq!((v.score, v.action), (100, ACTION_BLOCK));
}

#[test]
fn block_alone_wins_even_mixed_with_a_score_rule() {
    // both a block_alone rule and a score rule match; the request blocks on
    // the block_alone rule regardless of the combined score
    let e = engine();
    let v = run(&e, "/backup.bak", &[("User-Agent", "BadBot/1.0")]);
    assert_eq!(rules(&v), [700201, 800202]);
    assert_eq!((v.score, v.action), (20, ACTION_BLOCK));
}
