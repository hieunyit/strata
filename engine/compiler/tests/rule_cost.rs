//! W13-R-02: the time of each rule, sampled. A sampled transaction times
//! the prefilter's scans (Rule ID 0) and each rule it evaluates; its event
//! carries its most expensive rules (Event.rule_costs, field 23), and the
//! counters datagram the sums since the last one (PolicyCounters fields
//! 5-7). The sampling rate is process-wide: this file is its own test
//! binary, with one test.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::rulecost::{RULE_SCAN, set_sample_every};
use libstrata::tx::Tx;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [50; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: rule-cost, version: "1" }
rules:
  - id: 930501
    name: gated by the prefilter
    layer: managed
    stage: request_body
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args } ]
          operator: { type: contains, value: "evil-marker" }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 930502
    name: evaluated on every request
    layer: managed
    stage: request_body
    score: 5
    severity: notice
    action_mode: score
    match:
      all:
        - targets: [ { var: args } ]
          operator: { type: detect_sqli }
    metadata: { source: organization, license: Apache-2.0 }
"#;

fn engine() -> Arc<Engine> {
    let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        Path::new("."),
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
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

fn run(e: &Arc<Engine>, query: &str) -> Tx {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-api");
    t.set_client_addr(b"192.0.2.10");
    let uri = format!("/search?{query}");
    t.request_line(
        b"GET",
        uri.as_bytes(),
        b"/search",
        query.as_bytes(),
        b"HTTP/1.1",
    );
    t.request_headers(&[(b"Host", b"api.example.test")]);
    t.request_body_chunk(b"", true);
    t.add_time_ns(50_000);
    t
}

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = vec![];
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A RuleCost message for `rule` starts with field 1 = rule.
fn rule_cost_of(rule: u32) -> Vec<u8> {
    [&[0x08][..], &varint(u64::from(rule))].concat()
}

fn read_varint(b: &[u8], i: &mut usize) -> u64 {
    let (mut v, mut shift) = (0u64, 0);
    while *i < b.len() {
        let c = b[*i];
        *i += 1;
        v |= u64::from(c & 0x7f) << shift;
        if c & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    v
}

/// Top-level fields of a protobuf message: (number, varint or bytes).
fn fields(b: &[u8]) -> Vec<(u64, u64, Vec<u8>)> {
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        let tag = read_varint(b, &mut i);
        match tag & 7 {
            0 => {
                let v = read_varint(b, &mut i);
                out.push((tag >> 3, v, vec![]));
            }
            2 => {
                let n = read_varint(b, &mut i) as usize;
                out.push((tag >> 3, 0, b[i..i + n].to_vec()));
                i += n;
            }
            _ => panic!("wire type {}", tag & 7),
        }
    }
    out
}

/// RuleCost messages in `field`: (rule_id, samples, total_ns, max_ns).
fn rule_costs(msg: &[u8], field: u64) -> Vec<[u64; 4]> {
    fields(msg)
        .into_iter()
        .filter(|f| f.0 == field)
        .map(|f| {
            let mut c = [0u64; 4];
            for (n, v, _) in fields(&f.2) {
                c[(n - 1) as usize] = v;
            }
            c
        })
        .collect()
}

#[test]
fn sampled_transactions_report_their_rules() {
    let e = engine();

    // not sampled: nothing timed, no field 23
    set_sample_every(0);
    let t = run(&e, "q=evil-marker");
    assert!(t.request_costs().is_empty());
    let ev = t.encode_event().unwrap();
    assert!(!has(&ev, &[0xba, 0x01]), "field 23 in an event not sampled");
    drop(t);

    // every transaction sampled
    set_sample_every(1);
    let t = run(&e, "q=evil-marker&page=2");
    let costs = t.request_costs();
    let ids: Vec<u32> = costs.iter().map(|c| c.0).collect();
    assert!(ids.contains(&RULE_SCAN), "the prefilter's scans: {costs:?}");
    assert!(
        ids.contains(&930_501) && ids.contains(&930_502),
        "{costs:?}"
    );
    assert!(costs.iter().all(|c| c.1 >= 1 && c.2 >= c.3 && c.3 > 0));
    assert!(
        costs.windows(2).all(|w| w[0].2 >= w[1].2),
        "most expensive first"
    );
    let ev = t.encode_event().expect("blocked: an event");
    // field 23 (wire type 2) holding RuleCost messages
    assert!(has(&ev, &[0xba, 0x01]));
    assert!(has(&ev, &rule_cost_of(930_501)));
    drop(t);

    // a clean request: no event, but its costs reach the counters
    drop(run(&e, "q=hello"));
    let t = run(&e, "q=again");
    let datagram = t.encode_counters().expect("a second passed: counters");
    let top = fields(&datagram[4..]);
    // 6: the two sampled transactions dropped so far (the first was not
    // sampled); 7: their engine time, 50 µs each as added above
    let get = |n: u64| top.iter().find(|f| f.0 == n).map(|f| f.1);
    assert_eq!(get(6), Some(2), "sampled_requests");
    assert_eq!(get(7), Some(100_000), "sampled_engine_ns");
    let costs = rule_costs(&datagram[4..], 5);
    for rule in [u64::from(RULE_SCAN), 930_501, 930_502] {
        let c = costs
            .iter()
            .find(|c| c[0] == rule)
            .expect("in the counters");
        // the gated rule only runs when its gate holds (one request)
        assert!(c[1] >= 1 && c[2] >= c[3] && c[3] > 0, "{rule}: {c:?}");
    }
    assert!(
        costs.windows(2).all(|w| w[0][2] >= w[1][2]),
        "most expensive first"
    );
    // the event's field 23 reads back the same way
    let mut t2 = run(&e, "q=evil-marker");
    let ev = t2.encode_event().unwrap();
    assert!(rule_costs(&ev, 23).iter().any(|c| c[0] == 930_501));
    t2.set_policy(b"example-api");
    drop((t, t2));
    set_sample_every(100);
}
