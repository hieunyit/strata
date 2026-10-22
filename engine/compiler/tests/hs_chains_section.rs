//! #27/#28: the HYPERSCAN_CHAINS section (kind 17), one block-mode
//! database per transformation chain. Checks its layout, that a bundle with
//! it gives the verdicts of the same rules without it (both sides of the
//! block scan limit, end-anchored and multi_match patterns included), and
//! that a signed bundle whose chain databases do not match their chains is
//! refused.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, kind, public_key, verify};
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use strata_compiler::{Build, Options, compile_opts, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [46; 32];

const RULES: &str = r#"
ir_version: 1
ruleset: { name: hs_block, version: "1" }
rules:
  - id: 930001
    name: needle in an argument
    layer: managed
    stage: request_headers
    score: 5
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args } ]
          transforms: [ lowercase ]
          operator: { type: contains, value: "block_needle" }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 930002
    name: argument ends with a marker
    layer: managed
    stage: request_headers
    score: 5
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args } ]
          operator: { type: rx, value: "tail_marker$" }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 930003
    name: words in a list
    layer: managed
    stage: request_headers
    score: 5
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args } ]
          transforms: [ url_decode, lowercase ]
          operator: { type: pm, value: [ "union select", "sleep(" ] }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 930004
    name: marker before or after decoding
    layer: managed
    stage: request_headers
    score: 5
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [ { var: args } ]
          transforms: [ url_decode, remove_whitespace ]
          multi_match: true
          operator: { type: rx, value: "mm_[0-9]+_mark" }
    metadata: { source: organization, license: Apache-2.0 }
"#;

fn bundle(hs_block: bool, hs_chains: bool) -> Vec<u8> {
    let defs = rules_from_ir(&from_yaml(RULES).unwrap()).unwrap();
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        Path::new("."),
    )
    .unwrap();
    let build = Build {
        version: 1,
        created_at_ms: 0,
        rollback: false,
    };
    compile_opts(
        &defs,
        &pol,
        &build,
        &SEED,
        Options {
            hs_block,
            hs_chains,
        },
    )
    .unwrap()
}

fn map(b: &[u8]) -> Result<Engine, (i32, &'static str)> {
    Engine::map(
        Box::new(strata_hs::AlignedBuf::from_bytes(b)),
        &public_key(&SEED),
    )
}

fn sections(b: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let info = verify(b, &public_key(&SEED)).unwrap();
    (1..=kind::KNOWN)
        .filter(|&k| info.sections[k as usize] != (0, 0))
        .map(|k| (k, info.section(b, k).to_vec()))
        .collect()
}

fn rebuild(secs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let refs: Vec<(u32, &[u8])> = secs.iter().map(|(k, s)| (*k, &s[..])).collect();
    let policies = [PolicySpec::new(
        "example-api",
        Mode::Enforce,
        Oversize::Pass,
    )];
    build(
        &Spec {
            version: 1,
            created_at_ms: 0,
            flags: 0,
            policies: &policies,
            sections: &refs,
        },
        &SEED,
    )
    .unwrap()
}

fn u32_at(b: &[u8], off: usize) -> usize {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize
}

fn verdict(e: &Arc<Engine>, query: &str) -> (u32, Vec<u32>) {
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
    t.request_headers(&[(&b"Host"[..], &b"api.example.test"[..])]);
    let v = t.verdict();
    let mut rules = v.rules[..v.n_rules as usize].to_vec();
    rules.sort_unstable();
    (v.action, rules)
}

#[test]
fn layout_one_database_per_chain() {
    let b = bundle(true, true);
    let secs = sections(&b);
    assert!(
        secs.iter().all(|(k, _)| *k != kind::HYPERSCAN_BLOCK),
        "chains replace section 8"
    );
    let sec = &secs
        .iter()
        .find(|(k, _)| *k == kind::HYPERSCAN_CHAINS)
        .unwrap()
        .1;
    assert_eq!(&sec[..4], b"SHC1");
    let n = u32_at(sec, 4);
    // none, lowercase, url_decode+lowercase, and the three prefixes of the
    // multi_match chain (none is shared)
    assert!(n >= 5, "{n} chains");
    let mut chains = vec![];
    for i in 0..n {
        let e = &sec[8 + i * 28..8 + (i + 1) * 28];
        let (off, len) = (u32_at(e, 20), u32_at(e, 24));
        assert_eq!(off % 4096, 0);
        assert_eq!(&sec[off..off + 4], b"SHS1");
        assert!(off + len <= sec.len());
        chains.push(e[4..4 + e[0] as usize].to_vec());
    }
    let mut d = chains.clone();
    d.sort();
    d.dedup();
    assert_eq!(d.len(), chains.len(), "distinct chains");
    let e = map(&b).unwrap();
    assert_eq!(e.tables().n_hyperscan_chains(), n);
}

#[test]
fn same_verdicts_with_chain_databases() {
    let engines = [
        Arc::new(map(&bundle(false, false)).unwrap()),
        Arc::new(map(&bundle(true, false)).unwrap()),
        Arc::new(map(&bundle(true, true)).unwrap()),
    ];
    let mut checked = 0;
    for len in [10usize, 2047, 2048, 2049, 9000] {
        for (payload, want) in [
            ("BLOCK_NEEDLE", Some(930001)),
            ("x_tail_marker", Some(930002)),
            ("tail_marker_not_at_end_", None),
            ("1%20UNION%20SELECT%202", Some(930003)),
            ("mm_12_mark", Some(930004)),
            ("mm_%31%32_mark", Some(930004)),
            ("mm_1%202_mark", Some(930004)),
            ("nothing_here", None),
        ] {
            let pad = "a".repeat(len.saturating_sub(payload.len()));
            for q in [format!("q={pad}{payload}"), format!("q={payload}{pad}")] {
                let v: Vec<_> = engines.iter().map(|e| verdict(e, &q)).collect();
                assert_eq!(v[0], v[1], "len {len}, {payload}");
                assert_eq!(v[0], v[2], "len {len}, {payload}: chains");
                if q.ends_with(payload) {
                    assert_eq!(v[0].1.first().copied(), want, "len {len}, {payload}");
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 80);
}

#[test]
fn chain_databases_that_do_not_match_their_chains_are_refused() {
    let b = bundle(true, true);
    let secs = sections(&b);
    let at = secs
        .iter()
        .position(|(k, _)| *k == kind::HYPERSCAN_CHAINS)
        .unwrap();
    let sec = secs[at].1.clone();
    let n = u32_at(&sec, 4);
    let with = |s: Vec<u8>| {
        let mut v = secs.clone();
        v[at].1 = s;
        rebuild(&v)
    };
    // the untouched section maps
    assert!(map(&with(sec.clone())).is_ok());
    // two entries swap their chains: patterns on another chain
    let mut swapped = sec.clone();
    let (a, b) = (8 + 4, 8 + 28 + 4);
    let (ca, cb) = (sec[a - 4], sec[b - 4]);
    let chain_a = sec[a..a + 16].to_vec();
    let chain_b = sec[b..b + 16].to_vec();
    swapped[a - 4] = cb;
    swapped[b - 4] = ca;
    swapped[a..a + 16].copy_from_slice(&chain_b);
    swapped[b..b + 16].copy_from_slice(&chain_a);
    assert!(n >= 2);
    let err = map(&with(swapped)).unwrap_err();
    assert!(err.1.contains("another chain"), "{err:?}");
    // the same chain twice
    let mut twice = sec.clone();
    twice[b - 4] = ca;
    twice[b..b + 16].copy_from_slice(&chain_a);
    assert!(map(&with(twice)).is_err());
    // a sub-section out of the section
    let mut out = sec.clone();
    out[8 + 20..8 + 24].copy_from_slice(&(sec.len() as u32 + 4096).to_le_bytes());
    assert!(map(&with(out)).is_err());
    // without the stream section
    let mut v: Vec<_> = secs
        .iter()
        .filter(|(k, _)| *k != kind::HYPERSCAN)
        .cloned()
        .collect();
    v.retain(|(k, _)| *k != kind::HYPERSCAN_BLOCK);
    assert!(map(&rebuild(&v)).is_err());
}
