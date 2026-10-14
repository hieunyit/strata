//! #27: the HYPERSCAN_BLOCK section (kind 8), the block-mode copy of the
//! Hyperscan database that engines scan values up to 2048 bytes with.
//! Checks its layout, that a bundle with it gives the verdicts of the same
//! bundle without it on both sides of the length limit (end-anchored
//! patterns included), and that a signed bundle whose block section does
//! not match its stream section is refused.

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, kind, public_key, verify};
use libstrata::engine::Engine;
use libstrata::rules::BLOCK_SCAN_MAX;
use libstrata::tx::Tx;
use strata_compiler::{Build, Options, compile_opts, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [45; 32];

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
"#;

fn bundle(hs_block: bool) -> Vec<u8> {
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
    compile_opts(&defs, &pol, &build, &SEED, Options { hs_block }).unwrap()
}

fn map(b: &[u8]) -> Result<Engine, (i32, &'static str)> {
    Engine::map(
        Box::new(strata_hs::AlignedBuf::from_bytes(b)),
        &public_key(&SEED),
    )
}

/// Sections of a signed bundle, in directory order.
fn sections(b: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let info = verify(b, &public_key(&SEED)).unwrap();
    (1..=kind::KNOWN)
        .filter(|&k| info.sections[k as usize] != (0, 0))
        .map(|k| (k, info.section(b, k).to_vec()))
        .collect()
}

/// The bundle again from `secs`, signed.
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
fn layout_mirrors_the_stream_section() {
    let without = bundle(false);
    assert!(
        sections(&without)
            .iter()
            .all(|(k, _)| *k != kind::HYPERSCAN_BLOCK)
    );
    let b = bundle(true);
    let secs = sections(&b);
    let stream = &secs.iter().find(|(k, _)| *k == kind::HYPERSCAN).unwrap().1;
    let block = &secs
        .iter()
        .find(|(k, _)| *k == kind::HYPERSCAN_BLOCK)
        .unwrap()
        .1;
    assert_eq!(&stream[..4], b"SHS2");
    assert_eq!(&block[..4], b"SHS1");
    // pattern count, Hyperscan version and condition index are the same
    let n = u32::from_le_bytes(stream[4..8].try_into().unwrap()) as usize;
    assert!(n >= 4, "{n} patterns");
    assert_eq!(stream[4..40], block[4..40]);
    assert_eq!(stream[56..56 + n * 4], block[56..56 + n * 4]);
    let db_off = u32::from_le_bytes(block[40..44].try_into().unwrap()) as usize;
    assert_eq!(db_off % 4096, 0);
    let e = map(&b).unwrap();
    assert!(e.hyperscan().is_some() && e.hyperscan_block().is_some());
    assert!(map(&without).unwrap().hyperscan_block().is_none());
}

#[test]
fn same_verdicts_on_both_sides_of_the_limit() {
    let (stream_only, with_block) = (
        Arc::new(map(&bundle(false)).unwrap()),
        Arc::new(map(&bundle(true)).unwrap()),
    );
    assert_eq!(BLOCK_SCAN_MAX, 2048);
    let mut checked = 0;
    for len in [10usize, 2046, 2047, 2048, 2049, 2050, 4096, 9000] {
        for (payload, want) in [
            ("BLOCK_NEEDLE", Some(930001)),
            ("x_tail_marker", Some(930002)),
            ("tail_marker_not_at_end_", None),
            ("1%20UNION%20SELECT%202", Some(930003)),
            ("nothing_here", None),
        ] {
            // the value (q) is `len` bytes long, the payload at its end, so
            // an end-anchored pattern is at the end of the scanned bytes
            let pad = "a".repeat(len.saturating_sub(payload.len()));
            for q in [format!("q={pad}{payload}"), format!("q={payload}{pad}")] {
                let (a, b) = (verdict(&stream_only, &q), verdict(&with_block, &q));
                assert_eq!(a, b, "len {len}, {payload}");
                if q.ends_with(payload) {
                    assert_eq!(a.1.first().copied(), want, "len {len}, {payload}");
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 80);
}

#[test]
fn a_block_section_that_does_not_match_is_refused() {
    let secs = sections(&bundle(true));
    let at = |k| secs.iter().position(|(kk, _)| *kk == k).unwrap();
    let (si, bi) = (at(kind::HYPERSCAN), at(kind::HYPERSCAN_BLOCK));
    assert!(map(&rebuild(&secs)).is_ok(), "the rebuilt bundle maps");

    // another condition index (a pattern points elsewhere)
    let mut s = secs.clone();
    s[bi].1[56] ^= 1;
    let err = map(&rebuild(&s)).unwrap_err();
    assert!(err.1.contains("block section"), "{err:?}");

    // a stream image under the block kind
    let mut s = secs.clone();
    s[bi].1 = s[si].1.clone();
    assert!(map(&rebuild(&s)).is_err());

    // a block section without a stream section
    let mut s = secs.clone();
    s.remove(si);
    assert!(map(&rebuild(&s)).is_err());

    // another Hyperscan version string
    let mut s = secs.clone();
    s[bi].1[8] ^= 0x20;
    assert!(map(&rebuild(&s)).is_err());

    // damaged block bytecode: the CRC check at load refuses it
    let mut s = secs.clone();
    let n = s[bi].1.len();
    s[bi].1[n - 100] ^= 0xff;
    assert!(map(&rebuild(&s)).is_err());
}

/// An engine that predates the section skips it: a bundle with kind 8 is
/// read like one without it (unknown kinds are skipped). Simulated with a
/// kind past every known one, which every engine skips the same way.
#[test]
fn unknown_kinds_are_still_skipped() {
    let mut secs = sections(&bundle(true));
    let block = secs
        .iter()
        .position(|(k, _)| *k == kind::HYPERSCAN_BLOCK)
        .unwrap();
    secs[block].0 = kind::KNOWN + 1;
    let e = Arc::new(map(&rebuild(&secs)).unwrap());
    assert!(e.hyperscan_block().is_none());
    assert_eq!(verdict(&e, "q=block_needle").1, [930001]);
}

/// PO 14/10/2026: strata-compile writes HYPERSCAN_BLOCK by default;
/// --no-hs-block leaves it out.
#[test]
fn strata_compile_writes_the_block_section_by_default() {
    let dir = std::env::temp_dir().join(format!("hs-block-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let rules = dir.join("rules.yaml");
    std::fs::write(&rules, RULES).unwrap();
    let pol = dir.join("policies.yaml");
    std::fs::write(&pol, "policies: [{ name: example-api, mode: enforce }]").unwrap();
    let key = dir.join("seed");
    std::fs::write(&key, SEED).unwrap();
    let build = |extra: &[&str]| -> Vec<u8> {
        let out = dir.join("b.sbn");
        let st = std::process::Command::new(env!("CARGO_BIN_EXE_strata-compile"))
            .args([
                "--rules",
                rules.to_str().unwrap(),
                "--policies",
                pol.to_str().unwrap(),
            ])
            .args([
                "--key",
                key.to_str().unwrap(),
                "--version",
                "1",
                "--created-at",
                "0",
            ])
            .args(["--out", out.to_str().unwrap()])
            .args(extra)
            .status()
            .unwrap();
        assert!(st.success());
        std::fs::read(&out).unwrap()
    };
    let has_block = |b: &[u8]| sections(b).iter().any(|(k, _)| *k == kind::HYPERSCAN_BLOCK);
    assert!(has_block(&build(&[])), "on by default");
    assert!(has_block(&build(&["--hs-block"])));
    assert!(
        !has_block(&build(&["--no-hs-block"])),
        "--no-hs-block leaves it out"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
