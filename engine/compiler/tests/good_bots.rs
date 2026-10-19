//! W18-R-02: crawler ranges through a signed bundle (section GOOD_BOTS) to
//! the targets bot_claim / bot_verified and rule 500001.
use std::{path::Path, sync::Arc};

use libstrata::{
    bundle::public_key,
    engine::Engine,
    tx::Tx,
    verdict::{ACTION_ALLOW, ACTION_BLOCK, OK},
};
use strata_compiler::{
    Build, compile, from_yaml, good_bots_from_json, policies_from, rules_from_ir,
};

const SEED: [u8; 32] = [42; 32];
const RANGES: &[u8] = br#"{"version": "test", "crawlers": {
    "googlebot": ["66.249.64.0/27", "2001:4860:4801:10::/64"], "bingbot": ["157.55.39.0/24"]}}"#;

fn rule() -> String {
    let file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../rules/good-bots/500001-crawler-outside-its-published-ranges.yaml");
    let doc = from_yaml(&std::fs::read_to_string(file).unwrap()).unwrap();
    let ir = serde_json::json!({"ir_version": 1, "ruleset": {"name": "good-bots", "version": "1"},
        "rules": [doc["rule"].clone()]});
    ir.to_string()
}

fn bytes(ranges: Option<&[u8]>) -> Vec<u8> {
    let defs = rules_from_ir(&from_yaml(&rule()).unwrap()).unwrap();
    let mut pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        Path::new("."),
    )
    .unwrap();
    if let Some(r) = ranges {
        pol.good_bots = good_bots_from_json(r).unwrap();
    }
    compile(
        &defs,
        &pol,
        &Build {
            version: 18,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )
    .unwrap()
}

fn engine(b: Vec<u8>) -> Arc<Engine> {
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

fn send(e: &Arc<Engine>, ua: &[u8], addr: &[u8]) -> (u32, Vec<u32>) {
    let mut tx = Tx::new(Some(Arc::clone(e)), b"example-node", 0);
    tx.set_policy(b"example-api");
    tx.set_client_addr(addr);
    assert_eq!(tx.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1"), OK);
    assert_eq!(
        tx.request_headers(&[(b"Host", b"api.example.test"), (b"User-Agent", ua)]),
        OK
    );
    assert_eq!(tx.request_body_chunk(b"", true), OK);
    let v = tx.verdict();
    (v.action, v.rules[..v.n_rules as usize].to_vec())
}

const GOOGLE: &[u8] = b"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

#[test]
fn spoofed_crawlers_are_caught_and_real_ones_pass() {
    let e = engine(bytes(Some(RANGES)));
    assert_eq!(
        send(&e, GOOGLE, b"203.0.113.7"),
        (ACTION_BLOCK, vec![500001])
    );
    assert_eq!(send(&e, GOOGLE, b"66.249.64.31").0, ACTION_ALLOW);
    assert_eq!(
        send(&e, GOOGLE, b"66.249.64.32"),
        (ACTION_BLOCK, vec![500001])
    );
    assert_eq!(send(&e, GOOGLE, b"2001:4860:4801:10::7").0, ACTION_ALLOW);
    assert_eq!(send(&e, GOOGLE, b"::ffff:66.249.64.1").0, ACTION_ALLOW);
    assert_eq!(
        send(&e, b"Mozilla/5.0 (compatible; bingbot/2.0)", b"157.55.39.9").0,
        ACTION_ALLOW
    );
    assert_eq!(
        send(&e, b"Mozilla/5.0 (compatible; bingbot/2.0)", b"66.249.64.1").0,
        ACTION_BLOCK
    );
    // no ranges for Applebot in this bundle: unknown, not spoofed
    assert_eq!(
        send(&e, b"Mozilla/5.0 (Applebot/0.1)", b"203.0.113.7").0,
        ACTION_ALLOW
    );
    assert_eq!(
        send(&e, b"Mozilla/5.0 Firefox/130.0", b"203.0.113.7").0,
        ACTION_ALLOW
    );
}

#[test]
fn without_ranges_nothing_is_called_spoofed() {
    let e = engine(bytes(None));
    assert!(e.good_bots().is_empty());
    assert_eq!(send(&e, GOOGLE, b"203.0.113.7").0, ACTION_ALLOW);
}

#[test]
fn bad_ranges_are_refused_by_the_compiler() {
    for bad in [
        &br#"{"crawlers": {"googlebot": ["0.0.0.0/0"]}}"#[..],
        br#"{"crawlers": {"googlebot": ["66.249.64.1/27"]}}"#,
        br#"{"crawlers": {"Googlebot": ["66.249.64.0/27"]}}"#,
        br#"{"crawlers": {"googlebot": "66.249.64.0/27"}}"#,
        br#"{"version": "x"}"#,
        b"not json",
    ] {
        assert!(
            good_bots_from_json(bad).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}

#[test]
fn a_damaged_section_is_refused_by_the_engine() {
    let crawlers = good_bots_from_json(RANGES).unwrap();
    let section = libstrata::goodbots::encode(&crawlers).unwrap();
    assert!(libstrata::goodbots::parse(&section).is_ok());
    // the last 32 bytes: googlebot's IPv6 range; first after last
    let mut bad = section.clone();
    let n = bad.len();
    bad[n - 32..n - 16].copy_from_slice(&u128::MAX.to_le_bytes());
    bad[n - 16..].copy_from_slice(&0u128.to_le_bytes());
    assert!(libstrata::goodbots::parse(&bad).is_err());
    // two crawlers out of order
    let mut swapped = section.clone();
    let i = swapped.windows(7).position(|w| w == b"bingbot").unwrap();
    swapped[i..i + 7].copy_from_slice(b"zingbot");
    assert!(libstrata::goodbots::parse(&swapped).is_err());
}
