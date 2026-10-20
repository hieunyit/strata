//! W19-R-01: rules on the country and ASN of the client address, compiled
//! with the networks of the countries and ASNs they name (section GEO).

use std::path::Path;
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::OK;
use strata_compiler::{Build, compile, from_yaml, geo_from_json, policies_from, rules_from_ir};

const SEED: [u8; 32] = [16; 32];

// documentation and test networks only
const GEO: &str = r#"{"version": "test", "countries": {
    "VN": ["198.51.100.0/25", "2001:db8:1::/48"],
    "US": ["203.0.113.0/24"],
    "FR": ["192.0.2.0/24"]
  }, "asns": {
    "64500": ["198.51.100.0/26"],
    "64501": ["203.0.113.128/25"]
  }}"#;

fn rule(id: u32, var: &str, op: &str, value: &str, negate: bool) -> String {
    format!(
        "  - id: {id}
    name: geo {id}
    layer: pre
    stage: request_headers
    match: {{ all: [ {{ targets: [{{ var: {var} }}], operator: {{ type: {op}, value: {value}, negate: {negate} }} }} ] }}
    score: 100
    severity: critical
    metadata: {{ source: strata, license: Apache-2.0, attack_type: other }}
"
    )
}

fn bundle(rules: &str, geo: Option<&str>) -> Result<Vec<u8>, String> {
    let doc =
        format!("ir_version: 1\nruleset: {{ name: example-geo, version: \"1\" }}\nrules:\n{rules}");
    let rules = rules_from_ir(&from_yaml(&doc).unwrap()).map_err(|e| e.to_string())?;
    let mut pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        Path::new("."),
    )
    .unwrap();
    if let Some(g) = geo {
        pol.geo = geo_from_json(g.as_bytes())?;
    }
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

fn engine(rules: &str) -> Arc<Engine> {
    let b = bundle(rules, Some(GEO)).unwrap();
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

fn rules_for(e: &Arc<Engine>, addr: &[u8]) -> Vec<u32> {
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-api");
    t.set_client_addr(addr);
    assert_eq!(t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1"), OK);
    assert_eq!(t.request_headers(&[(b"Host", b"api.example.test")]), OK);
    let v = t.verdict();
    let mut r = v.rules[..v.n_rules as usize].to_vec();
    r.sort();
    r
}

#[test]
fn block_by_country_and_asn() {
    let e = engine(
        &[
            rule(100901, "geo_country", "pm", "[US, FR]", false),
            rule(100902, "geo_asn", "streq", "\"64500\"", false),
        ]
        .concat(),
    );
    assert_eq!(rules_for(&e, b"203.0.113.7"), vec![100901]);
    assert_eq!(rules_for(&e, b"192.0.2.1"), vec![100901]);
    assert_eq!(rules_for(&e, b"198.51.100.10"), vec![100902]); // VN, AS64500
    assert!(rules_for(&e, b"198.51.100.100").is_empty()); // VN, another ASN
    assert!(rules_for(&e, b"8.8.8.8").is_empty()); // a country no rule names
    assert!(rules_for(&e, b"10.0.0.1").is_empty());
    assert_eq!(rules_for(&e, b"::ffff:203.0.113.7"), vec![100901]);
}

#[test]
fn allow_only_one_country() {
    // block every address outside VN, except local ones
    let e = engine(&rule(100903, "geo_country", "pm", "[VN, private]", true));
    assert!(rules_for(&e, b"198.51.100.1").is_empty());
    assert!(rules_for(&e, b"2001:db8:1::5").is_empty());
    assert!(rules_for(&e, b"192.168.1.10").is_empty());
    assert!(rules_for(&e, b"127.0.0.1").is_empty());
    assert_eq!(rules_for(&e, b"203.0.113.7"), vec![100903]); // US
    assert_eq!(rules_for(&e, b"8.8.8.8"), vec![100903]); // other
    // not an address: no value, the negated condition does not match
    assert!(rules_for(&e, b"unix:").is_empty());
}

#[test]
fn only_the_networks_named_are_packed() {
    let one = bundle(
        &rule(100901, "geo_country", "streq", "FR", false),
        Some(GEO),
    )
    .unwrap();
    let two = bundle(
        &rule(100901, "geo_country", "pm", "[FR, VN]", false),
        Some(GEO),
    )
    .unwrap();
    let none = bundle(&rule(100901, "method", "streq", "GET", false), Some(GEO)).unwrap();
    let has = |b: &[u8], s: &[u8]| b.windows(s.len()).any(|w| w == s);
    assert!(has(&one, b"SGE1") && has(&two, b"SGE1") && !has(&none, b"SGE1"));
    // VN's IPv4 network start, 198.51.100.0, little-endian
    let vn = u32::from(std::net::Ipv4Addr::new(198, 51, 100, 0)).to_le_bytes();
    assert!(!has(&one, &vn) && has(&two, &vn));
}

#[test]
fn refused() {
    for (rules, geo, why) in [
        (
            rule(100901, "geo_country", "streq", "DE", false),
            Some(GEO),
            "no networks",
        ),
        (
            rule(100901, "geo_country", "streq", "VN", false),
            None,
            "no networks",
        ),
        (
            rule(100901, "geo_country", "rx", "\"^V\"", false),
            Some(GEO),
            "streq or pm",
        ),
        (
            rule(100901, "geo_country", "streq", "vn", false),
            Some(GEO),
            "is not a Country",
        ),
        (
            rule(100901, "geo_asn", "streq", "AS64500", false),
            Some(GEO),
            "is not a Asn",
        ),
    ] {
        let err = bundle(&rules, geo).unwrap_err();
        assert!(err.contains(why), "{err}");
    }
    // overlapping countries in the networks given
    let bad = r#"{"countries": {"VN": ["198.51.100.0/24"], "US": ["198.51.100.0/25"]}}"#;
    assert!(
        bundle(
            &rule(100901, "geo_country", "pm", "[VN, US]", false),
            Some(bad)
        )
        .is_err()
    );
}
