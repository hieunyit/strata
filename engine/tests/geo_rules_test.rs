//! Integration tests for W19-R-01: GeoIP / ASN policy restrictions and rule matching.

use std::sync::Arc;

use libstrata::bundle::{self, Mode, Oversize, PolicySpec, Spec};
use libstrata::engine::Engine;
use libstrata::geo::{
    CompactRangeV4, GeoAction, GeoResolver, PolicyGeoRestriction, encode_section,
};
use libstrata::rules::{self, CondDef, RuleDef, TargetDef, Value as RValue};
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, OK};

const SEED: [u8; 32] = [42; 32];

fn sample_compact_ranges() -> Vec<CompactRangeV4> {
    vec![
        // 1.1.1.0 - 1.1.1.255: US, Cloudflare ASN 13335
        CompactRangeV4 {
            start: 0x01010100,
            end: 0x010101FF,
            country: *b"US",
            asn: 13335,
        },
        // 14.225.0.0 - 14.225.255.255: VN, Viettel ASN 7552
        CompactRangeV4 {
            start: 0x0EE10000,
            end: 0x0EE1FFFF,
            country: *b"VN",
            asn: 7552,
        },
        // 175.45.176.0 - 175.45.176.255: KP, Ryugyong ASN 131279
        CompactRangeV4 {
            start: 0xAF2DB000,
            end: 0xAF2DB0FF,
            country: *b"KP",
            asn: 131279,
        },
        // 95.173.136.0 - 95.173.136.255: RU, Rostelecom ASN 12389
        CompactRangeV4 {
            start: 0x5FAD8800,
            end: 0x5FAD88FF,
            country: *b"RU",
            asn: 12389,
        },
    ]
}

#[test]
fn test_geo_restrictions_direct_resolution() {
    let restrictions = vec![PolicyGeoRestriction {
        enabled: true,
        default_action: GeoAction::Pass,
        action: GeoAction::Block,
        blocked_countries: vec![*b"KP"],
        blocked_asns: vec![13335],
        challenge_countries: vec![*b"RU"],
        challenge_asns: vec![7552],
    }];

    let geo = GeoResolver::with_compact(restrictions, sample_compact_ranges());

    // 1. Blocked country KP
    assert_eq!(
        geo.check_policy(0, "175.45.176.10"),
        Some((GeoAction::Block, "country in blocked_countries"))
    );

    // 2. Blocked ASN 13335
    assert_eq!(
        geo.check_policy(0, "1.1.1.1"),
        Some((GeoAction::Block, "ASN in blocked_asns"))
    );

    // 3. Challenged country RU
    assert_eq!(
        geo.check_policy(0, "95.173.136.5"),
        Some((GeoAction::Challenge, "country in challenge_countries"))
    );

    // 4. Challenged ASN 7552
    assert_eq!(
        geo.check_policy(0, "14.225.50.1"),
        Some((GeoAction::Challenge, "ASN in challenge_asns"))
    );

    // 5. Internal fast-path: 127.0.0.1, 10.0.0.1, 192.168.1.1 never blocked
    assert_eq!(geo.check_policy(0, "127.0.0.1"), None);
    assert_eq!(geo.check_policy(0, "10.0.5.1"), None);
    assert_eq!(geo.check_policy(0, "192.168.1.254"), None);
    assert_eq!(geo.check_policy(0, "::1"), None);

    let loc_internal = geo.resolve("127.0.0.1");
    assert!(loc_internal.is_internal);
    assert_eq!(&loc_internal.country_iso, b"IN");
}

#[test]
fn test_engine_geo_bundle_mapping() {
    let restrictions = vec![PolicyGeoRestriction {
        enabled: true,
        default_action: GeoAction::Pass,
        action: GeoAction::Block,
        blocked_countries: vec![*b"KP"],
        blocked_asns: vec![13335],
        challenge_countries: vec![],
        challenge_asns: vec![],
    }];

    let geo_sec = encode_section(&restrictions, &sample_compact_ranges(), None);

    let spec = Spec {
        version: 1901,
        created_at_ms: 1000,
        flags: 0,
        policies: &[PolicySpec::new(
            "geo-protected",
            Mode::Enforce,
            Oversize::Pass,
        )],
        sections: &[(bundle::kind::GEO, &geo_sec)],
    };

    let bundle_bytes = bundle::build(&spec, &SEED).unwrap();
    let engine = Engine::map(Box::new(bundle_bytes), &bundle::public_key(&SEED)).unwrap();

    let geo_opt = engine.geo();
    assert!(geo_opt.is_some(), "Engine must parse GEO section");
    let geo = geo_opt.unwrap();

    // Check resolution via Engine
    assert_eq!(
        geo.check_policy(0, "175.45.176.1"),
        Some((GeoAction::Block, "country in blocked_countries"))
    );
    assert_eq!(
        geo.check_policy(0, "1.1.1.1"),
        Some((GeoAction::Block, "ASN in blocked_asns"))
    );
    assert_eq!(geo.check_policy(0, "14.225.1.1"), None);
}

#[test]
fn test_geo_rules_evaluation_in_engine() {
    let geo_var = rules::code(rules::VARS, "geo_country").expect("geo_country var");
    let asn_var = rules::code(rules::VARS, "geo_asn").expect("geo_asn var");
    let geo_op = rules::code(rules::OPERATORS, "geo_match").expect("geo_match op");
    let asn_op = rules::code(rules::OPERATORS, "asn_match").expect("asn_match op");

    // Rule 800001: geo_match KP -> Block
    let rule_geo = RuleDef {
        id: 800001,
        name: "GeoCountryBlock".into(),
        layer: 0,
        stage: 0,
        severity: 0,
        score: 5,
        paranoia: 1,
        any: false,
        block_alone: true,
        signature: false,
        conditions: vec![CondDef {
            targets: vec![TargetDef {
                var: geo_var,
                key: None,
                exclude: vec![],
                count: false,
            }],
            transforms: vec![],
            op: geo_op,
            negate: false,
            multi_match: false,
            value: RValue::List(vec![b"KP".to_vec()]),
        }],
    };

    // Rule 800002: asn_match 13335 -> Block
    let rule_asn = RuleDef {
        id: 800002,
        name: "GeoAsnBlock".into(),
        layer: 0,
        stage: 0,
        severity: 0,
        score: 5,
        paranoia: 1,
        any: false,
        block_alone: true,
        signature: false,
        conditions: vec![CondDef {
            targets: vec![TargetDef {
                var: asn_var,
                key: None,
                exclude: vec![],
                count: false,
            }],
            transforms: vec![],
            op: asn_op,
            negate: false,
            multi_match: false,
            value: RValue::List(vec![b"13335".to_vec()]),
        }],
    };

    let rules_list = vec![rule_geo, rule_asn];
    let mut rule_sections = rules::encode(&rules_list, None);

    let geo_sec = encode_section(&[], &sample_compact_ranges(), None);
    rule_sections.push((bundle::kind::GEO, geo_sec));

    let refs: Vec<(u32, &[u8])> = rule_sections.iter().map(|(k, b)| (*k, &b[..])).collect();

    let spec = Spec {
        version: 1902,
        created_at_ms: 1000,
        flags: 0,
        policies: &[PolicySpec::new("waf-policy", Mode::Enforce, Oversize::Pass)],
        sections: &refs,
    };

    let bundle_bytes = bundle::build(&spec, &SEED).unwrap();
    let engine = Arc::new(Engine::map(Box::new(bundle_bytes), &bundle::public_key(&SEED)).unwrap());

    // 1. Traffic from North Korea (KP) -> should trigger rule 800001 and block!
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-01", 0);
        tx.set_policy(b"waf-policy");
        tx.set_client_addr(b"175.45.176.1");
        assert_eq!(tx.request_line(b"GET", b"/api/v1", b"/api/v1", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[(b"x-forwarded-for", b"175.45.176.1")]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_BLOCK, "Traffic from KP must be blocked");
        assert!(v.rules[..v.n_rules as usize].contains(&800001));
    }

    // 2. Traffic from Cloudflare ASN 13335 -> should trigger rule 800002 and block!
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-01", 0);
        tx.set_policy(b"waf-policy");
        tx.set_client_addr(b"1.1.1.1");
        assert_eq!(tx.request_line(b"GET", b"/api/v1", b"/api/v1", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[(b"x-forwarded-for", b"1.1.1.1")]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_BLOCK, "Traffic from ASN 13335 must be blocked");
        assert!(v.rules[..v.n_rules as usize].contains(&800002));
    }

    // 3. Traffic from Vietnam (VN, Viettel 7552) -> clean request, allowed!
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-01", 0);
        tx.set_policy(b"waf-policy");
        tx.set_client_addr(b"14.225.1.1");
        assert_eq!(tx.request_line(b"GET", b"/api/v1", b"/api/v1", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[(b"x-forwarded-for", b"14.225.1.1")]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_ALLOW, "Traffic from VN must be allowed");
    }

    // 4. Traffic from internal IP (127.0.0.1) -> clean request, allowed!
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-01", 0);
        tx.set_policy(b"waf-policy");
        tx.set_client_addr(b"127.0.0.1");
        assert_eq!(tx.request_line(b"GET", b"/api/v1", b"/api/v1", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[(b"x-forwarded-for", b"127.0.0.1")]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_ALLOW, "Traffic from internal IP must be allowed");
    }
}
