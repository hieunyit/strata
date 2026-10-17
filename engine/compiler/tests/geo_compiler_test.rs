use std::path::Path;

use libstrata::bundle;
use libstrata::engine::Engine;
use strata_compiler::{Build, Options, compile_opts, policies_from, rules_from_ir};

const SEED: [u8; 32] = [7; 32];

#[test]
fn test_compiler_geo_policy_and_bundle_roundtrip() {
    let policy_json = serde_json::json!({
        "policies": [
            {
                "name": "strict-geo-policy",
                "mode": "enforce",
                "geo_restrictions": {
                    "enabled": true,
                    "default_action": "pass",
                    "blocked_countries": ["KP", "IR"],
                    "challenged_countries": ["RU"],
                    "blocked_asns": [13335],
                    "challenged_asns": [7552]
                }
            }
        ]
    });

    let pol = policies_from(&policy_json, Path::new(".")).expect("parse policies");
    assert_eq!(pol.policies.len(), 1);
    assert_eq!(pol.geo_restrictions.len(), 1);
    let gr = pol.geo_restrictions[0].as_ref().expect("has geo restriction");
    assert!(gr.enabled);
    assert_eq!(gr.blocked_countries, vec![*b"KP", *b"IR"]);
    assert_eq!(gr.challenge_countries, vec![*b"RU"]);
    assert_eq!(gr.blocked_asns, vec![13335]);
    assert_eq!(gr.challenge_asns, vec![7552]);

    let ir_json = serde_json::json!({
        "ir_version": 1,
        "ruleset": {
            "name": "custom",
            "version": "1.0.0"
        },
        "rules": [
            {
                "id": 850001,
                "name": "GeoCountryRule",
                "layer": "managed",
                "stage": "request_headers",
                "severity": "critical",
                "score": 5,
                "action_mode": "block_alone",
                "metadata": {
                    "source": "organization",
                    "license": "proprietary"
                },
                "match": {
                    "all": [
                        {
                            "targets": [
                                { "var": "geo_country" }
                            ],
                            "operator": {
                                "type": "geo_match",
                                "value": ["KP", "IR"]
                            }
                        }
                    ]
                }
            },
            {
                "id": 850002,
                "name": "GeoAsnRule",
                "layer": "managed",
                "stage": "request_headers",
                "severity": "critical",
                "score": 5,
                "action_mode": "block_alone",
                "metadata": {
                    "source": "organization",
                    "license": "proprietary"
                },
                "match": {
                    "all": [
                        {
                            "targets": [
                                { "var": "geo_asn" }
                            ],
                            "operator": {
                                "type": "asn_match",
                                "value": ["13335", "7552"]
                            }
                        }
                    ]
                }
            }
        ]
    });

    let rules = rules_from_ir(&ir_json).expect("parse rules IR");
    assert_eq!(rules.len(), 2);

    let build = Build {
        version: 1903,
        created_at_ms: 1000,
        rollback: false,
    };

    let bundle_bytes = compile_opts(&rules, &pol, &build, &SEED, Options::default())
        .expect("compile signed bundle");

    // Verify bundle maps cleanly in Engine
    let engine = Engine::map(Box::new(bundle_bytes), &bundle::public_key(&SEED))
        .expect("engine map bundle");

    let geo = engine.geo().expect("engine parsed GEO section");
    // Verify policy 0 restriction loaded into engine
    let pol_res = geo.check_policy(0, "127.0.0.1");
    assert_eq!(pol_res, None, "127.0.0.1 internal fast-path bypasses restriction");
}
