//! RV-N-02: JA4 of real ClientHellos (engine/tests/vectors/ja4-client-hellos.json:
//! curl, python-requests, Chrome, Firefox captured on 2026-10-19, reference
//! values from tshark 4.2.2), rules on `tls_ja4` through a signed bundle,
//! and the event field.
use std::{path::Path, sync::Arc};

use libstrata::{
    bundle::public_key,
    engine::Engine,
    ja4,
    tx::Tx,
    verdict::{ACTION_ALLOW, ACTION_BLOCK, OK},
};
use serde_json::Value;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [24; 32];

fn vectors() -> Vec<(String, String, Vec<u8>)> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/ja4-client-hellos.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| {
            let hex = x["client_hello"].as_str().unwrap();
            let hello = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            (
                x["client"].as_str().unwrap().to_string(),
                x["ja4"].as_str().unwrap().to_string(),
                hello,
            )
        })
        .collect()
}

#[test]
fn real_client_hellos_match_the_reference() {
    let vectors = vectors();
    assert_eq!(vectors.len(), 6);
    for (client, want, hello) in &vectors {
        let mut out = [0u8; ja4::LEN];
        ja4::fingerprint(hello, false, &mut out).unwrap_or_else(|| panic!("{client}"));
        assert_eq!(std::str::from_utf8(&out).unwrap(), want, "{client}");
        assert!(ja4::is_valid(&out));
        // the same hello over QUIC only changes the prefix
        ja4::fingerprint(hello, true, &mut out).unwrap();
        assert_eq!(out[0], b'q');
        assert_eq!(&out[1..], &want.as_bytes()[1..]);
        // every truncation is refused, never a wrong value
        for cut in [0, 1, 4, 40, hello.len() / 2, hello.len() - 1] {
            assert!(ja4::fingerprint(&hello[..cut], false, &mut out).is_none());
        }
    }
}

const IR: &str = r#"
ir_version: 1
ruleset: { name: example-ja4-test, version: "1" }
rules:
  - id: 800819
    name: Example JA4 block fixture
    layer: managed
    stage: request_headers
    score: 100
    severity: critical
    action_mode: block_alone
    match:
      all:
        - targets: [{ var: tls_ja4 }]
          operator: { type: streq, value: JA4 }
    metadata: { source: organization, license: Apache-2.0 }
"#;

fn engine(ir: &str) -> Arc<Engine> {
    let defs = rules_from_ir(&from_yaml(ir).unwrap()).unwrap();
    let policies = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        Path::new("."),
    )
    .unwrap();
    let build = Build {
        version: 24,
        created_at_ms: 0,
        rollback: false,
    };
    let bytes = compile(&defs, &policies, &build, &SEED).unwrap();
    Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&bytes)),
            &public_key(&SEED),
        )
        .unwrap(),
    )
}

fn request(engine: &Arc<Engine>, ja4: Option<&[u8]>) -> Tx {
    let mut tx = Tx::new(Some(Arc::clone(engine)), b"example-node", 0);
    tx.set_policy(b"example-api");
    if let Some(v) = ja4 {
        assert!(tx.set_ja4(v));
    }
    assert_eq!(tx.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1"), OK);
    assert_eq!(tx.request_headers(&[(b"Host", b"api.example.test")]), OK);
    assert_eq!(tx.request_body_chunk(b"", true), OK);
    tx
}

#[test]
fn rules_match_the_fingerprint_and_the_event_carries_it() {
    let vectors = vectors();
    let (curl, chrome) = (&vectors[0].1, &vectors[3].1);
    let plain = engine(&IR.replace("JA4", curl));

    let tx = request(&plain, Some(curl.as_bytes()));
    let v = tx.verdict();
    assert_eq!(v.action, ACTION_BLOCK);
    assert_eq!(v.rules[..v.n_rules as usize], [800819]);
    // event.proto field 24 (tag 0xc2 0x01), length 36, the fingerprint
    let ev = tx.encode_event().unwrap();
    let mut field = vec![0xc2, 0x01, 36];
    field.extend_from_slice(curl.as_bytes());
    assert!(
        ev.windows(field.len()).any(|w| w == field),
        "no ja4 in the event"
    );

    for other in [Some(chrome.as_bytes()), None] {
        let tx = request(&plain, other);
        assert_eq!(tx.verdict().action, ACTION_ALLOW);
        assert_eq!(tx.verdict().n_rules, 0);
    }

    // negated: a different fingerprint matches, no TLS (no target) does not
    let negated = engine(
        &IR.replace("JA4", curl)
            .replace("streq,", "streq, negate: true,"),
    );
    assert_eq!(
        request(&negated, Some(chrome.as_bytes())).verdict().action,
        ACTION_BLOCK
    );
    assert_eq!(request(&negated, None).verdict().action, ACTION_ALLOW);
}

#[test]
fn malformed_fingerprints_are_refused() {
    let mut tx = Tx::new(None, b"example-node", 0);
    for bad in [
        &b""[..],
        b"t13d1516h2_8daaf6152771",
        b"T13d1516h2_8daaf6152771_02713d6af862",
        b"t13d1516h2_8daaf6152771_02713d6af862x",
        b"t13d1516h2\n8daaf6152771_02713d6af862",
    ] {
        assert!(!tx.set_ja4(bad), "{}", bad.escape_ascii());
    }
    assert!(tx.set_ja4(b"t13d1516h2_8daaf6152771_02713d6af862"));
}
