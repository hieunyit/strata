//! W18-R-01: CRS 920640 (body without Content-Type), imported since
//! REQUEST_BODY_LENGTH maps to request_body with transformation length.
//! The upstream go-ftw tests send raw headers (unconverted, see
//! docs/crs-ftw-unconverted.md): their cases, through the whole imported
//! 920 file and a signed bundle.
//!
//! With a Content-Length, 920340 (same CRS check on the header, score 100)
//! already blocks at request_headers, and Strata decides as soon as the
//! threshold is reached, so 920640 is not reached; ModSecurity scores both
//! at the end of phase 2. 920640 adds the chunked bodies (no
//! Content-Length), which 920340 cannot see.
use std::{path::Path, sync::Arc};

use libstrata::{
    bundle::public_key,
    engine::Engine,
    tx::Tx,
    verdict::{ACTION_ALLOW, ACTION_BLOCK, OK},
};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [64; 32];

fn engine() -> Arc<Engine> {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/crs/920-protocol.yaml");
    let defs = rules_from_ir(&from_yaml(&std::fs::read_to_string(file).unwrap()).unwrap()).unwrap();
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

/// (action, rules) of a request; chunked: Transfer-Encoding instead of
/// Content-Length.
fn send(
    e: &Arc<Engine>,
    method: &[u8],
    ct: Option<&[u8]>,
    body: &[u8],
    chunked: bool,
) -> (u32, Vec<u32>) {
    let mut tx = Tx::new(Some(Arc::clone(e)), b"example-node", 0);
    tx.set_policy(b"example-api");
    assert_eq!(tx.request_line(method, b"/", b"/", b"", b"HTTP/1.1"), OK);
    let len = body.len().to_string();
    let mut h: Vec<(&[u8], &[u8])> = vec![
        (b"Host", b"localhost"),
        (b"User-Agent", b"OWASP CRS test agent"),
    ];
    if chunked {
        h.push((b"Transfer-Encoding", b"chunked"));
    } else if method != b"GET" {
        h.push((b"Content-Length", len.as_bytes()));
    }
    if let Some(ct) = ct {
        h.push((b"Content-Type", ct));
    }
    assert_eq!(tx.request_headers(&h), OK);
    assert_eq!(tx.request_body_chunk(body, true), OK);
    let v = tx.verdict();
    (v.action, v.rules[..v.n_rules as usize].to_vec())
}

#[test]
fn upstream_cases() {
    let e = engine();
    let json = br#"{"id_order":"select(sleep(10));"}"#;
    let xml = br#"<?xml version="1.0"?><data><id>123</id></data>"#;
    // body without Content-Type: blocked, by 920340 (Content-Length) or
    // 920640 (chunked)
    for (name, method, body) in [
        ("920640-1", &b"POST"[..], &json[..]),
        ("920640-6", b"POST", b"test_data"),
        ("920640-7", b"POST", xml),
        ("920640-8", b"PUT", br#"{"name":"updated"}"#),
        (
            "920640-10",
            b"PATCH",
            br#"{"op":"replace","path":"/name","value":"test"}"#,
        ),
    ] {
        let (action, rules) = send(&e, method, None, body, false);
        assert_eq!(action, ACTION_BLOCK, "{name}: {rules:?}");
        assert!(rules.contains(&920340), "{name}: {rules:?}");
        let (action, rules) = send(&e, method, None, body, true);
        assert_eq!(action, ACTION_BLOCK, "{name} chunked: {rules:?}");
        assert!(
            rules.contains(&920640) && !rules.contains(&920340),
            "{name} chunked: {rules:?}"
        );
    }
    // no body, or a Content-Type (empty included: the header is there)
    for (name, method, ct, body, chunked) in [
        (
            "920640-2",
            &b"POST"[..],
            Some(&b"application/json"[..]),
            &json[..],
            false,
        ),
        (
            "920640-2 chunked",
            b"POST",
            Some(b"application/json"),
            json,
            true,
        ),
        ("920640-3", b"GET", None, b"", false),
        ("920640-4", b"POST", Some(b""), json, false),
        ("920640-4 chunked", b"POST", Some(b""), json, true),
        ("920640-9", b"POST", None, b"", false),
        ("920640-9 chunked", b"POST", None, b"", true),
    ] {
        let (_, rules) = send(&e, method, ct, body, chunked);
        assert!(
            !rules.contains(&920640) && !rules.contains(&920340),
            "{name}: {rules:?}"
        );
    }
    let (action, _) = send(&e, b"GET", None, b"", false);
    assert_eq!(action, ACTION_ALLOW);
}
