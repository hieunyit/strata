//! Golden tests for event protobuf encoding (W07-R-03).
//!
//! Run with `UPDATE_GOLDEN=1 cargo test --test event_golden` to regenerate
//! `engine/tests/golden/events/*.bin`. By default, compares serialized bytes.
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use libstrata::block_id::{self, Kind};
use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use libstrata::engine::Engine;
use libstrata::event::{MAX_DATAGRAM, Match};
use libstrata::tx::Tx;
use libstrata::verdict::TXF_FORCE_SHADOW;

const SEED: [u8; 32] = [9; 32];

fn test_engine() -> Arc<Engine> {
    let spec = Spec {
        version: 1,
        created_at_ms: 0,
        flags: 0,
        policies: &[PolicySpec::new(
            "example-api",
            Mode::Enforce,
            Oversize::Pass,
        )],
        sections: &[],
    };
    let b = build(&spec, &SEED).unwrap();
    Arc::new(Engine::map(Box::new(b), &public_key(&SEED)).unwrap())
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/events")
}

fn check_or_update(name: &str, data: &[u8]) {
    let dir = golden_dir();
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.bin"));

    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        fs::write(&path, data).unwrap();
        eprintln!("Updated golden file: {}", path.display());
    } else {
        let expected = fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "Failed to read {}: {e}. Run with UPDATE_GOLDEN=1 to create.",
                path.display()
            )
        });
        assert_eq!(
            data,
            expected.as_slice(),
            "Mismatch for golden event scenario '{name}'"
        );
    }
}

fn fixed_id(kind: Kind, node: u16, seq: u32) -> [u8; block_id::ID_LEN] {
    block_id::format(kind, block_id::pack(1_700_000_000_000, node, seq))
}

#[test]
fn golden_blocked_scenario() {
    let engine = test_engine();
    let mut t = Tx::new(Some(engine), b"node-01", 0);
    t.set_policy(b"example-api");
    t.set_client_addr(b"192.0.2.1");
    t.set_identity(b"user:alice");
    t.set_request_id(b"req-12345");
    t.request_line(
        b"GET",
        b"/test?STRATA-TEST-BLOCK",
        b"/test",
        b"STRATA-TEST-BLOCK",
        b"HTTP/1.1",
    );
    t.request_header(b"Host", b"api.example.test");
    t.request_headers_done();
    t.set_id_for_test(fixed_id(Kind::Block, 1, 100));

    let ev = t
        .encode_event()
        .expect("blocked request must produce event");
    assert!(ev.len() <= MAX_DATAGRAM);
    check_or_update("blocked", &ev);
}

#[test]
fn golden_shadow_scenario() {
    let engine = test_engine();
    let mut t = Tx::new(Some(engine), b"node-shadow", TXF_FORCE_SHADOW);
    t.set_policy(b"example-api");
    t.set_client_addr(b"192.0.2.2");
    t.set_identity(b"user:bob");
    t.set_request_id(b"req-shadow-99");
    t.request_line(
        b"GET",
        b"/shadow?STRATA-TEST-BLOCK",
        b"/shadow",
        b"STRATA-TEST-BLOCK",
        b"HTTP/1.1",
    );
    t.request_header(b"Host", b"shadow.example.test");
    t.request_headers_done();
    t.set_id_for_test(fixed_id(Kind::Event, 2, 200));

    let ev = t.encode_event().expect("shadow request must produce event");
    assert!(ev.len() <= MAX_DATAGRAM);
    check_or_update("shadow", &ev);
}

#[test]
fn golden_engine_error_scenario() {
    let mut t = Tx::new(None, b"node-err", 0);
    t.set_client_addr(b"192.0.2.3");
    t.set_request_id(b"req-err-1");
    t.request_line(b"GET", b"/err", b"/err", b"", b"HTTP/1.1");
    t.request_headers_done();
    t.response_headers(500);
    t.set_id_for_test(fixed_id(Kind::Event, 3, 300));

    let ev = t.encode_event().expect("engine error must produce event");
    assert!(ev.len() <= MAX_DATAGRAM);
    check_or_update("engine_error", &ev);
}

#[test]
fn golden_long_snippet_scenario() {
    let engine = test_engine();
    let mut t = Tx::new(Some(engine), b"node-snip", 0);
    t.set_policy(b"example-api");
    t.set_client_addr(b"192.0.2.4");
    t.set_identity(b"user:carol");
    t.set_request_id(b"req-snip-123");
    t.request_line(b"POST", b"/submit", b"/submit", b"", b"HTTP/1.1");
    t.request_header(b"Host", b"snip.example.test");
    t.request_headers_done();

    // Trigger block with needle + CCCD in body
    let mut body = b"start STRATA-TEST-BLOCK id 079099001122 ".to_vec();
    body.extend_from_slice(&[b'X'; 200]);
    t.request_body_chunk(&body, true);
    t.set_id_for_test(fixed_id(Kind::Block, 4, 400));

    let ev = t
        .encode_event()
        .expect("blocked request must produce event");
    assert!(ev.len() <= MAX_DATAGRAM);
    check_or_update("long_snippet", &ev);
}

#[test]
fn golden_large_event_truncated_scenario() {
    // Event directly encoded with 60 matches of 128 bytes to test size bounding logic
    let matches: Vec<Match> = (0..60)
        .map(|i| Match {
            rule_id: 800_000 + i,
            layer: "managed".to_string(),
            field: format!("ARGS:field_{i}"),
            snippet: vec![b'Z'; 128],
        })
        .collect();

    let path = format!("/huge/{}", "P".repeat(2500));
    let id = fixed_id(Kind::Block, 5, 500);
    let id_str = String::from_utf8(id.to_vec()).unwrap();

    let ev = libstrata::event::Event {
        block_id: &id_str,
        time_unix_ms: 1_700_000_000_000,
        node_id: "node-huge",
        request_id: "req-huge-truncated",
        policy_id: "example-huge",
        bundle_version: 10,
        client_ip: "192.0.2.5",
        identity: "user:huge",
        method: "POST",
        host: "huge.example.test",
        path: &path,
        status: 403,
        action: libstrata::event::Action::Block,
        layer_scores: vec![("managed", 100), ("protocol", 50)],
        rule_ids: &[800001, 800002],
        matches,
    };

    let encoded = libstrata::event::encode_event(ev);
    assert!(encoded.len() <= MAX_DATAGRAM);
    check_or_update("large_event_truncated", &encoded);
}
