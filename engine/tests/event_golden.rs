//! Golden tests for event protobuf encoding (W07-R-03).
//!
//! Run with `UPDATE_GOLDEN=1 cargo test --test event_golden` to regenerate
//! `engine/tests/golden/events/*.bin`. By default, compares serialized bytes.
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use libstrata::engine::Engine;
use libstrata::event::{Action, EventData, MAX_DATAGRAM, MatchData, encode, prepare_snippet};
use libstrata::tx::Tx;

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

#[test]
fn golden_blocked_scenario() {
    let matches = [MatchData {
        rule_id: 899001,
        layer: "managed",
        field: "URI",
        snippet: b"STRATA-TEST-BLOCK",
    }];
    let ev = EventData {
        block_id: "STR-8F3K-Q2VD-7XNM-A1PC",
        time_unix_ms: 1_700_000_000_000,
        node_id: "node-01",
        request_id: "req-12345",
        policy_id: "example-api",
        bundle_version: 1,
        client_ip: "192.0.2.1",
        identity: "user:alice",
        method: "GET",
        host: "api.example.test",
        path: "/test",
        status: 403,
        action: Action::Block,
        layer_scores: &[("anomaly", 100), ("managed", 100)],
        rule_ids: &[899001],
        matches: &matches,
    };

    let data = encode(&ev);
    assert!(data.len() <= MAX_DATAGRAM);
    check_or_update("blocked", &data);
}

#[test]
fn golden_shadow_scenario() {
    let matches = [MatchData {
        rule_id: 899001,
        layer: "managed",
        field: "URI",
        snippet: b"STRATA-TEST-BLOCK",
    }];
    let ev = EventData {
        block_id: "EVT-2A3B-4C5D-6E7F-8G9H",
        time_unix_ms: 1_700_000_000_000,
        node_id: "node-shadow",
        request_id: "req-shadow-99",
        policy_id: "example-api",
        bundle_version: 1,
        client_ip: "192.0.2.2",
        identity: "user:bob",
        method: "GET",
        host: "shadow.example.test",
        path: "/shadow",
        status: 0,
        action: Action::Log,
        layer_scores: &[("anomaly", 100), ("managed", 100)],
        rule_ids: &[899001],
        matches: &matches,
    };

    let data = encode(&ev);
    assert!(data.len() <= MAX_DATAGRAM);
    check_or_update("shadow", &data);
}

#[test]
fn golden_engine_error_scenario() {
    let ev = EventData {
        block_id: "EVT-3A3B-4C5D-6E7F-8G9H",
        time_unix_ms: 1_700_000_000_000,
        node_id: "node-err",
        request_id: "req-err-1",
        policy_id: "",
        bundle_version: 0,
        client_ip: "192.0.2.3",
        identity: "",
        method: "GET",
        host: "",
        path: "/err",
        status: 500,
        action: Action::Log,
        layer_scores: &[("anomaly", 0)],
        rule_ids: &[],
        matches: &[],
    };

    let data = encode(&ev);
    assert!(data.len() <= MAX_DATAGRAM);
    check_or_update("engine_error", &data);
}

#[test]
fn golden_long_snippet_scenario() {
    let raw_snippet = b"start STRATA-TEST-BLOCK id 079099001122 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    let masked_snippet = prepare_snippet("REQUEST_BODY", raw_snippet);
    let matches = [MatchData {
        rule_id: 899001,
        layer: "managed",
        field: "REQUEST_BODY",
        snippet: &masked_snippet,
    }];
    let ev = EventData {
        block_id: "STR-4A3B-4C5D-6E7F-8G9H",
        time_unix_ms: 1_700_000_000_000,
        node_id: "node-snip",
        request_id: "req-snip-123",
        policy_id: "example-api",
        bundle_version: 1,
        client_ip: "192.0.2.4",
        identity: "user:carol",
        method: "POST",
        host: "snip.example.test",
        path: "/submit",
        status: 403,
        action: Action::Block,
        layer_scores: &[("anomaly", 100), ("managed", 100)],
        rule_ids: &[899001],
        matches: &matches,
    };

    let data = encode(&ev);
    assert!(data.len() <= MAX_DATAGRAM);
    check_or_update("long_snippet", &data);
}

#[test]
fn golden_large_event_truncated_scenario() {
    static SNIPPET: [u8; 128] = [b'Z'; 128];
    let matches: Vec<MatchData<'static>> = (0..60)
        .map(|i| MatchData {
            rule_id: 800_000 + i as u32,
            layer: "managed",
            field: "ARGS:field",
            snippet: &SNIPPET,
        })
        .collect();

    let path = format!("/huge/{}", "P".repeat(2500));
    let ev = EventData {
        block_id: "STR-5A3B-4C5D-6E7F-8G9H",
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
        action: Action::Block,
        layer_scores: &[("anomaly", 150), ("managed", 100), ("protocol", 50)],
        rule_ids: &[800001, 800002],
        matches: &matches,
    };

    let data = encode(&ev);
    assert!(data.len() <= MAX_DATAGRAM);
    check_or_update("large_event_truncated", &data);
}

#[test]
fn test_tx_to_event_data_fields() {
    let engine = test_engine();
    let mut t = Tx::new(Some(engine), b"node-01", 0);
    t.set_policy(b"example-api");
    t.set_client_addr(b"192.0.2.1");
    t.set_identity(b"user:alice");
    t.set_request_id(b"req-12345");
    t.request_line(
        b"GET",
        b"/test?STRATA-TEST-BLOCK",
        b"/test?STRATA-TEST-BLOCK",
        b"STRATA-TEST-BLOCK",
        b"HTTP/1.1",
    );
    t.request_header(b"Host", b"api.example.test");
    t.request_headers_done();

    let ev_bytes = t
        .encode_event()
        .expect("blocked request must produce event");
    assert!(ev_bytes.len() <= MAX_DATAGRAM);
    assert!(t.verdict().id.is_some());
    let id_str = String::from_utf8_lossy(&t.verdict().id.unwrap()).to_string();
    assert!(id_str.starts_with("STR-"));
    // Ensure path in ev_bytes excludes query string
    assert!(ev_bytes.windows(5).any(|w| w == b"/test"));
}
