//! Integration tests for Challenge, Identity Rate Limiting & Cluster Sync (RV-R-04).
//!
//! Required criteria:
//! - Client without JS execution is challenged (status 403 with challenge page).
//! - Headless browser solves challenge (sets cookie), passes challenge, then gets
//!   rate limited by identity (status 429).
//! - Forged or expired challenge cookie is strictly rejected.
//! - Cluster-wide counter sync aggregates attempts across nodes.
#![forbid(unsafe_code)]

use std::sync::Arc;
use libstrata::bundle::{self, Mode, Oversize, PolicySpec, Spec};
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_CHALLENGE};

const SEED: [u8; 32] = [42; 32];

fn make_test_engine() -> Arc<Engine> {
    let spec = Spec {
        version: 1,
        created_at_ms: 1000,
        flags: 0,
        policies: &[PolicySpec::new("login-policy", Mode::Enforce, Oversize::Pass)],
        sections: &[],
    };
    let bundle_bytes = bundle::build(&spec, &SEED).unwrap();
    Arc::new(Engine::map(Box::new(bundle_bytes), &bundle::public_key(&SEED)).unwrap())
}

fn parse_token_from_html(html: &str) -> Option<String> {
    // Looks for `var c = "__strata_challenge=" + "TOKEN" + "; ..."`
    let marker = "\"__strata_challenge=\" + \"";
    let start = html.find(marker)? + marker.len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_string())
}

#[test]
fn test_client_without_js_is_challenged() {
    let engine = make_test_engine();
    let mut tx = Tx::new(Some(engine), b"node-1", 0);
    tx.set_client_addr(b"203.0.113.195");
    tx.set_identity(b"user:attacker");

    assert_eq!(tx.request_line(b"POST", b"/login", b"/login", b"", b"HTTP/1.1"), 0);
    assert_eq!(tx.request_header(b"Host", b"example.test"), 0);
    assert_eq!(tx.request_header(b"User-Agent", b"Python-requests/2.31.0"), 0);
    assert_eq!(tx.request_headers_done(), 0);

    // Trigger challenge (e.g. from geo/bot/anomaly score rule)
    tx.trigger_challenge();

    let v = tx.verdict();
    assert_eq!(v.action, ACTION_CHALLENGE, "client without JS execution must receive ACTION_CHALLENGE");
    assert_eq!(v.status, 403);
    assert!(!tx.is_challenge_cleared());

    // Verify challenge page is generated with JS challenge script
    let page = tx.challenge_page().expect("challenge page should be generated");
    assert!(page.contains("__strata_challenge="));
    assert!(page.contains("window.location.reload()"));
    assert!(page.contains("<noscript><p>JavaScript is required"));
}

#[test]
fn test_headless_browser_solves_challenge_and_gets_rate_limited() {
    let engine = make_test_engine();
    let now = 1700000000u64;

    // --- STEP 1: Headless browser makes initial request, receives challenge ---
    let mut tx1 = Tx::new(Some(engine.clone()), b"node-1", 0);
    tx1.set_time_for_test(now);
    tx1.set_client_addr(b"198.51.100.50");
    tx1.set_identity(b"user:credential_stuffer");
    assert_eq!(tx1.request_line(b"POST", b"/login", b"/login", b"", b"HTTP/1.1"), 0);
    assert_eq!(tx1.request_headers_done(), 0);
    tx1.trigger_challenge();

    let v1 = tx1.verdict();
    assert_eq!(v1.action, ACTION_CHALLENGE);

    let html = tx1.challenge_page().expect("challenge page");
    let token = parse_token_from_html(&html).expect("must parse challenge token from page");

    // --- STEP 2: Headless browser executes JS, sets cookie, and reloads ---
    let mut tx2 = Tx::new(Some(engine.clone()), b"node-1", 0);
    tx2.set_time_for_test(now + 1);
    tx2.set_client_addr(b"198.51.100.50");
    tx2.set_identity(b"user:credential_stuffer");
    assert_eq!(tx2.request_line(b"POST", b"/login", b"/login", b"", b"HTTP/1.1"), 0);
    assert_eq!(
        tx2.request_header(
            b"Cookie",
            format!("session=xyz; __strata_challenge={token}").as_bytes()
        ),
        0
    );
    assert_eq!(tx2.request_headers_done(), 0);
    tx2.trigger_challenge();

    // Challenge is solved and cleared!
    assert!(tx2.is_challenge_cleared(), "valid challenge cookie must clear challenge");
    assert_eq!(tx2.verdict().action, ACTION_ALLOW, "request should now be allowed past challenge");

    // --- STEP 3: Headless browser attempts credential stuffing (rate limited by identity) ---
    // Limit: 3 requests per 60s
    let limit = 3;
    let window_secs = 60;

    // Check rate limit on tx2: count = 1
    tx2.check_rate_limit(limit, window_secs);
    assert_eq!(tx2.verdict().action, ACTION_ALLOW);

    // Request 2
    let mut tx3 = Tx::new(Some(engine.clone()), b"node-1", 0);
    tx3.set_time_for_test(now + 2);
    tx3.set_client_addr(b"198.51.100.50");
    tx3.set_identity(b"user:credential_stuffer");
    tx3.set_challenge_cleared(true);
    tx3.check_rate_limit(limit, window_secs);
    assert_eq!(tx3.verdict().action, ACTION_ALLOW);

    // Request 3 (reaches limit)
    let mut tx4 = Tx::new(Some(engine.clone()), b"node-1", 0);
    tx4.set_time_for_test(now + 3);
    tx4.set_client_addr(b"198.51.100.50");
    tx4.set_identity(b"user:credential_stuffer");
    tx4.set_challenge_cleared(true);
    tx4.check_rate_limit(limit, window_secs);
    assert_eq!(tx4.verdict().action, ACTION_ALLOW);

    // Request 4: Exceeds limit -> RATE LIMITED (Status 429)
    let mut tx5 = Tx::new(Some(engine.clone()), b"node-1", 0);
    tx5.set_time_for_test(now + 4);
    tx5.set_client_addr(b"198.51.100.50");
    tx5.set_identity(b"user:credential_stuffer");
    tx5.set_challenge_cleared(true);
    tx5.check_rate_limit(limit, window_secs);

    let v5 = tx5.verdict();
    assert_eq!(v5.action, ACTION_BLOCK, "excessive requests must be blocked by rate limit");
    assert_eq!(v5.status, 429, "rate limited request must return HTTP 429");
    assert!(v5.rules.contains(&libstrata::tx::RULE_RATE_LIMIT));
}

#[test]
fn test_forged_cookie_is_rejected() {
    let engine = make_test_engine();
    let mut tx = Tx::new(Some(engine), b"node-1", 0);
    tx.set_client_addr(b"203.0.113.10");
    tx.set_identity(b"alice");

    assert_eq!(tx.request_line(b"GET", b"/protected", b"/protected", b"", b"HTTP/1.1"), 0);
    // Send forged HMAC signature
    assert_eq!(
        tx.request_header(
            b"Cookie",
            b"__strata_challenge=v1.1700000000.1700001800.0000000012345678.00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        ),
        0
    );
    assert_eq!(tx.request_headers_done(), 0);
    tx.trigger_challenge();

    assert!(!tx.is_challenge_cleared(), "forged cookie must NOT clear challenge");
    assert_eq!(tx.verdict().action, ACTION_CHALLENGE);
    assert_eq!(tx.verdict().status, 403);
}

#[test]
fn test_expired_cookie_is_rejected() {
    let engine = make_test_engine();
    let now = 1700000000u64;

    // Generate valid token at `now` with TTL 1800s
    let token = libstrata::challenge::generate_token(
        &libstrata::challenge::DEFAULT_CHALLENGE_KEY,
        "203.0.113.10",
        "alice",
        now,
        1800,
        999,
    );

    // Present token at `now + 1801` (expired)
    let mut tx = Tx::new(Some(engine), b"node-1", 0);
    tx.set_time_for_test(now + 1801);
    tx.set_client_addr(b"203.0.113.10");
    tx.set_identity(b"alice");

    assert_eq!(tx.request_line(b"GET", b"/protected", b"/protected", b"", b"HTTP/1.1"), 0);
    assert_eq!(
        tx.request_header(b"Cookie", format!("__strata_challenge={token}").as_bytes()),
        0
    );
    assert_eq!(tx.request_headers_done(), 0);
    tx.trigger_challenge();

    assert!(!tx.is_challenge_cleared(), "expired cookie must NOT clear challenge");
    assert_eq!(tx.verdict().action, ACTION_CHALLENGE);
}

#[test]
fn test_cluster_wide_rate_limiting_sync() {
    let engine_node_a = make_test_engine();
    let engine_node_b = make_test_engine();
    let now = 1700000000u64;
    let limit = 5;
    let window = 60;

    // Node A receives 3 login attempts from "user:attacker"
    for i in 0..3 {
        let mut tx = Tx::new(Some(engine_node_a.clone()), b"node-a", 0);
        tx.set_time_for_test(now + i);
        tx.set_identity(b"user:attacker");
        tx.check_rate_limit(limit, window);
        assert_eq!(tx.verdict().action, ACTION_ALLOW);
    }

    // Node B receives 2 login attempts from "user:attacker"
    for i in 0..2 {
        let mut tx = Tx::new(Some(engine_node_b.clone()), b"node-b", 0);
        tx.set_time_for_test(now + i);
        tx.set_identity(b"user:attacker");
        tx.check_rate_limit(limit, window);
        assert_eq!(tx.verdict().action, ACTION_ALLOW);
    }

    // Sync from Node A to Node B (P-01 §3 Tier 2)
    let sync_batch = engine_node_a.rate_limiter().export_sync(now, window);
    assert_eq!(sync_batch.len(), 1);
    assert_eq!(sync_batch[0].count, 3);

    engine_node_b.rate_limiter().import_cluster_sync(&sync_batch, now, window);

    // Node B count is now 2 + 3 = 5 (at limit)
    assert_eq!(engine_node_b.rate_limiter().get_count(b"user:attacker", now, window), 5);

    // Next request on Node B exceeds cluster limit (5 + 1 = 6 > 5) -> BLOCKED (429)
    let mut tx_over = Tx::new(Some(engine_node_b.clone()), b"node-b", 0);
    tx_over.set_time_for_test(now + 10);
    tx_over.set_identity(b"user:attacker");
    tx_over.check_rate_limit(limit, window);

    let v = tx_over.verdict();
    assert_eq!(v.action, ACTION_BLOCK);
    assert_eq!(v.status, 429, "cluster-wide rate limit must enforce HTTP 429 across all nodes");
}
