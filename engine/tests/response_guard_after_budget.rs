use std::sync::Arc;

use libstrata::bundle::{Mode, Oversize, PolicySpec, Response, Spec, build, public_key};
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, E_BUDGET, OK};

const SEED: [u8; 32] = [8; 32];
const JWT_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
const CCCD_NUM: &str = "001099012345";

fn engine_with_guard() -> Arc<Engine> {
    let guard_policy = PolicySpec {
        response: Response(Response::GUARD_CCCD | Response::GUARD_JWT),
        ..PolicySpec::new("guard-api", Mode::Enforce, Oversize::Pass)
    };
    let spec = Spec {
        version: 1,
        created_at_ms: 0,
        flags: 0,
        policies: &[guard_policy],
        sections: &[],
    };
    let b = build(&spec, &SEED).unwrap();
    Arc::new(Engine::map(Box::new(b), &public_key(&SEED)).unwrap())
}

#[test]
fn response_guard_masks_after_request_budget_timeout() {
    let engine = engine_with_guard();
    let mut tx = Tx::new(Some(engine), b"node-01", 0);
    tx.set_policy(b"guard-api");
    // Set 1 microsecond budget
    tx.set_budget(1);

    assert_eq!(
        tx.request_line(b"POST", b"/checkout", b"/checkout", b"", b"HTTP/1.1"),
        OK
    );

    // Timeout during request inspection
    assert!(tx.budget_enter().is_ok());
    std::thread::sleep(std::time::Duration::from_millis(1));
    tx.budget_exit();

    let rc = tx.request_headers(&[(b"Content-Length", b"10")]);
    assert_eq!(rc, E_BUDGET, "request should fail with E_BUDGET");

    // Verdict at end of request: error is E_BUDGET, action is ALLOW (fail-open), but need_response is TRUE!
    let v_req = tx.verdict();
    assert_eq!(v_req.error, E_BUDGET);
    assert_eq!(v_req.action, ACTION_ALLOW);
    assert!(
        v_req.need_response,
        "need_response must be true even after budget timeout when data guard is configured"
    );

    // Response arrives from upstream
    let rc_resp_hdr = tx.response_headers(200);
    assert_eq!(
        rc_resp_hdr, OK,
        "response_headers must succeed with OK to allow masking"
    );

    // Send response body containing CCCD and JWT
    let body = format!("user cccd: {} and token: {}", CCCD_NUM, JWT_TOKEN);
    let (rc_body, rewritten) = tx.response_body_chunk(body.as_bytes(), true);
    assert_eq!(rc_body, OK, "response_body_chunk must return OK");
    assert!(
        rewritten.is_some(),
        "response body must be rewritten/masked"
    );

    let rewritten_val = rewritten.unwrap();
    let rewritten_str = String::from_utf8_lossy(&rewritten_val);
    assert!(
        !rewritten_str.contains(CCCD_NUM),
        "CCCD must not leak: {}",
        rewritten_str
    );
    assert!(
        !rewritten_str.contains(JWT_TOKEN),
        "JWT must not leak: {}",
        rewritten_str
    );
    assert!(
        rewritten_str.contains("************"),
        "CCCD should be replaced with asterisks"
    );
    assert!(
        rewritten_str.contains("***"),
        "JWT should be replaced with asterisks"
    );

    // Verdict after response: sticky error E_BUDGET remains in verdict
    let v_final = tx.verdict();
    assert_eq!(
        v_final.error, E_BUDGET,
        "verdict.error must remain E_BUDGET"
    );
    assert!(v_final.id.is_some());
    let id_bytes = v_final.id.unwrap();
    let id_str = String::from_utf8_lossy(&id_bytes);
    assert!(
        id_str.starts_with("EVT-"),
        "Event ID must start with EVT-: {}",
        id_str
    );
}
