//! Response calls after the request budget ran out (W07-N-01): the status
//! still reaches the event, which the connector sends in its cleanup.

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use strata::abi::*;
use strata::ffi::*;

const SEED: [u8; 32] = [5; 32];

fn s(b: &[u8]) -> strata_str_t {
    strata_str_t {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

#[test]
fn status_reaches_the_event_after_budget() {
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
    let bundle = build(&spec, &SEED).unwrap();
    let key = public_key(&SEED);
    let mut err = strata_err_t {
        code: 0,
        msg: [0; 256],
    };
    let e = unsafe { strata_engine_map(bundle.as_ptr(), bundle.len(), key.as_ptr(), &mut err) };
    assert!(!e.is_null());

    // 1 µs: some call of the request runs out of it
    let tx = unsafe { strata_tx_new(e, s(b"example-api"), std::ptr::null(), 1) };
    let mut rc = unsafe {
        strata_tx_request_line(tx, s(b"POST"), s(b"/t"), s(b"/t"), s(b""), s(b"HTTP/1.1"))
    };
    if rc == STRATA_OK {
        rc = unsafe { strata_tx_request_headers(tx, std::ptr::null(), 0) };
    }
    let chunk = vec![b'a'; 64 * 1024];
    for _ in 0..1000 {
        if rc == STRATA_E_BUDGET {
            break;
        }
        rc = unsafe { strata_tx_request_body_chunk(tx, chunk.as_ptr(), chunk.len(), 0) };
    }
    assert_eq!(rc, STRATA_E_BUDGET);

    let mut v = strata_verdict_t::empty();
    unsafe { strata_tx_verdict(tx, &mut v) };
    assert_eq!(v.error, STRATA_E_BUDGET);

    let rc = unsafe { strata_tx_response_headers(tx, 503, std::ptr::null(), 0) };
    assert_eq!(
        rc, STRATA_OK,
        "response calls are not stopped by the request budget"
    );

    let mut ev = [0u8; 8192];
    let n = unsafe { strata_tx_event(tx, ev.as_mut_ptr(), ev.len()) };
    assert!(n > 0);
    // field 12 (status), varint 503
    assert!(
        ev[..n].windows(3).any(|w| w == [0x60, 0xf7, 0x03]),
        "event carries status 503"
    );

    unsafe { strata_tx_free(tx) };
    unsafe { strata_engine_release(e) };
}
