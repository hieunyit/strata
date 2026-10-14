//! W12-R-02: strata_engine_disable_rules through the C ABI. A disabled rule
//! no longer matches, an empty list switches it back on, and bad arguments
//! are refused.

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use strata::abi::*;
use strata::ffi::*;

const SEED: [u8; 32] = [6; 32];
// the stub rule of the test bundles (STRATA-TEST-BLOCK in the URI)
const STUB: u32 = 899_001;

fn s(b: &[u8]) -> strata_str_t {
    strata_str_t {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn verdict(e: *mut EngineHandle, uri: &[u8]) -> strata_verdict_t {
    unsafe {
        let tx = strata_tx_new(e, s(b"example-api"), std::ptr::null(), 0);
        strata_tx_request_line(tx, s(b"GET"), s(uri), s(uri), s(b""), s(b"HTTP/1.1"));
        strata_tx_request_headers(tx, std::ptr::null(), 0);
        let mut v = std::mem::zeroed::<strata_verdict_t>();
        strata_tx_verdict(tx, &mut v);
        strata_tx_free(tx);
        v
    }
}

#[test]
fn disabled_rules_stop_matching() {
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

    assert_eq!(strata_abi_version() >> 16, 1);
    assert_eq!(
        verdict(e, b"/STRATA-TEST-BLOCK").action,
        STRATA_ACTION_BLOCK
    );

    let ids = [123u32, STUB];
    assert_eq!(
        unsafe { strata_engine_disable_rules(e, ids.as_ptr(), ids.len()) },
        STRATA_OK
    );
    let v = verdict(e, b"/STRATA-TEST-BLOCK");
    assert_eq!((v.action, v.n_rules), (STRATA_ACTION_ALLOW, 0));

    // empty list: back on
    assert_eq!(
        unsafe { strata_engine_disable_rules(e, std::ptr::null(), 0) },
        STRATA_OK
    );
    assert_eq!(
        verdict(e, b"/STRATA-TEST-BLOCK").action,
        STRATA_ACTION_BLOCK
    );

    // bad arguments
    assert_eq!(
        unsafe { strata_engine_disable_rules(std::ptr::null(), ids.as_ptr(), 1) },
        STRATA_E_INVALID
    );
    assert_eq!(
        unsafe { strata_engine_disable_rules(e, std::ptr::null(), 1) },
        STRATA_E_INVALID
    );
    let many = vec![1u32; 4097];
    assert_eq!(
        unsafe { strata_engine_disable_rules(e, many.as_ptr(), many.len()) },
        STRATA_E_INVALID
    );
    // a refused call keeps the previous list (empty here)
    assert_eq!(
        verdict(e, b"/STRATA-TEST-BLOCK").action,
        STRATA_ACTION_BLOCK
    );

    unsafe { strata_engine_release(e) };
}
