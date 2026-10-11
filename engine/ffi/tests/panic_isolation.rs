//! Panic isolation tests (W07-R-01):
//! Verifies catch_unwind wrapping across all 4 injection needles
//! (request line, request header, request body chunk, response body chunk)
//! and FFI entry points (strata_abi_version, strata_engine_info, strata_engine_retain, strata_tx_time_us).

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use strata::abi::*;
use strata::ffi::*;

const SEED: [u8; 32] = [3; 32];
const PANIC_NEEDLE: &[u8] = b"STRATA-TEST-PANIC";

fn s(b: &[u8]) -> strata_str_t {
    strata_str_t {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn create_engine() -> *mut EngineHandle {
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
    let e = unsafe {
        strata_engine_map(
            bundle.as_ptr(),
            bundle.len(),
            key.as_ptr(),
            &mut err as *mut strata_err_t,
        )
    };
    std::mem::forget(bundle);
    assert!(!e.is_null());
    e
}

fn create_tx(e: *mut EngineHandle) -> *mut TxHandle {
    unsafe { strata_tx_new(e, s(b"example-api"), std::ptr::null(), 0) }
}

#[test]
fn ffi_calls_never_unwind_on_null() {
    assert_ne!(strata_abi_version(), 0);

    let mut info = strata_engine_info_t::default();
    unsafe { strata_engine_info(std::ptr::null(), &mut info) };
    assert_eq!(info.version, 0);

    unsafe { strata_engine_retain(std::ptr::null_mut()) };
    assert_eq!(unsafe { strata_tx_time_us(std::ptr::null()) }, 0);
}

#[test]
fn panic_isolation_at_request_line() {
    let e = create_engine();
    let tx = create_tx(e);

    let mut raw_uri = Vec::from(b"/search?q=".as_slice());
    raw_uri.extend_from_slice(PANIC_NEEDLE);

    let rc = unsafe {
        strata_tx_request_line(
            tx,
            s(b"GET"),
            s(&raw_uri),
            s(&raw_uri),
            s(PANIC_NEEDLE),
            s(b"HTTP/1.1"),
        )
    };
    assert_eq!(
        rc, STRATA_E_INTERNAL,
        "must catch panic and return STRATA_E_INTERNAL"
    );

    let mut v = strata_verdict_t::empty();
    unsafe { strata_tx_verdict(tx, &mut v) };
    assert_eq!(v.error, STRATA_E_INTERNAL);

    let id = unsafe {
        std::ffi::CStr::from_ptr(v.block_id.as_ptr())
            .to_str()
            .unwrap()
    };
    assert!(
        id.starts_with("EVT-"),
        "Event ID must start with EVT-: {}",
        id
    );

    unsafe { strata_tx_free(tx) };
    unsafe { strata_engine_release(e) };
}

#[test]
fn panic_isolation_at_request_header() {
    let e = create_engine();
    let tx = create_tx(e);

    unsafe {
        strata_tx_request_line(
            tx,
            s(b"GET"),
            s(b"/api"),
            s(b"/api"),
            s(b""),
            s(b"HTTP/1.1"),
        );
    }

    let headers = [strata_header_t {
        key: s(b"X-Test"),
        val: s(PANIC_NEEDLE),
    }];

    let rc = unsafe { strata_tx_request_headers(tx, headers.as_ptr(), headers.len()) };
    assert_eq!(
        rc, STRATA_E_INTERNAL,
        "panic in header must return STRATA_E_INTERNAL"
    );

    let mut v = strata_verdict_t::empty();
    unsafe { strata_tx_verdict(tx, &mut v) };
    assert_eq!(v.error, STRATA_E_INTERNAL);

    unsafe { strata_tx_free(tx) };
    unsafe { strata_engine_release(e) };
}

#[test]
fn panic_isolation_at_request_body_chunk() {
    let e = create_engine();
    let tx = create_tx(e);

    unsafe {
        strata_tx_request_line(
            tx,
            s(b"POST"),
            s(b"/upload"),
            s(b"/upload"),
            s(b""),
            s(b"HTTP/1.1"),
        );
        strata_tx_request_headers(tx, std::ptr::null(), 0);
    }

    let rc =
        unsafe { strata_tx_request_body_chunk(tx, PANIC_NEEDLE.as_ptr(), PANIC_NEEDLE.len(), 1) };
    assert_eq!(
        rc, STRATA_E_INTERNAL,
        "panic in request body chunk must return STRATA_E_INTERNAL"
    );

    let mut v = strata_verdict_t::empty();
    unsafe { strata_tx_verdict(tx, &mut v) };
    assert_eq!(v.error, STRATA_E_INTERNAL);

    unsafe { strata_tx_free(tx) };
    unsafe { strata_engine_release(e) };
}

#[test]
fn panic_isolation_at_response_body_chunk() {
    let e = create_engine();
    let tx = create_tx(e);

    unsafe {
        strata_tx_request_line(tx, s(b"GET"), s(b"/"), s(b"/"), s(b""), s(b"HTTP/1.1"));
        strata_tx_request_headers(tx, std::ptr::null(), 0);
        strata_tx_request_body_chunk(tx, std::ptr::null(), 0, 1);
        strata_tx_response_headers(tx, 200, std::ptr::null(), 0);
    }

    let mut rewritten = strata_buf_t::empty();
    let rc = unsafe {
        strata_tx_response_body_chunk(
            tx,
            PANIC_NEEDLE.as_ptr(),
            PANIC_NEEDLE.len(),
            1,
            &mut rewritten,
        )
    };
    assert_eq!(
        rc, STRATA_E_INTERNAL,
        "panic in response body chunk must return STRATA_E_INTERNAL"
    );

    let mut v = strata_verdict_t::empty();
    unsafe { strata_tx_verdict(tx, &mut v) };
    assert_eq!(v.error, STRATA_E_INTERNAL);

    unsafe { strata_tx_free(tx) };
    unsafe { strata_engine_release(e) };
}
