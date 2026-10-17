use strata::{abi::*, ffi::*};
#[path = "../../tests/common/staging_fixture.rs"]
mod fixture;
fn s(b: &[u8]) -> strata_str_t {
    strata_str_t {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}
#[test]
fn signed_staging_through_c_abi() {
    let bytes = fixture::image(&[700011, 700013], true);
    let key = libstrata::bundle::public_key(&[7; 32]);
    let mut error = strata_err_t {
        code: 0,
        msg: [0; 256],
    };
    let engine =
        unsafe { strata_engine_map(bytes.as_ptr(), bytes.len(), key.as_ptr(), &mut error) };
    assert!(!engine.is_null(), "{}", error.code);
    for (policy, value, action) in [
        (
            b"example-api".as_slice(),
            b"first second".as_slice(),
            STRATA_ACTION_LOG,
        ),
        (b"example-api", b"alone", STRATA_ACTION_LOG),
        (b"example-web", b"first second", STRATA_ACTION_BLOCK),
        (b"example-web", b"alone", STRATA_ACTION_BLOCK),
    ] {
        let conn = strata_conn_t {
            client_addr: s(b"192.0.2.10"),
            client_port: 40000,
            _reserved: 0,
            flags: 0,
            node_id: s(b"example-node"),
            identity: s(b""),
            request_id: s(b""),
        };
        unsafe {
            let tx = strata_tx_new(engine, s(policy), &conn, 0);
            assert!(!tx.is_null());
            assert_eq!(
                strata_tx_request_line(tx, s(b"GET"), s(b"/"), s(b"/"), s(b""), s(b"HTTP/1.1")),
                STRATA_OK
            );
            let headers: Vec<_> = fixture::headers(value)
                .into_iter()
                .map(|(key, val)| strata_header_t {
                    key: s(key),
                    val: s(val),
                })
                .collect();
            assert_eq!(
                strata_tx_request_headers(tx, headers.as_ptr(), headers.len()),
                STRATA_OK
            );
            let mut v = strata_verdict_t::empty();
            strata_tx_verdict(tx, &mut v);
            assert_eq!(v.error, STRATA_OK);
            assert_eq!(v.action, action);
            assert!(v.n_rules > 0);
            strata_tx_free(tx);
        }
    }
    unsafe { strata_engine_release(engine) };
    for (index, offset, word) in [(0, 8, u32::MAX), (0, 8, 1001), (1, 0, 700011)] {
        let bytes = fixture::patch_rule(fixture::image(&[700011], true), index, offset, word);
        let rejected =
            unsafe { strata_engine_map(bytes.as_ptr(), bytes.len(), key.as_ptr(), &mut error) };
        assert!(rejected.is_null());
        assert_eq!(error.code, STRATA_E_BUNDLE);
    }
}
