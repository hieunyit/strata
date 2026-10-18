use strata::abi::*;
use strata::ffi::*;
#[path = "../../tests/common/exception_fixture.rs"]
mod fixture;

fn s(bytes: &[u8]) -> strata_str_t {
    strata_str_t {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
    }
}

#[test]
fn scoped_exception_is_enforced_through_c_abi() {
    for field in ["ARGS:Name", "REQUEST_HEADERS:x-example-filter"] {
        let entries = [fixture::exception(field, u64::MAX / 2)];
        let bundle = fixture::image(&entries, true);
        let public = libstrata::bundle::public_key(&[7; 32]);
        let mut error = strata_err_t {
            code: 0,
            msg: [0; 256],
        };
        let engine = unsafe {
            strata_engine_map(bundle.as_ptr(), bundle.len(), public.as_ptr(), &mut error)
        };
        assert!(!engine.is_null(), "{}", error.code);
        for (body, extra_header, args_expected, header_expected) in [
            (
                &b"Name=1+OR+1%3D1"[..],
                false,
                STRATA_ACTION_ALLOW,
                STRATA_ACTION_BLOCK,
            ),
            (
                b"Name=1+OR+1%3D1&other=1+OR+1%3D1",
                false,
                STRATA_ACTION_BLOCK,
                STRATA_ACTION_BLOCK,
            ),
            (
                b"Name=1+OR+1%3D1",
                true,
                STRATA_ACTION_BLOCK,
                STRATA_ACTION_BLOCK,
            ),
            (
                b"Name=ordinary",
                true,
                STRATA_ACTION_BLOCK,
                STRATA_ACTION_ALLOW,
            ),
        ] {
            let expected = if field.starts_with("ARGS:") {
                args_expected
            } else {
                header_expected
            };
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
                let tx = strata_tx_new(engine, s(b"example-api"), &conn, 0);
                assert!(!tx.is_null());
                assert_eq!(
                    strata_tx_request_line(
                        tx,
                        s(b"POST"),
                        s(b"/v1/login"),
                        s(b"/v1/login"),
                        s(b""),
                        s(b"HTTP/1.1")
                    ),
                    STRATA_OK
                );
                let mut headers = vec![
                    strata_header_t {
                        key: s(b"Host"),
                        val: s(b"api.example.test"),
                    },
                    strata_header_t {
                        key: s(b"Content-Type"),
                        val: s(b"application/x-www-form-urlencoded"),
                    },
                ];
                if extra_header {
                    headers.push(strata_header_t {
                        key: s(b"X-Example-Filter"),
                        val: s(b"1 OR 1=1"),
                    });
                }
                assert_eq!(
                    strata_tx_request_headers(tx, headers.as_ptr(), headers.len()),
                    STRATA_OK
                );
                assert_eq!(
                    strata_tx_request_body_chunk(tx, body.as_ptr(), body.len(), 1),
                    STRATA_OK
                );
                let mut verdict = strata_verdict_t::empty();
                strata_tx_verdict(tx, &mut verdict);
                assert_eq!(verdict.error, STRATA_OK);
                strata_tx_free(tx);
                assert_eq!(verdict.action, expected);
            }
        }
        unsafe { strata_engine_release(engine) };
    }
}
