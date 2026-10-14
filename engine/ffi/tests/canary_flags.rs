//! W12-G2-01: the verdict says which side of an enforce canary the request
//! fell on (STRATA_VF_CANARY / STRATA_VF_CANARY_SHADOW, ABI 1.4), so the
//! connector can count the two groups. A policy without canary sets
//! neither.

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use strata::abi::*;
use strata::ffi::*;

const SEED: [u8; 32] = [7; 32];

fn s(b: &[u8]) -> strata_str_t {
    strata_str_t {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn flags(e: *mut EngineHandle, policy: &[u8], addr: &str) -> (u32, u16) {
    let conn = strata_conn_t {
        client_addr: s(addr.as_bytes()),
        client_port: 40000,
        _reserved: 0,
        flags: 0,
        node_id: s(b"edge-1"),
        identity: s(b""),
        request_id: s(b""),
    };
    unsafe {
        let tx = strata_tx_new(e, s(policy), &conn, 0);
        let uri = b"/STRATA-TEST-BLOCK";
        strata_tx_request_line(tx, s(b"GET"), s(uri), s(uri), s(b""), s(b"HTTP/1.1"));
        strata_tx_request_headers(tx, std::ptr::null(), 0);
        let mut v = std::mem::zeroed::<strata_verdict_t>();
        strata_tx_verdict(tx, &mut v);
        strata_tx_free(tx);
        (
            v.action,
            v.flags & (STRATA_VF_CANARY | STRATA_VF_CANARY_SHADOW),
        )
    }
}

#[test]
fn verdict_flags_name_the_canary_group() {
    let policies = [
        PolicySpec {
            canary: 2_000, // 20%
            ..PolicySpec::new("example-canary", Mode::Enforce, Oversize::Pass)
        },
        PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass),
    ];
    let spec = Spec {
        version: 1,
        created_at_ms: 0,
        flags: 0,
        policies: &policies,
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

    let (mut canary, mut shadow) = (0, 0);
    for i in 0..500 {
        let addr = format!("198.51.{}.{}", i / 256, i % 256);
        match flags(e, b"example-canary", &addr) {
            (STRATA_ACTION_BLOCK, STRATA_VF_CANARY) => canary += 1,
            (STRATA_ACTION_LOG, STRATA_VF_CANARY_SHADOW) => shadow += 1,
            other => panic!("{addr}: {other:?}"),
        }
        assert_eq!(flags(e, b"example-api", &addr), (STRATA_ACTION_BLOCK, 0));
        assert_eq!(flags(e, b"no-such-policy", &addr).1, 0);
    }
    assert!((60..140).contains(&canary), "20% canary: {canary}/500");
    assert_eq!(canary + shadow, 500);
    unsafe { strata_engine_release(e) };
}
