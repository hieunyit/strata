//! Diagnostic only: first/warm C ABI requests, no configured CPU limit.
//! Profile instructions with --toggle-collect=profile_first_request or
//! --toggle-collect=profile_warm_request. Timings under instrumentation are not SLOs.
use std::time::Instant;
use strata::abi::*;
use strata::ffi::*;

fn s(b: &[u8]) -> strata_str_t {
    strata_str_t {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}
unsafe fn request(tx: *mut TxHandle) {
    unsafe {
        assert_eq!(
            strata_tx_request_line(
                tx,
                s(b"GET"),
                s(b"/probe?q=ordinary"),
                s(b"/probe"),
                s(b"q=ordinary"),
                s(b"HTTP/1.1")
            ),
            STRATA_OK
        );
        let headers = [
            strata_header_t {
                key: s(b"Host"),
                val: s(b"api.example.test"),
            },
            strata_header_t {
                key: s(b"User-Agent"),
                val: s(b"example-client/1"),
            },
            strata_header_t {
                key: s(b"Connection"),
                val: s(b"close"),
            },
            strata_header_t {
                key: s(b"Accept-Encoding"),
                val: s(b"identity"),
            },
        ];
        assert_eq!(
            strata_tx_request_headers(tx, headers.as_ptr(), headers.len()),
            STRATA_OK
        );
        assert_eq!(
            strata_tx_request_body_chunk(tx, std::ptr::null(), 0, 1),
            STRATA_OK
        );
    }
}
/// # Safety
/// tx must be a live transaction created by this diagnostic.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe fn profile_first_request(tx: *mut TxHandle) {
    std::hint::black_box(1);
    unsafe { request(tx) }
}
/// # Safety
/// tx must be a live transaction created by this diagnostic.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe fn profile_warm_request(tx: *mut TxHandle) {
    std::hint::black_box(2);
    unsafe { request(tx) }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "bundle.sbn public.key");
    let bundle = strata_hs::AlignedBuf::from_bytes(&std::fs::read(&args[1]).unwrap());
    let public = std::fs::read(&args[2]).unwrap();
    assert_eq!(public.len(), 32);
    let mut err = strata_err_t {
        code: 0,
        msg: [0; 256],
    };
    let engine = unsafe {
        strata_engine_map(
            bundle.as_ref().as_ptr(),
            bundle.as_ref().len(),
            public.as_ptr(),
            &mut err,
        )
    };
    assert!(!engine.is_null(), "map {}", err.code);
    libstrata::rulecost::set_sample_every(1);
    for first in [true, false] {
        let conn = strata_conn_t {
            client_addr: s(b"127.0.0.1"),
            client_port: 40000,
            _reserved: 0,
            flags: 0,
            node_id: s(b"cold-profile"),
            identity: s(b""),
            request_id: s(b""),
        };
        let tx = unsafe { strata_tx_new(engine, s(b"example-api"), &conn, 0) };
        assert!(!tx.is_null());
        let start = Instant::now();
        unsafe {
            if first {
                profile_first_request(tx)
            } else {
                profile_warm_request(tx)
            }
        }
        let elapsed = start.elapsed().as_nanos();
        let mut verdict = strata_verdict_t::empty();
        unsafe { strata_tx_verdict(tx, &mut verdict) };
        assert_eq!(verdict.error, STRATA_OK);
        println!(
            "{}",
            serde_json::json!({"phase":if first {"first"} else {"warm"},"elapsed_ns":elapsed,"recorded_engine_us":unsafe{strata_tx_time_us(tx)},"action":verdict.action,"budget_us":0,"scope":"diagnostic_C_ABI_not_NGINX"})
        );
        unsafe { strata_tx_free(tx) };
        // Diagnostic reads the live immutable handle created above; no aliases
        // mutate the engine, and it remains owned until engine_release below.
        let e = unsafe { &*engine.cast::<libstrata::engine::Engine>() };
        let (costs, requests, _) = e.rule_costs().take();
        let tables = e.tables();
        let rows:Vec<_>=costs.iter().take(20).map(|&(i,n,total,max)| {
            let rule=i.and_then(|i|tables.rule(i as usize));
            serde_json::json!({"rule_id":rule.as_ref().map(|r|r.id),"name":rule.map(|r|String::from_utf8_lossy(r.name).into_owned()),"samples":n,"total_ns":total,"max_ns":max})
        }).collect();
        println!(
            "{}",
            serde_json::json!({"kind":"rule_cost_diagnostic","first":first,"sampled_requests":requests,"top20":rows})
        );
    }
    unsafe { strata_engine_release(engine) };
}
