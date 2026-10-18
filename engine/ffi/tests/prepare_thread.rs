//! Worker preparation through the C ABI: no synthetic traffic, safe repeats
//! and per-thread state, with the engine kept alive until every caller exits.
use libstrata::bundle::public_key;
use strata::abi::*;
use strata::ffi::*;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

#[test]
fn preparation_is_repeatable_thread_local_and_does_not_count_traffic() {
    assert_eq!(
        unsafe { strata_engine_prepare_thread(std::ptr::null()) },
        STRATA_E_INVALID
    );
    let seed = [17; 32];
    let doc = from_yaml(r#"
ir_version: 1
ruleset: { name: p, version: "1" }
rules:
  - { id: 800604, name: method-rx, layer: managed, stage: request_headers, score: 100, severity: critical,
      match: { all: [
        { targets: [ { var: method } ], operator: { type: streq, value: "GET" } },
        { targets: [ { var: args } ], operator: { type: pm, value: [xy, zz] } } ] },
      metadata: { source: organization, license: Apache-2.0 } }
"#).unwrap();
    let policies = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        std::path::Path::new("."),
    )
    .unwrap();
    let b = compile(
        &rules_from_ir(&doc).unwrap(),
        &policies,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &seed,
    )
    .unwrap();
    let bytes = strata_hs::AlignedBuf::from_bytes(&b);
    let mut err = strata_err_t {
        code: 0,
        msg: [0; 256],
    };
    // SAFETY: aligned bundle and key remain live until release below.
    let e = unsafe {
        strata_engine_map(
            bytes.as_ref().as_ptr(),
            b.len(),
            public_key(&seed).as_ptr(),
            &mut err,
        )
    };
    assert!(!e.is_null(), "map: {}", err.code);
    let address = e as usize;
    let workers: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..4 {
                    // SAFETY: parent holds the engine until all threads join.
                    assert_eq!(
                        unsafe { strata_engine_prepare_thread(address as *const EngineHandle) },
                        STRATA_OK
                    );
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(unsafe { strata_engine_prepare_thread(e) }, STRATA_OK);
    // SAFETY: same live handle; read only, all other callers have joined.
    let engine = unsafe { &*e.cast::<libstrata::engine::Engine>() };
    assert!(
        engine.counters().take_due(u64::MAX).is_none(),
        "warmup must not inflate traffic denominator"
    );
    let (costs, requests, _) = engine.rule_costs().take();
    assert_eq!(requests, 0);
    assert!(costs.is_empty());
    unsafe { strata_engine_release(e) };
}
