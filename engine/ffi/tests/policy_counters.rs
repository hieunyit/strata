//! RV-N-01: per-policy request counts through the C ABI. The connector's
//! `strata_tx_sample` call gives them about once a second (a datagram
//! starting `\xffSC1`, event.proto `PolicyCounters`) when the transaction
//! has no replay sample; a length query never takes them.

use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use strata::abi::*;
use strata::ffi::*;

const SEED: [u8; 32] = [9; 32];

fn s(b: &[u8]) -> strata_str_t {
    strata_str_t {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

fn engine() -> *mut EngineHandle {
    let policies = [
        PolicySpec::new("example-api", Mode::Enforce, Oversize::Pass),
        PolicySpec::new("example-upload", Mode::Shadow, Oversize::Pass),
    ];
    let spec = Spec {
        version: 4,
        created_at_ms: 0,
        flags: 0,
        policies: &policies,
        sections: &[],
    };
    // libstrata does not copy the bundle: it must outlive the engine
    let bundle: &[u8] = Box::leak(build(&spec, &SEED).unwrap().into_boxed_slice());
    let mut err = strata_err_t {
        code: 0,
        msg: [0; 256],
    };
    let e = unsafe {
        strata_engine_map(
            bundle.as_ptr(),
            bundle.len(),
            public_key(&SEED).as_ptr(),
            &mut err,
        )
    };
    assert!(!e.is_null());
    e
}

fn conn() -> strata_conn_t {
    strata_conn_t {
        client_addr: s(b"192.0.2.1"),
        client_port: 1,
        _reserved: 0,
        flags: 0,
        node_id: s(b"edge-01"),
        identity: s(b""),
        request_id: s(b""),
    }
}

/// One request of `policy`; `skip`: the connector did not pass its body.
fn request(e: *mut EngineHandle, policy: &[u8], skip: bool) {
    let c = conn();
    unsafe {
        let tx = strata_tx_new(e, s(policy), &c, 0);
        strata_tx_request_line(
            tx,
            s(b"POST"),
            s(b"/v1/x"),
            s(b"/v1/x"),
            s(b""),
            s(b"HTTP/1.1"),
        );
        strata_tx_request_headers(tx, std::ptr::null(), 0);
        if skip {
            assert_eq!(strata_tx_request_body_skipped(tx, 1 << 20), STRATA_OK);
        }
        let mut v = std::mem::zeroed::<strata_verdict_t>();
        strata_tx_verdict(tx, &mut v);
        strata_tx_free(tx);
    }
}

fn varint(b: &mut &[u8]) -> u64 {
    let (mut v, mut sh) = (0u64, 0);
    loop {
        let c = b[0];
        *b = &b[1..];
        v |= u64::from(c & 0x7f) << sh;
        sh += 7;
        if c < 0x80 {
            return v;
        }
    }
}

/// (field, varint or bytes) of a flat protobuf message
fn fields(mut b: &[u8]) -> Vec<(u32, u64, Vec<u8>)> {
    let mut out = vec![];
    while !b.is_empty() {
        let tag = varint(&mut b);
        let f = (tag >> 3) as u32;
        if tag & 7 == 0 {
            out.push((f, varint(&mut b), vec![]));
        } else {
            let n = varint(&mut b) as usize;
            out.push((f, 0, b[..n].to_vec()));
            b = &b[n..];
        }
    }
    out
}

/// policy -> [requests, partial, body_skipped, error, degraded]
fn counts(d: &[u8]) -> std::collections::BTreeMap<String, [u64; 5]> {
    assert_eq!(&d[..4], b"\xffSC1");
    let mut m = std::collections::BTreeMap::new();
    for (f, _, msg) in fields(&d[4..]) {
        if f != 4 {
            continue;
        }
        let (mut name, mut v) = (String::new(), [0u64; 5]);
        for (k, n, b) in fields(&msg) {
            match k {
                1 => name = String::from_utf8(b).unwrap(),
                2..=6 => v[k as usize - 2] = n,
                _ => panic!("field {k}"),
            }
        }
        m.insert(name, v);
    }
    m
}

/// The sample call of a new transaction, as the connector makes it.
fn sample_call(e: *mut EngineHandle, cap: usize) -> Option<Vec<u8>> {
    let c = conn();
    unsafe {
        let tx = strata_tx_new(e, s(b"example-api"), &c, 0);
        let mut buf = vec![0u8; cap.max(1)];
        let dst = if cap == 0 {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr()
        };
        let n = strata_tx_sample(tx, dst, cap);
        // this transaction itself counts when freed
        strata_tx_free(tx);
        (n > 0).then(|| {
            buf.truncate(n);
            buf
        })
    }
}

#[test]
fn requests_per_policy_reach_the_event_socket() {
    let e = engine();
    for _ in 0..3 {
        request(e, b"example-api", false);
    }
    request(e, b"example-api", true);
    request(e, b"example-upload", false);
    request(e, b"no-such-policy", false);
    // a length query or a buffer smaller than a datagram takes nothing
    assert!(sample_call(e, 0).is_none());
    assert!(sample_call(e, 1024).is_none());
    let d = sample_call(e, 8192).expect("counts");
    let got = counts(&d);
    // the two sample calls above count too
    assert_eq!(got["example-api"], [6, 0, 1, 0, 0], "{got:?}");
    assert_eq!(got["example-upload"], [1, 0, 0, 0, 0]);
    assert_eq!(got[""], [1, 0, 0, 0, 0]);
    let head = fields(&d[4..]);
    assert!(
        head.iter()
            .any(|(f, n, _)| *f == 1 && *n > 1_700_000_000_000)
    );
    assert!(head.iter().any(|(f, _, b)| *f == 2 && b == b"edge-01"));
    assert!(head.iter().any(|(f, n, _)| *f == 3 && *n == 4));
    // within the second: nothing more; the counts wait
    request(e, b"example-api", false);
    assert!(sample_call(e, 8192).is_none());
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let next = counts(&sample_call(e, 8192).expect("next second"));
    // the call that sent, the request, the call that waited
    assert_eq!(next["example-api"], [3, 0, 0, 0, 0], "{next:?}");
    unsafe { strata_engine_release(e) };
}
