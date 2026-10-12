//! W08-R-01: fuzz the C ABI (libstrata-ffi). One engine is built once; each
//! input drives a full transaction through the FFI entry points with
//! fuzzer-chosen request line, headers, body chunks and (sometimes) the
//! response path, then reads the verdict and the event and frees the tx. The
//! point is the unsafe boundary: every pointer/length pair the connector
//! passes must be handled without a memory error (checked under ASan/UBSan).
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use libstrata::bundle::{Mode, Oversize, PolicySpec, Spec, build, public_key};
use strata::abi::*;
use strata::ffi::*;

const SEED: [u8; 32] = [5; 32];

fn s(b: &[u8]) -> strata_str_t {
    strata_str_t {
        ptr: if b.is_empty() { std::ptr::null() } else { b.as_ptr() },
        len: b.len(),
    }
}

// The engine is built once and shared. The pointer is an Arc::into_raw handle
// (Send/Sync in practice: the engine is read-only); store it as usize.
fn engine() -> *mut EngineHandle {
    static E: OnceLock<usize> = OnceLock::new();
    *E.get_or_init(|| {
        let spec = Spec {
            version: 1,
            created_at_ms: 0,
            flags: 0,
            policies: &[
                PolicySpec::new("example-api", Mode::Enforce, Oversize::Block),
                PolicySpec::new("example-web", Mode::Shadow, Oversize::Pass),
            ],
            sections: &[],
        };
        let bundle = build(&spec, &SEED).unwrap();
        let key = public_key(&SEED);
        let mut err = strata_err_t { code: 0, msg: [0; 256] };
        // SAFETY: bundle and key are valid for the call; the engine keeps the
        // bundle alive (leaked on purpose, lives for the whole fuzz run).
        let e = unsafe { strata_engine_map(bundle.as_ptr(), bundle.len(), key.as_ptr(), &mut err) };
        assert!(!e.is_null(), "engine map failed: {}", err.code);
        std::mem::forget(bundle);
        e as usize
    }) as *mut EngineHandle
}

/// Reads length-prefixed slices out of the fuzz input (1-byte length, capped
/// at the bytes left), so one input decomposes into many request fields.
struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, i: 0 }
    }
    fn byte(&mut self) -> u8 {
        let v = self.b.get(self.i).copied().unwrap_or(0);
        self.i += 1;
        v
    }
    fn take(&mut self) -> &'a [u8] {
        let n = self.byte() as usize;
        let start = self.i.min(self.b.len());
        let end = start.saturating_add(n).min(self.b.len());
        self.i = end;
        &self.b[start..end]
    }
    fn done(&self) -> bool {
        self.i >= self.b.len()
    }
}

fuzz_target!(|data: &[u8]| {
    let e = engine();
    let mut c = Cursor::new(data);

    // Half the inputs pass a connection context, half a NULL one.
    let sel = c.byte();
    let conn = strata_conn_t {
        client_addr: s(c.take()),
        client_port: u16::from(c.byte()) << 8 | u16::from(c.byte()),
        _reserved: 0,
        flags: u32::from(c.byte()) << 16, // exercises TXF_FORCE_SHADOW (bit 16)
        node_id: s(c.take()),
        identity: s(c.take()),
        request_id: s(c.take()),
    };
    let conn_ptr = if sel & 1 == 0 {
        &conn as *const strata_conn_t
    } else {
        std::ptr::null()
    };
    let policy = if sel & 2 == 0 { b"example-api".as_slice() } else { c.take() };

    // SAFETY: all strings borrow from `data`/`conn`, valid for the whole body.
    let tx = unsafe { strata_tx_new(e, s(policy), conn_ptr, u64::from(c.byte()) * 1000) };
    if tx.is_null() {
        return;
    }

    let (method, raw, uri, args, proto) = (c.take(), c.take(), c.take(), c.take(), c.take());
    unsafe { strata_tx_request_line(tx, s(method), s(raw), s(uri), s(args), s(proto)) };

    // request headers
    let nh = (c.byte() % 16) as usize;
    let mut hdrs: Vec<strata_header_t> = Vec::with_capacity(nh);
    for _ in 0..nh {
        hdrs.push(strata_header_t { key: s(c.take()), val: s(c.take()) });
    }
    unsafe {
        strata_tx_request_headers(
            tx,
            if hdrs.is_empty() { std::ptr::null() } else { hdrs.as_ptr() },
            hdrs.len(),
        )
    };

    // request body, in a few chunks; the last one is marked
    loop {
        let chunk = c.take();
        let last = c.done();
        unsafe {
            strata_tx_request_body_chunk(tx, chunk.as_ptr(), chunk.len(), i32::from(last))
        };
        if last {
            break;
        }
    }

    // sometimes drive the response path too
    if sel & 4 == 0 {
        let status = u16::from(c.byte()) << 8 | u16::from(c.byte());
        let nh = (c.byte() % 8) as usize;
        let mut rh: Vec<strata_header_t> = Vec::with_capacity(nh);
        for _ in 0..nh {
            rh.push(strata_header_t { key: s(c.take()), val: s(c.take()) });
        }
        unsafe {
            strata_tx_response_headers(
                tx,
                status,
                if rh.is_empty() { std::ptr::null() } else { rh.as_ptr() },
                rh.len(),
            )
        };
        let body = c.take();
        let mut out = strata_buf_t::empty();
        unsafe { strata_tx_response_body_chunk(tx, body.as_ptr(), body.len(), 1, &mut out) };
        unsafe { strata_buf_free(&mut out) };
    }

    let mut v = strata_verdict_t::empty();
    unsafe { strata_tx_verdict(tx, &mut v) };

    // pull the event into a fixed buffer, like the connector does
    let mut buf = [0u8; 8192];
    unsafe { strata_tx_event(tx, buf.as_mut_ptr(), buf.len()) };

    unsafe { strata_tx_free(tx) };
});
