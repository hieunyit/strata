//! `extern "C"` entry points. The only module allowed to use `unsafe`.
//!
//! Every entry point runs inside `guard`, which catches panics so none crosses
//! the boundary. Any error from a transaction call, including a caught panic
//! (`STRATA_E_INTERNAL`), marks the transaction broken.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;
use std::{ptr, slice};

use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::Verdict;

use crate::abi::*;

/// Opaque `strata_engine_t`: an `Arc<Engine>` behind the pointer.
pub struct EngineHandle {
    _private: [u8; 0],
}

/// Opaque `strata_tx_t`: a `Box<Tx>` behind the pointer; one request, used
/// from a single thread.
pub struct TxHandle {
    _private: [u8; 0],
}

/// The connector's read-only bundle mapping. The ABI contract keeps it
/// valid and unchanged until the last `strata_engine_release`, so the
/// engine may read it for its whole life without copying.
struct Mapped {
    ptr: *const u8,
    len: usize,
}

// SAFETY: the mapping is read-only and outlives the engine (ABI contract);
// shared reads from any thread are fine.
unsafe impl Send for Mapped {}
unsafe impl Sync for Mapped {}

impl AsRef<[u8]> for Mapped {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: ptr is non-NULL with len readable bytes (checked when the
        // engine was mapped) and stays valid for the engine's life.
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// Copies an engine verdict into its C layout.
fn to_c(v: &Verdict) -> strata_verdict_t {
    let mut out = strata_verdict_t::empty();
    out.action = v.action;
    out.status = v.status;
    out.error = v.error;
    out.score = v.score;
    out.n_rules = v.n_rules.min(STRATA_MAX_RULES as u32);
    out.rules = v.rules;
    if v.need_body {
        out.flags |= STRATA_VF_NEED_BODY;
    }
    if v.need_response {
        out.flags |= STRATA_VF_NEED_RESPONSE;
    }
    if v.json {
        out.flags |= STRATA_VF_JSON;
    }
    if let Some(id) = &v.id {
        write_c_str(&mut out.block_id, id);
    }
    out
}

/// Runs `f`, converting a panic into `on_panic`.
pub(crate) fn guard<T>(on_panic: T, f: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(on_panic)
}

/// Borrows a `strata_str_t` as a byte slice for the duration of a call.
///
/// # Safety
/// `s.ptr` must point to `s.len` readable bytes (or be anything when len == 0).
unsafe fn bytes<'a>(s: strata_str_t) -> Result<&'a [u8], strata_rc_t> {
    if s.len == 0 {
        Ok(&[])
    } else if s.ptr.is_null() {
        Err(STRATA_E_INVALID)
    } else {
        // SAFETY: caller guarantees ptr/len describe a live buffer.
        Ok(unsafe { slice::from_raw_parts(s.ptr, s.len) })
    }
}

/// Runs a transaction call: NULL check, panic capture, error stickiness.
///
/// # Safety
/// `tx` must be NULL or a live pointer returned by `strata_tx_new`.
unsafe fn with_tx(
    tx: *mut TxHandle,
    f: impl FnOnce(&mut Tx) -> Result<strata_rc_t, strata_rc_t>,
) -> strata_rc_t {
    if tx.is_null() {
        return STRATA_E_INVALID;
    }
    // SAFETY: non-NULL and live per the contract above.
    let tx = unsafe { &mut *tx.cast::<Tx>() };
    let start = Instant::now();
    let rc = catch_unwind(AssertUnwindSafe(|| f(tx).unwrap_or_else(|rc| rc)))
        .unwrap_or(STRATA_E_INTERNAL);
    tx.add_time(start.elapsed());
    // Any failed call leaves the inspection incomplete: mark the transaction
    // broken so the verdict carries the error and the connector applies its
    // fail mode, even if it ignored this return code.
    if rc != STRATA_OK {
        tx.fail(rc);
    }
    rc
}

/// Returns `(major << 16) | minor`; connectors refuse a different major.
#[unsafe(no_mangle)]
pub extern "C" fn strata_abi_version() -> u32 {
    STRATA_ABI_VERSION
}

/// Builds an engine directly over a read-only mapped bundle after verifying
/// its Ed25519 signature with `pubkey`. `base` must be page-aligned (as
/// returned by mmap): sections are 4 KB-aligned relative to it, and the
/// Hyperscan image inside needs that alignment. libstrata does not copy the bundle: the mapping must stay valid until the last
/// `strata_engine_release`. `pubkey` points to `STRATA_PUBKEY_LEN` bytes.
/// Returns NULL on failure and fills `err` when it is not NULL.
///
/// # Safety
/// `base` must point to `len` readable bytes; `pubkey` to 32 bytes or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_engine_map(
    base: *const u8,
    len: usize,
    pubkey: *const u8,
    err: *mut strata_err_t,
) -> *mut EngineHandle {
    let result = guard(
        Err((STRATA_E_INTERNAL, "panic in strata_engine_map")),
        || {
            if base.is_null() || len == 0 {
                return Err((STRATA_E_INVALID, "bundle pointer is NULL or empty"));
            }
            if pubkey.is_null() {
                return Err((STRATA_E_INVALID, "public key is NULL"));
            }
            // SAFETY: caller contract: pubkey points to STRATA_PUBKEY_LEN bytes.
            let key = unsafe { slice::from_raw_parts(pubkey, STRATA_PUBKEY_LEN) };
            Engine::map(Box::new(Mapped { ptr: base, len }), key)
        },
    );
    let (code, msg, handle) = match result {
        Ok(engine) => (
            STRATA_OK,
            &b""[..],
            Arc::into_raw(Arc::new(engine))
                .cast_mut()
                .cast::<EngineHandle>(),
        ),
        Err((code, msg)) => (code, msg.as_bytes(), ptr::null_mut()),
    };
    if !err.is_null() {
        // SAFETY: err is non-NULL and points to a strata_err_t per contract.
        let err = unsafe { &mut *err };
        err.code = code;
        write_c_str(&mut err.msg, msg);
    }
    handle
}

/// Fills `out` with the signed header fields of the engine's bundle (version,
/// creation time, rollback flag). With a NULL engine, `out` is zeroed.
///
/// # Safety
/// `e` must be NULL or a live engine handle; `out` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_engine_info(
    e: *const EngineHandle,
    out: *mut strata_engine_info_t,
) {
    if out.is_null() {
        return;
    }
    let info = if e.is_null() {
        strata_engine_info_t::default()
    } else {
        // SAFETY: live handle per contract.
        let i = unsafe { &*e.cast::<Engine>() }.info();
        strata_engine_info_t {
            version: i.version,
            created_at_ms: i.created_at_ms,
            flags: if i.flags & libstrata::bundle::FLAG_ROLLBACK != 0 {
                STRATA_BUNDLE_ROLLBACK
            } else {
                0
            },
            n_policies: i.n_policies,
        }
    };
    // SAFETY: out is non-NULL and writable.
    unsafe { *out = info };
}

/// Looks a policy up in the engine's bundle. Returns `STRATA_OK` and fills
/// `out`, `STRATA_E_NOT_FOUND` when the bundle has no such policy, or
/// `STRATA_E_INVALID` for a NULL engine or `out`.
///
/// # Safety
/// `e` must be NULL or a live engine handle; `name` valid for the call;
/// `out` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_engine_policy(
    e: *const EngineHandle,
    name: strata_str_t,
    out: *mut strata_policy_info_t,
) -> strata_rc_t {
    if e.is_null() || out.is_null() {
        return STRATA_E_INVALID;
    }
    guard(STRATA_E_INTERNAL, || {
        // SAFETY: live handle and valid name per contract.
        let engine = unsafe { &*e.cast::<Engine>() };
        let Ok(name) = (unsafe { bytes(name) }) else {
            return STRATA_E_INVALID;
        };
        match engine.policy(name) {
            Some(p) => {
                // SAFETY: out is non-NULL and writable.
                unsafe {
                    *out = strata_policy_info_t {
                        mode: p.mode as u32,
                        index: p.index,
                    }
                };
                STRATA_OK
            }
            None => STRATA_E_NOT_FOUND,
        }
    })
}

/// Default block page of the engine's bundle: `html` (template with
/// `{{block_id}}`, `{{time}}`, `{{support_contact}}`) and `contact` point
/// into the bundle mapping and stay valid while the caller holds a reference
/// to the engine. Returns `STRATA_E_NOT_FOUND` when the bundle has none,
/// `STRATA_E_INVALID` for NULL arguments.
///
/// # Safety
/// `e` must be NULL or a live engine handle; `html`, `contact` NULL or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_engine_block_page(
    e: *const EngineHandle,
    html: *mut strata_str_t,
    contact: *mut strata_str_t,
) -> strata_rc_t {
    if e.is_null() || html.is_null() || contact.is_null() {
        return STRATA_E_INVALID;
    }
    guard(STRATA_E_INTERNAL, || {
        // SAFETY: live handle per contract.
        let engine = unsafe { &*e.cast::<Engine>() };
        match engine.block_page() {
            Some((h, c)) => {
                // SAFETY: both out pointers are non-NULL and writable.
                unsafe {
                    *html = strata_str_t {
                        ptr: h.as_ptr(),
                        len: h.len(),
                    };
                    *contact = strata_str_t {
                        ptr: c.as_ptr(),
                        len: c.len(),
                    };
                }
                STRATA_OK
            }
            None => STRATA_E_NOT_FOUND,
        }
    })
}

/// Adds a reference to the engine.
///
/// # Safety
/// `e` must be NULL or a live engine handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_engine_retain(e: *mut EngineHandle) {
    if !e.is_null() {
        // SAFETY: e came from Arc::into_raw and is still alive.
        unsafe { Arc::increment_strong_count(e.cast_const().cast::<Engine>()) };
    }
}

/// Drops a reference; the last one frees the engine. The connector unmaps
/// the bundle only after it has released its last reference and every
/// transaction built on the engine has been freed.
///
/// # Safety
/// `e` must be NULL or a live engine handle; each call balances one
/// `strata_engine_map` or `strata_engine_retain`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_engine_release(e: *mut EngineHandle) {
    if !e.is_null() {
        // SAFETY: as above; the strong count is at least one.
        guard((), || unsafe {
            Arc::decrement_strong_count(e.cast_const().cast::<Engine>())
        });
    }
}

/// Starts a transaction. `engine` may be NULL (no bundle loaded): the
/// transaction then reports `STRATA_E_BUNDLE` and carries an Event ID.
/// The transaction holds its own engine reference. `conn` may be NULL.
/// Returns NULL only on an internal error.
///
/// # Safety
/// `engine` must be NULL or a live engine handle; `policy` and the strings in
/// `conn` must be valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_new(
    engine: *mut EngineHandle,
    policy: strata_str_t,
    conn: *const strata_conn_t,
    cpu_budget_us: u64,
) -> *mut TxHandle {
    // no budget accounting yet
    let _ = cpu_budget_us;
    guard(ptr::null_mut(), || {
        let engine = if engine.is_null() {
            None
        } else {
            // SAFETY: live handle from Arc::into_raw; take a new reference.
            unsafe {
                Arc::increment_strong_count(engine.cast_const().cast::<Engine>());
                Some(Arc::from_raw(engine.cast_const().cast::<Engine>()))
            }
        };
        let (node, flags, client) = if conn.is_null() {
            (&[][..], 0, &[][..])
        } else {
            // SAFETY: conn is non-NULL and valid for the call.
            let c = unsafe { &*conn };
            (
                unsafe { bytes(c.node_id) }.unwrap_or(&[]),
                c.flags,
                unsafe { bytes(c.client_addr) }.unwrap_or(&[]),
            )
        };
        let mut tx = Tx::new(engine, node, flags);
        tx.set_client_addr(client);
        // SAFETY: policy is valid for the call.
        tx.set_policy(unsafe { bytes(policy) }.unwrap_or(&[]));
        Box::into_raw(Box::new(tx)).cast::<TxHandle>()
    })
}

/// Request line. The URI is passed in three forms: raw as sent by the client
/// (`r->unparsed_uri`), normalized by the proxy (`r->uri`) and the query.
///
/// # Safety
/// `tx` must be NULL or live; strings valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_request_line(
    tx: *mut TxHandle,
    method: strata_str_t,
    raw_uri: strata_str_t,
    norm_uri: strata_str_t,
    args: strata_str_t,
    proto: strata_str_t,
) -> strata_rc_t {
    unsafe {
        with_tx(tx, |t| {
            Ok(t.request_line(
                bytes(method)?,
                bytes(raw_uri)?,
                bytes(norm_uri)?,
                bytes(args)?,
                bytes(proto)?,
            ))
        })
    }
}

/// All request headers in one call, raw, in arrival order, duplicates kept.
///
/// # Safety
/// `tx` must be NULL or live; `h` must point to `n` headers (or n == 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_request_headers(
    tx: *mut TxHandle,
    h: *const strata_header_t,
    n: usize,
) -> strata_rc_t {
    unsafe {
        with_tx(tx, |t| {
            let headers: &[strata_header_t] = if n == 0 {
                &[]
            } else if h.is_null() {
                return Err(STRATA_E_INVALID);
            } else {
                slice::from_raw_parts(h, n)
            };
            let pairs = headers
                .iter()
                .map(|p| Ok((bytes(p.key)?, bytes(p.val)?)))
                .collect::<Result<Vec<_>, strata_rc_t>>()?;
            Ok(t.request_headers(&pairs))
        })
    }
}

/// One chunk of request body (framing already removed); `last` != 0 on the
/// final call, which may have `len == 0`.
///
/// # Safety
/// `tx` must be NULL or live; `p` must point to `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_request_body_chunk(
    tx: *mut TxHandle,
    p: *const u8,
    len: usize,
    last: i32,
) -> strata_rc_t {
    unsafe {
        with_tx(tx, |t| {
            Ok(t.request_body_chunk(bytes(strata_str_t { ptr: p, len })?, last != 0))
        })
    }
}

/// The connector inspected only part of the request body (its inspection
/// limit): `bytes` were not passed. Call before the final body chunk. The
/// policy's `oversize` decides: block (rule 100020 blocks alone) or pass
/// (rule 100020 is recorded).
///
/// # Safety
/// `tx` must be NULL or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_request_body_skipped(
    tx: *mut TxHandle,
    bytes: u64,
) -> strata_rc_t {
    unsafe { with_tx(tx, |t| Ok(t.request_body_skipped(bytes))) }
}

/// The connector reports that it could not pass all the input (for
/// example `STRATA_E_INCOMPLETE`: request body it cannot read without
/// I/O). The transaction is marked broken with `reason`: the verdict carries
/// it with an Event ID, and the connector applies its fail mode. Returns
/// `reason`, or `STRATA_E_INVALID` for a NULL tx or `STRATA_OK`.
///
/// # Safety
/// `tx` must be NULL or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_fail(tx: *mut TxHandle, reason: strata_rc_t) -> strata_rc_t {
    if reason == STRATA_OK {
        return STRATA_E_INVALID;
    }
    unsafe { with_tx(tx, |_| Ok(reason)) }
}

/// Response status and headers.
///
/// # Safety
/// `tx` must be NULL or live; `h` must point to `n` headers (or n == 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_response_headers(
    tx: *mut TxHandle,
    status: u16,
    h: *const strata_header_t,
    n: usize,
) -> strata_rc_t {
    unsafe {
        with_tx(tx, |t| {
            if n != 0 && h.is_null() {
                return Err(STRATA_E_INVALID);
            }
            Ok(t.response_headers(status))
        })
    }
}

/// One chunk of response body (`last` != 0 on the final call, which may
/// have `len == 0`).
///
/// On return, `rewritten->ptr == NULL` means "send the chunk unchanged".
/// Otherwise send exactly `rewritten->len` bytes from `rewritten->ptr`
/// *instead of* the chunk, then release them with `strata_buf_free`. The
/// data guard masks values with '*' and may hold the tail of a chunk back
/// (a value could continue in the next one) and emit it with the next call,
/// so `rewritten->len` can differ from `len` (and be 0); over the whole
/// body the lengths add up to the same total, so Content-Length stays
/// valid. The final call flushes everything held. `rewritten` must not be
/// NULL when the verdict has `STRATA_VF_NEED_RESPONSE`; a call that would
/// rewrite with a NULL `rewritten` fails with `STRATA_E_INVALID`.
///
/// # Safety
/// `tx` must be NULL or live; `p` must point to `len` bytes; `rewritten`
/// NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_response_body_chunk(
    tx: *mut TxHandle,
    p: *const u8,
    len: usize,
    last: i32,
    rewritten: *mut strata_buf_t,
) -> strata_rc_t {
    unsafe {
        response_out(tx, rewritten, |t| {
            Ok(t.response_body_chunk(bytes(strata_str_t { ptr: p, len })?, last != 0))
        })
    }
}

/// The connector flushes the response (a `flush` buffer, e.g. Server-Sent
/// Events with `proxy_buffering off`): the bytes the data guard holds back
/// are emitted now instead of with the next chunk (ABI 1.1).
///
/// On return, `out->ptr == NULL` means nothing to send. Otherwise send
/// `out->len` bytes (possibly 0) from `out->ptr` right after the bytes of
/// the previous chunk, then release them with `strata_buf_free`. A value
/// split exactly across the flush is not masked. `out` must not be NULL
/// when the verdict has `STRATA_VF_NEED_RESPONSE`, as for
/// `strata_tx_response_body_chunk`.
///
/// # Safety
/// `tx` must be NULL or live; `out` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_response_body_flush(
    tx: *mut TxHandle,
    out: *mut strata_buf_t,
) -> strata_rc_t {
    unsafe { response_out(tx, out, |t| Ok(t.response_body_flush())) }
}

/// Response calls that may hand bytes back through `out`.
///
/// # Safety
/// `tx` must be NULL or live; `out` NULL or writable.
unsafe fn response_out(
    tx: *mut TxHandle,
    out: *mut strata_buf_t,
    f: impl FnOnce(&mut Tx) -> Result<(strata_rc_t, Option<Vec<u8>>), strata_rc_t>,
) -> strata_rc_t {
    if !out.is_null() {
        // SAFETY: non-NULL and writable per contract.
        unsafe { *out = strata_buf_t::empty() };
    }
    unsafe {
        with_tx(tx, |t| {
            let (rc, bytes) = f(t)?;
            if let Some(v) = bytes {
                if out.is_null() {
                    return Err(STRATA_E_INVALID);
                }
                // handed to the caller; strata_buf_free rebuilds the Vec
                let mut v = std::mem::ManuallyDrop::new(v);
                *out = strata_buf_t {
                    ptr: v.as_mut_ptr(),
                    len: v.len(),
                    cap: v.capacity(),
                };
            }
            Ok(rc)
        })
    }
}

/// Current verdict. With a NULL `tx`, `out` gets an `allow` verdict with
/// `error = STRATA_E_INVALID`.
///
/// # Safety
/// `tx` must be NULL or live; `out` must be NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_verdict(tx: *const TxHandle, out: *mut strata_verdict_t) {
    if out.is_null() {
        return;
    }
    let v = if tx.is_null() {
        let mut v = strata_verdict_t::empty();
        v.error = STRATA_E_INVALID;
        v
    } else {
        // SAFETY: live per contract.
        let t = unsafe { &*tx.cast::<Tx>() };
        guard(
            {
                let mut v = strata_verdict_t::empty();
                v.error = STRATA_E_INTERNAL;
                v
            },
            || to_c(&t.verdict()),
        )
    };
    // SAFETY: out is non-NULL and writable.
    unsafe { *out = v };
}

/// Engine time spent on the transaction so far, in microseconds (measured
/// around every transaction call). 0 for a NULL `tx`.
///
/// # Safety
/// `tx` must be NULL or live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_time_us(tx: *const TxHandle) -> u64 {
    if tx.is_null() {
        return 0;
    }
    // SAFETY: live per contract.
    unsafe { &*tx.cast::<Tx>() }.time_us()
}

/// Serializes the transaction's event into `dst` (up to `cap` bytes) and
/// returns the full event size; nothing is written when it exceeds `cap`.
/// Returns 0 when there is no event. The stub never produces events.
///
/// # Safety
/// `tx` must be NULL or live; `dst` must point to `cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_event(tx: *const TxHandle, dst: *mut u8, cap: usize) -> usize {
    let _ = (tx, dst, cap);
    0
}

/// Frees a transaction. NULL is ignored; set your pointer to NULL afterwards.
///
/// # Safety
/// `tx` must be NULL or a live pointer from `strata_tx_new`, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_tx_free(tx: *mut TxHandle) {
    if !tx.is_null() {
        // SAFETY: tx came from Box::into_raw in strata_tx_new.
        guard((), || drop(unsafe { Box::from_raw(tx.cast::<Tx>()) }));
    }
}

/// Frees a buffer returned in `rewritten` and resets it to empty, so a second
/// call is a no-op. NULL is ignored.
///
/// # Safety
/// `b` must be NULL or point to a buffer filled by libstrata (or empty).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strata_buf_free(b: *mut strata_buf_t) {
    if b.is_null() {
        return;
    }
    // SAFETY: b is non-NULL and points to a strata_buf_t.
    let buf = unsafe { &mut *b };
    if !buf.ptr.is_null() {
        // SAFETY: ptr/len/cap came from a Vec<u8> leaked by libstrata.
        guard((), || {
            drop(unsafe { Vec::from_raw_parts(buf.ptr, buf.len, buf.cap) })
        });
    }
    *buf = strata_buf_t::empty();
}

#[cfg(test)]
mod tests {
    use super::guard;

    #[test]
    fn guard_catches_panic() {
        assert_eq!(guard(7, || panic!("boom")), 7);
        assert_eq!(guard(7, || 1), 1);
    }
}
