//! C ABI types shared by every connector (`strata.h`).
//!
//! Frozen at the end of week 2: any incompatible change after that bumps
//! `STRATA_ABI_VERSION_MAJOR` and ships a compatibility layer; additions
//! bump the minor (1.1: `strata_tx_response_body_flush`; 1.2:
//! `STRATA_TXF_DEGRADED`; 1.3: `strata_engine_disable_rules`).
#![forbid(unsafe_code)]
#![allow(non_camel_case_types)]

use std::os::raw::c_char;

/// Major ABI version. A connector refuses to load a libstrata whose major
/// version differs from the one it was compiled against.
pub const STRATA_ABI_VERSION_MAJOR: u32 = 1;
/// Minor ABI version: additive, backward-compatible changes only.
pub const STRATA_ABI_VERSION_MINOR: u32 = 4;
/// Value returned by `strata_abi_version()`: `(major << 16) | minor`.
pub const STRATA_ABI_VERSION: u32 = (STRATA_ABI_VERSION_MAJOR << 16) | STRATA_ABI_VERSION_MINOR;

/// Return code of fallible calls. Any non-OK code returned by a transaction
/// call marks that transaction broken: later calls return the first error
/// and the verdict reports it in `error` (sticky), so a connector that only
/// checks the verdict still applies its fail mode.
pub type strata_rc_t = i32;
/// Success.
pub const STRATA_OK: strata_rc_t = 0;
/// Invalid argument (NULL pointer with non-zero length, NULL handle...).
pub const STRATA_E_INVALID: strata_rc_t = 1;
/// Call out of order, or the transaction is already marked broken.
pub const STRATA_E_STATE: strata_rc_t = 2;
/// Internal error, including a caught panic; the transaction is marked broken.
pub const STRATA_E_INTERNAL: strata_rc_t = 3;
/// The transaction exceeded its CPU budget.
pub const STRATA_E_BUDGET: strata_rc_t = 4;
/// No usable bundle (missing, corrupt, bad signature).
pub const STRATA_E_BUNDLE: strata_rc_t = 5;
/// The requested item (e.g. a policy) is not in the bundle.
pub const STRATA_E_NOT_FOUND: strata_rc_t = 6;
/// The connector could not pass all the input to libstrata (for example a
/// request body it cannot read without I/O); reported with `strata_tx_fail`.
pub const STRATA_E_INCOMPLETE: strata_rc_t = 7;

/// `strata_policy_info_t.mode`: policy mode signed into the bundle.
pub const STRATA_POLICY_SHADOW: u32 = 0;
pub const STRATA_POLICY_ENFORCE: u32 = 1;

/// Verdict actions.
pub const STRATA_ACTION_ALLOW: u32 = 0;
pub const STRATA_ACTION_LOG: u32 = 1;
pub const STRATA_ACTION_CHALLENGE: u32 = 2;
pub const STRATA_ACTION_BLOCK: u32 = 3;

/// Verdict flags.
/// The engine needs the request body before it can decide.
pub const STRATA_VF_NEED_BODY: u16 = 1 << 0;
/// The engine wants to inspect the response.
pub const STRATA_VF_NEED_RESPONSE: u16 = 1 << 1;
/// The block response should be JSON rather than HTML (policy + `Accept`).
pub const STRATA_VF_JSON: u16 = 1 << 2;
/// The request's policy has an enforce canary and the client is inside it
/// (enforced). ABI 1.4, W12-G2-01: the connector counts the canary group.
pub const STRATA_VF_CANARY: u16 = 1 << 3;
/// The request's policy has an enforce canary and the client is outside it
/// (shadow): the group the canary is compared with. ABI 1.4.
pub const STRATA_VF_CANARY_SHADOW: u16 = 1 << 4;

/// Per-request flags passed in `strata_conn_t.flags`.
pub const STRATA_TXF_TLS: u32 = 1 << 0;
pub const STRATA_TXF_HTTP2: u32 = 1 << 1;
pub const STRATA_TXF_HTTP3: u32 = 1 << 2;
/// Force shadow for this request (`strata_mode shadow`): never block,
/// report would-be blocks as `log` with an `EVT-` id.
pub const STRATA_TXF_FORCE_SHADOW: u32 = 1 << 16;
/// Degraded mode (ABI 1.2, circuit breaker of the connector): run only the
/// minimal checks, the protocol layer and the rules made only of `ip_match`
/// conditions; every other rule is skipped. A libstrata older than 1.2
/// ignores the flag and runs the full engine.
pub const STRATA_TXF_DEGRADED: u32 = 1 << 17;

/// Maximum number of matched rule ids reported in a verdict.
pub const STRATA_MAX_RULES: usize = 16;
/// Size of the NUL-terminated Block ID buffer ("STR-XXXX-XXXX-XXXX-XXXX\0").
pub const STRATA_BLOCK_ID_SIZE: usize = 24;
/// Size of the NUL-terminated error message buffer in `strata_err_t`.
pub const STRATA_ERR_MSG_SIZE: usize = 256;
/// Length in bytes of the Ed25519 public key passed to `strata_engine_map`.
pub const STRATA_PUBKEY_LEN: usize = 32;

/// `strata_engine_info_t.flags`: the bundle carries a signed rollback flag
/// and may replace a newer version.
pub const STRATA_BUNDLE_ROLLBACK: u32 = 1 << 0;

/// Borrowed byte string. Not NUL-terminated, not necessarily UTF-8;
/// `ptr` may be NULL when `len == 0`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct strata_str_t {
    pub ptr: *const u8,
    pub len: usize,
}

/// Borrowed key/value pair.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct strata_str_pair_t {
    pub key: strata_str_t,
    pub val: strata_str_t,
}

/// One raw header, in arrival order, duplicates included.
pub type strata_header_t = strata_str_pair_t;

/// Request/connection context given to `strata_tx_new`.
/// All strings are borrowed for the duration of the call only.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct strata_conn_t {
    /// Client address in text form, after `realip` (`$remote_addr`).
    pub client_addr: strata_str_t,
    pub client_port: u16,
    pub _reserved: u16,
    /// `STRATA_TXF_*`.
    pub flags: u32,
    /// Node name (`strata_node_id`), hashed into the Block ID.
    pub node_id: strata_str_t,
    /// Client identity (`strata_identity`), may be empty.
    pub identity: strata_str_t,
    /// Host request id (`$request_id`), may be empty.
    pub request_id: strata_str_t,
}

/// Decision for a transaction, filled by `strata_tx_verdict`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct strata_verdict_t {
    /// `STRATA_ACTION_*`.
    pub action: u32,
    /// HTTP status to return for `block` / `challenge`, 0 otherwise.
    pub status: u16,
    /// `STRATA_VF_*`.
    pub flags: u16,
    /// Sticky transaction error; when not `STRATA_OK` the connector applies
    /// its fail mode and `block_id` holds the Event ID of the error.
    pub error: strata_rc_t,
    /// Total score.
    pub score: i32,
    /// Number of valid entries in `rules`.
    pub n_rules: u32,
    pub rules: [u32; STRATA_MAX_RULES],
    /// NUL-terminated: `STR-…` when blocked, `EVT-…` in shadow or on error,
    /// empty when allowed.
    pub block_id: [c_char; STRATA_BLOCK_ID_SIZE],
}

/// A policy of the engine's bundle, from `strata_engine_policy`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct strata_policy_info_t {
    /// `STRATA_POLICY_*`.
    pub mode: u32,
    /// Position in the bundle's policy table.
    pub index: u32,
}

/// Metadata of the bundle an engine was built from (signed header fields).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct strata_engine_info_t {
    /// Bundle version, increasing with every deploy.
    pub version: u64,
    /// Bundle creation time, Unix milliseconds.
    pub created_at_ms: u64,
    /// `STRATA_BUNDLE_*`.
    pub flags: u32,
    /// Number of policies in the bundle.
    pub n_policies: u32,
}

/// Error details from `strata_engine_map`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct strata_err_t {
    pub code: strata_rc_t,
    /// NUL-terminated message.
    pub msg: [c_char; STRATA_ERR_MSG_SIZE],
}

/// Buffer owned by libstrata (rewritten response data). The connector copies
/// it out, then releases it with `strata_buf_free`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct strata_buf_t {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl strata_verdict_t {
    pub const fn empty() -> Self {
        Self {
            action: STRATA_ACTION_ALLOW,
            status: 0,
            flags: 0,
            error: STRATA_OK,
            score: 0,
            n_rules: 0,
            rules: [0; STRATA_MAX_RULES],
            block_id: [0; STRATA_BLOCK_ID_SIZE],
        }
    }
}

impl strata_buf_t {
    pub const fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Copies `src` into a fixed C string buffer, truncating and NUL-terminating.
pub fn write_c_str(dst: &mut [c_char], src: &[u8]) {
    let Some(max) = dst.len().checked_sub(1) else {
        return;
    };
    let n = src.len().min(max);
    for (d, s) in dst.iter_mut().zip(&src[..n]) {
        *d = *s as c_char;
    }
    dst[n] = 0;
}
