//! Result codes, actions and the verdict, as plain Rust.
//!
//! The numeric values are those of the C ABI (`strata.h`); libstrata-ffi
//! checks at compile time that they stay identical, then copies a `Verdict`
//! into `strata_verdict_t`.
#![forbid(unsafe_code)]

use crate::block_id::ID_LEN;

/// Return code of engine calls.
pub type Rc = i32;
pub const OK: Rc = 0;
pub const E_INVALID: Rc = 1;
pub const E_STATE: Rc = 2;
pub const E_INTERNAL: Rc = 3;
pub const E_BUDGET: Rc = 4;
pub const E_BUNDLE: Rc = 5;
pub const E_NOT_FOUND: Rc = 6;
/// The connector could not pass all the input (see `Tx::fail`).
pub const E_INCOMPLETE: Rc = 7;

pub const ACTION_ALLOW: u32 = 0;
pub const ACTION_LOG: u32 = 1;
pub const ACTION_CHALLENGE: u32 = 2;
pub const ACTION_BLOCK: u32 = 3;

/// Per-request option: never block, report would-be blocks as `log`.
pub const TXF_FORCE_SHADOW: u32 = 1 << 16;
/// Degraded mode: only the protocol layer and the `ip_match` rules run
/// (connector circuit breaker, nginx-module.md › Circuit breaker cấp worker).
pub const TXF_DEGRADED: u32 = 1 << 17;

pub const MAX_RULES: usize = 16;
pub const PUBKEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub action: u32,
    pub status: u16,
    pub need_body: bool,
    pub need_response: bool,
    pub json: bool,
    pub error: Rc,
    pub score: i32,
    pub n_rules: u32,
    pub rules: [u32; MAX_RULES],
    /// `STR-…` when blocked, `EVT-…` in shadow or on error.
    pub id: Option<[u8; ID_LEN]>,
}

impl Verdict {
    pub const fn allow() -> Self {
        Verdict {
            action: ACTION_ALLOW,
            status: 0,
            need_body: false,
            need_response: false,
            json: false,
            error: OK,
            score: 0,
            n_rules: 0,
            rules: [0; MAX_RULES],
            id: None,
        }
    }
}
