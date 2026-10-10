//! libstrata — Strata WAF engine behind a small, versioned C ABI (`strata.h`).
//!
//! This is the week 1–2 stub: the full ABI is implemented, the detection
//! logic is a single test rule (see [`tx`]). `unsafe` is confined to [`ffi`].

pub mod abi;
pub mod block_id;
pub mod engine;
pub mod ffi;
pub mod tx;
