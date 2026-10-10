//! libstrata — Strata WAF engine (safe Rust).
//!
//! The C ABI lives in the `libstrata-ffi` crate (`engine/ffi/`), the only
//! place where `unsafe` is allowed. Detection is still the stub test rule
//! in [`tx`]; rule sections of the bundle are not interpreted yet.
#![forbid(unsafe_code)]

pub mod block_id;
pub mod bundle;
pub mod engine;
pub mod tx;
pub mod verdict;
