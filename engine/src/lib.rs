//! libstrata — Strata WAF engine (safe Rust).
//!
//! The C ABI lives in the `libstrata-ffi` crate (`engine/ffi/`), the only
//! place where `unsafe` is allowed. Detection: the protocol layer
//! ([`detectors::protocol`]) and the stub test rule in [`tx`]; rule sections
//! of the bundle are not interpreted yet.
#![forbid(unsafe_code)]

pub mod anon;
pub mod block_id;
pub mod budget;
pub mod bundle;
pub mod canary;
pub mod detectors;
pub mod engine;
pub mod eval;
pub mod event;
pub mod guard;
pub mod json;
pub mod multipart;
pub mod operators;
pub mod rules;
pub mod transform;
pub mod tx;
pub mod verdict;
pub mod xml;

pub use regex;
pub use regex_automata;
