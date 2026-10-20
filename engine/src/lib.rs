//! libstrata — Strata WAF engine (safe Rust).
//!
//! The C ABI lives in the `libstrata-ffi` crate (`engine/ffi/`), the only
//! place where `unsafe` is allowed. Detection: the protocol layer
//! ([`detectors::protocol`]) and the stub test rule in [`tx`]; rule sections
//! of the bundle are not interpreted yet.
#![forbid(unsafe_code)]

pub mod anon;
pub mod b64;
pub mod block_id;
pub mod budget;
pub mod bundle;
pub mod canary;
pub mod counters;
pub mod detectors;
pub mod engine;
pub mod eval;
pub mod event;
pub mod exceptions;
pub mod goodbots;
pub mod guard;
pub mod ja4;
pub mod json;
pub mod multipart;
pub mod operators;
pub mod paranoia;
pub mod privacy;
pub mod rule_exclusions;
pub mod rulecost;
pub mod rules;
pub mod staging;
pub mod transform;
pub mod tx;
pub mod verdict;
pub mod xml;

pub use regex;
pub use regex_automata;
