//! SQL injection and XSS detection for `detect_sqli` / `detect_xss`: a
//! Rust port of libinjection v3.10.0 (BSD-3-Clause, Copyright (c)
//! 2012-2016 Nick Galbreath; see engine/NOTICE). Checked against the
//! original test suite (engine/tests/libinjection.rs) and against the C
//! library on the sample corpora (`make libinjection-diff`).
#![forbid(unsafe_code)]

pub mod html5;
pub mod sqli;
/// SSTI component; not yet exposed as a rule operator.
pub mod ssti;
#[rustfmt::skip]
mod sqli_data;
pub mod xss;

pub use sqli::detect as detect_sqli;
pub use xss::detect as detect_xss;
