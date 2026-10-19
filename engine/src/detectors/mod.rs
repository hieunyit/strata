//! Detection layers, cheapest first (strata-overview.md › Pipeline detection).
#![forbid(unsafe_code)]

pub mod injection;
pub mod protocol;
pub mod response;

/// One rule firing: its fixed id, the score it adds, whether it blocks
/// on its own, whether it belongs to the signature pack (RV-S-01), and the
/// match details for event reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub rule: u32,
    pub score: i32,
    pub block_alone: bool,
    pub signature: bool,
    /// a CRS rule above the policy's enforced paranoia level, within its
    /// shadow level (W17-S-01): reported, kept apart, never blocks
    pub paranoia_shadow: bool,
    pub layer: &'static str,
    pub field: String,
    pub snippet: Vec<u8>,
}
