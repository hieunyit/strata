//! Detection layers, cheapest first (strata-overview.md › Pipeline detection).
#![forbid(unsafe_code)]

pub mod injection;
pub mod protocol;
pub mod response;

/// One rule firing: its fixed id, the score it adds, and whether it blocks
/// on its own (ambiguous requests are blocked without scoring).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Violation {
    pub rule: u32,
    pub score: i32,
    pub block_alone: bool,
}
