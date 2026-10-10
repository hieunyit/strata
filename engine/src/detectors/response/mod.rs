//! Response layer (W06-R-01), rules 600000-699999: allowed status codes,
//! database error messages, and the data guard values (citizen ID numbers,
//! JSON Web Tokens). Findings are recorded, never block: the response
//! headers are already on their way. Switched on per policy
//! (`bundle::Response`).
#![forbid(unsafe_code)]

pub mod cccd;
pub mod db_errors;
pub mod jwt;

/// Status outside the allowed codes.
pub const STATUS_NOT_ALLOWED: u32 = 600_001;

/// Allowed response codes (fixed in v0): every 1xx, 2xx and 3xx, and the
/// client and server errors an application normally returns. Others (500,
/// 502, 418...) often reveal errors or probing.
pub fn status_allowed(status: u16) -> bool {
    matches!(status, 100..=399)
        || matches!(status, 400 | 401 | 403 | 404 | 405 | 409 | 422 | 429 | 503)
}

/// ASCII digit test shared by the matchers.
pub(crate) fn digit(c: u8) -> bool {
    c.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_codes() {
        for s in [
            100, 101, 200, 204, 206, 301, 304, 308, 400, 401, 403, 404, 405, 409, 422, 429, 503,
        ] {
            assert!(status_allowed(s), "{s}");
        }
        for s in [0, 99, 402, 410, 418, 451, 500, 501, 502, 504, 999] {
            assert!(!status_allowed(s), "{s}");
        }
    }
}
