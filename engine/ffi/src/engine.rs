//! Engine built on a mapped bundle (stub).
//!
//! The real engine reads its sections in place from the read-only mapping.
//! The stub only checks the magic and keeps no reference to the mapping.
#![forbid(unsafe_code)]

use crate::abi::{STRATA_E_BUNDLE, STRATA_E_INVALID, STRATA_PUBKEY_LEN, strata_rc_t};

/// Magic at the start of a (stub) bundle file.
pub const BUNDLE_MAGIC: &[u8; 4] = b"SBN0";

#[derive(Debug)]
pub struct Engine {
    _private: (),
}

impl Engine {
    /// Builds an engine over `bundle`. Signature checking with `pubkey`
    /// is not implemented in the stub.
    pub fn map(bundle: &[u8], pubkey: &[u8]) -> Result<Engine, (strata_rc_t, &'static str)> {
        if pubkey.len() != STRATA_PUBKEY_LEN {
            return Err((STRATA_E_INVALID, "public key must be 32 bytes"));
        }
        if !bundle.starts_with(BUNDLE_MAGIC) {
            return Err((STRATA_E_BUNDLE, "bad bundle magic"));
        }
        Ok(Engine { _private: () })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_magic() {
        assert!(Engine::map(b"SBN0 example-api", &[0; 32]).is_ok());
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(
            Engine::map(b"XXXX", &[0; 32]).unwrap_err().0,
            STRATA_E_BUNDLE
        );
        assert_eq!(
            Engine::map(b"SBN", &[0; 32]).unwrap_err().0,
            STRATA_E_BUNDLE
        );
        assert_eq!(
            Engine::map(b"SBN0", &[0; 31]).unwrap_err().0,
            STRATA_E_INVALID
        );
    }
}
