//! Engine built on a mapped bundle.
//!
//! The bundle is verified (Ed25519) and read in place from the read-only
//! mapping; the engine keeps only the header info. Rule sections are still
//! a stub: detection is the single test rule in `tx`.
#![forbid(unsafe_code)]

use crate::abi::{STRATA_E_BUNDLE, STRATA_E_INVALID, STRATA_PUBKEY_LEN, strata_rc_t};
use crate::bundle::{self, Info};

#[derive(Debug)]
pub struct Engine {
    info: Info,
}

impl Engine {
    /// Builds an engine over `bundle` after checking its signature.
    pub fn map(bundle: &[u8], pubkey: &[u8]) -> Result<Engine, (strata_rc_t, &'static str)> {
        if pubkey.len() != STRATA_PUBKEY_LEN {
            return Err((STRATA_E_INVALID, "public key must be 32 bytes"));
        }
        match bundle::verify(bundle, pubkey) {
            Ok(info) => Ok(Engine { info }),
            Err(bundle::Error::BadKey) => Err((STRATA_E_INVALID, bundle::Error::BadKey.message())),
            Err(e) => Err((STRATA_E_BUNDLE, e.message())),
        }
    }

    pub fn info(&self) -> &Info {
        &self.info
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bundle::{Spec, build, public_key};

    pub(crate) const SEED: [u8; 32] = [3; 32];

    pub(crate) fn test_bundle(version: u64) -> Vec<u8> {
        let spec = Spec {
            version,
            created_at_ms: 1,
            flags: 0,
            policies: &["example-api"],
            sections: b"",
        };
        build(&spec, &SEED).unwrap()
    }

    pub(crate) fn test_engine() -> Engine {
        Engine::map(&test_bundle(1), &public_key(&SEED)).unwrap()
    }

    #[test]
    fn maps_signed_bundle() {
        let e = test_engine();
        assert_eq!(e.info().version, 1);
        assert_eq!(e.info().n_policies, 1);
    }

    #[test]
    fn rejects_bad_input() {
        let key = public_key(&SEED);
        assert_eq!(Engine::map(b"XXXX", &key).unwrap_err().0, STRATA_E_BUNDLE);
        assert_eq!(
            Engine::map(&test_bundle(1), &[0; 31]).unwrap_err().0,
            STRATA_E_INVALID
        );
        let mut b = test_bundle(1);
        let n = b.len();
        b[n - 1] ^= 1;
        assert_eq!(
            Engine::map(&b, &key).unwrap_err(),
            (STRATA_E_BUNDLE, "bad bundle signature")
        );
    }
}
