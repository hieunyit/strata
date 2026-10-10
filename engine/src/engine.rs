//! Engine built on a mapped bundle.
//!
//! The bundle is verified (Ed25519) once, then read in place: the engine
//! keeps the mapping (whatever owns it: the connector's read-only mmap
//! through libstrata-ffi, or a buffer in tests) and copies nothing out of
//! it. Rule sections are still a stub: detection is the protocol layer and
//! the test rule in `tx`.
#![forbid(unsafe_code)]

use crate::bundle::{self, Info, Mode};
use crate::verdict::{E_BUNDLE, E_INVALID, PUBKEY_LEN, Rc};

/// Bytes of a bundle that stay valid, unchanged, for the engine's life.
pub trait Mapping: AsRef<[u8]> + Send + Sync {}
impl<T: AsRef<[u8]> + Send + Sync> Mapping for T {}

pub struct Engine {
    bytes: Box<dyn Mapping>,
    info: Info,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Builds an engine over `bundle` after checking its signature.
    pub fn map(bundle: Box<dyn Mapping>, pubkey: &[u8]) -> Result<Engine, (Rc, &'static str)> {
        if pubkey.len() != PUBKEY_LEN {
            return Err((E_INVALID, "public key must be 32 bytes"));
        }
        match bundle::verify((*bundle).as_ref(), pubkey) {
            Ok(info) => Ok(Engine {
                bytes: bundle,
                info,
            }),
            Err(bundle::Error::BadKey) => Err((E_INVALID, bundle::Error::BadKey.message())),
            Err(e) => Err((E_BUNDLE, e.message())),
        }
    }

    pub fn info(&self) -> &Info {
        &self.info
    }

    /// Index and signed mode of a policy, read from the mapping.
    pub fn policy(&self, name: &[u8]) -> Option<(u32, Mode)> {
        bundle::find_policy((*self.bytes).as_ref(), &self.info, name)
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
            policies: &[
                ("example-api", Mode::Enforce),
                ("example-web", Mode::Shadow),
            ],
            sections: b"",
        };
        build(&spec, &SEED).unwrap()
    }

    pub(crate) fn test_engine() -> Engine {
        Engine::map(Box::new(test_bundle(1)), &public_key(&SEED)).unwrap()
    }

    #[test]
    fn maps_signed_bundle() {
        let e = test_engine();
        assert_eq!(e.info().version, 1);
        assert_eq!(e.info().n_policies, 2);
    }

    #[test]
    fn looks_policies_up_in_place() {
        let e = test_engine();
        assert_eq!(e.policy(b"example-api"), Some((0, Mode::Enforce)));
        assert_eq!(e.policy(b"example-web"), Some((1, Mode::Shadow)));
        assert_eq!(e.policy(b"example"), None);
        assert_eq!(e.policy(b""), None);
    }

    #[test]
    fn rejects_bad_input() {
        let key = public_key(&SEED);
        assert_eq!(
            Engine::map(Box::new(*b"XXXX"), &key).unwrap_err().0,
            E_BUNDLE
        );
        assert_eq!(
            Engine::map(Box::new(test_bundle(1)), &[0; 31])
                .unwrap_err()
                .0,
            E_INVALID
        );
        let mut b = test_bundle(1);
        let n = b.len();
        b[n - 1] ^= 1;
        assert_eq!(
            Engine::map(Box::new(b), &key).unwrap_err(),
            (E_BUNDLE, "bad bundle signature")
        );
    }
}
