//! Engine built on a mapped bundle.
//!
//! The bundle is verified (Ed25519) once, then read in place: the engine
//! keeps the mapping (whatever owns it: the connector's read-only mmap
//! through libstrata-ffi, or a buffer in tests) and copies nothing out of
//! it. Rule sections are still a stub: detection is the protocol layer and
//! the test rule in `tx`.
#![forbid(unsafe_code)]

use crate::bundle::{self, Info, Policy};
use crate::rules::{RuleView, Tables};
use crate::verdict::{E_BUNDLE, E_INVALID, PUBKEY_LEN, Rc};
use strata_hs::MappedDb;

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
        let bytes = (*bundle).as_ref();
        let info = match bundle::verify(bytes, pubkey) {
            Ok(info) => info,
            Err(bundle::Error::BadKey) => {
                return Err((E_INVALID, bundle::Error::BadKey.message()));
            }
            Err(e) => return Err((E_BUNDLE, e.message())),
        };
        // every record is checked once here; later reads are in place
        let tables = Tables::validate(bytes, &info).map_err(|e| (E_BUNDLE, e.message()))?;
        if let Some(hs) = tables.hyperscan() {
            // the image is version-specific; its CRC is checked here, on the
            // mapping itself (hs_scan alone would trust damaged bytecode)
            if hs.version != strata_hs::version().as_bytes() {
                return Err((E_BUNDLE, "bundle built for another Hyperscan version"));
            }
            MappedDb::validate(hs.image).map_err(|e| (E_BUNDLE, e.message()))?;
        }
        Ok(Engine {
            bytes: bundle,
            info,
        })
    }

    pub fn info(&self) -> &Info {
        &self.info
    }

    /// The Hyperscan database of the bundle, validated at map time.
    pub fn hyperscan(&self) -> Option<MappedDb<'_>> {
        self.tables()
            .hyperscan()
            .map(|h| MappedDb::assume_valid(h.image))
    }

    pub fn tables(&self) -> Tables<'_> {
        Tables::view((*self.bytes).as_ref(), &self.info)
    }

    pub fn n_rules(&self) -> usize {
        self.tables().n_rules()
    }

    pub fn rule(&self, i: usize) -> Option<RuleView<'_>> {
        self.tables().rule(i)
    }

    /// Default block page template and support contact, from the bundle.
    pub fn block_page(&self) -> Option<(&[u8], &[u8])> {
        self.tables().block_page()
    }

    /// Index and signed mode of a policy, read from the mapping.
    pub fn policy(&self, name: &[u8]) -> Option<Policy<'_>> {
        bundle::find_policy((*self.bytes).as_ref(), &self.info, name)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bundle::{Mode, Oversize, PolicySpec, Response, Spec, build, public_key};

    pub(crate) const SEED: [u8; 32] = [3; 32];

    pub(crate) fn test_bundle(version: u64) -> Vec<u8> {
        let spec = Spec {
            version,
            created_at_ms: 1,
            flags: 0,
            policies: &[
                PolicySpec::new("example-api", Mode::Enforce, Oversize::Block),
                PolicySpec::new("example-web", Mode::Shadow, Oversize::Pass),
                PolicySpec {
                    response: Response(Response::ALL),
                    ..PolicySpec::new("example-guard", Mode::Enforce, Oversize::Pass)
                },
            ],
            sections: &[],
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
        assert_eq!(e.info().n_policies, 3);
    }

    #[test]
    fn looks_policies_up_in_place() {
        let e = test_engine();
        let p = |n: &[u8]| e.policy(n).map(|p| (p.index, p.mode, p.oversize));
        assert_eq!(p(b"example-api"), Some((0, Mode::Enforce, Oversize::Block)));
        assert_eq!(p(b"example-web"), Some((1, Mode::Shadow, Oversize::Pass)));
        assert_eq!(e.policy(b"example-api").unwrap().response, Response(0));
        assert_eq!(
            e.policy(b"example-guard").unwrap().response,
            Response(Response::ALL)
        );
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
