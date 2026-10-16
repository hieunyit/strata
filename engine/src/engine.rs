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

static NEXT_ENGINE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub struct Engine {
    id: u64,
    bytes: Box<dyn Mapping>,
    info: Info,
    /// some rule runs at stage request_body: transactions keep the request
    /// line, the headers and the body for it
    body_rules: bool,
    raw_body_rules: bool,
    parsed_body_rules: bool,
    /// rx patterns Hyperscan does not take, for the `regex` crate
    regexes: crate::eval::Regexes,
    /// byte ranges and ip match sets evaluated per bundle
    operators: crate::operators::CompiledOperators,
    /// rules the Hyperscan prefilter may skip (W09-R-01)
    prefilter: crate::eval::Prefilter,
    prefilter_on: bool,
    /// per policy index: its privacy settings (P-01 §1)
    privacy: Vec<Option<crate::privacy::Privacy>>,
    exceptions: Vec<Vec<crate::exceptions::Exception>>,
    /// Rule IDs switched off without reloading the bundle (W12-R-02),
    /// sorted; each transaction takes the list current at its start.
    disabled: std::sync::RwLock<std::sync::Arc<[u32]>>,
    /// Replay sampling (W12-N-01), off by default.
    replay: std::sync::RwLock<Option<std::sync::Arc<ReplayConfig>>>,
    /// Requests and inspection gaps per policy (RV-N-01).
    counters: crate::counters::PolicyCounters,
    /// sampled time by rule (W13-R-02)
    rule_costs: crate::rulecost::RuleCosts,
}

/// Most rule IDs `set_disabled_rules` takes at once.
pub const MAX_DISABLED_RULES: usize = 4096;

/// Longest replay key id (control file, docs/design/control-file.md).
pub const MAX_KEY_ID: usize = 16;

/// Replay sampling of an engine (W12-N-01).
pub struct ReplayConfig {
    /// HMAC key of the connector group's samples.
    pub key: [u8; 32],
    pub key_id: String,
    /// Share of transactions sampled, in basis points (1..10000).
    pub rate_bp: u16,
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
        if let Some(hs) = tables.hyperscan_block() {
            // same version as the stream section (Tables::validate)
            MappedDb::validate(hs.image).map_err(|e| (E_BUNDLE, e.message()))?;
        }
        let flagged: Vec<u32> = bundle::policies(bytes, &info)
            .filter(|p| p.privacy)
            .map(|p| p.index)
            .collect();
        let privacy = crate::privacy::parse(
            info.section(bytes, bundle::kind::PRIVACY),
            info.n_policies,
            &flagged,
        )
        .map_err(|e| (E_BUNDLE, e.message()))?;
        let flagged_exceptions: Vec<u32> = bundle::policies(bytes, &info)
            .filter(|p| p.exceptions)
            .map(|p| p.index)
            .collect();
        let parsed_exceptions = crate::exceptions::parse(
            info.section(bytes, bundle::kind::EXCEPTIONS),
            info.n_policies,
            &flagged_exceptions,
        )
        .map_err(|e| (E_BUNDLE, e.message()))?;
        let mut exceptions = vec![vec![]; info.n_policies as usize];
        if !parsed_exceptions.is_empty() {
            let managed = crate::rules::code(crate::rules::LAYERS, "managed");
            let managed_ids: std::collections::HashSet<u32> = (0..tables.n_rules())
                .filter_map(|i| tables.rule(i))
                .filter(|r| Some(r.layer) == managed)
                .map(|r| r.id)
                .collect();
            for e in parsed_exceptions {
                if !managed_ids.contains(&e.rule_id) {
                    return Err((E_BUNDLE, "exception must name an existing managed rule"));
                }
                exceptions[e.policy_index as usize].push(e);
            }
        }
        let body = crate::rules::code(crate::rules::STAGES, "request_body").unwrap_or(u8::MAX);
        let var_req_body =
            crate::rules::code(crate::rules::VARS, "request_body").unwrap_or(u8::MAX);
        let var_args = crate::rules::code(crate::rules::VARS, "args").unwrap_or(u8::MAX);
        let var_args_post = crate::rules::code(crate::rules::VARS, "args_post").unwrap_or(u8::MAX);
        let var_args_names =
            crate::rules::code(crate::rules::VARS, "args_names").unwrap_or(u8::MAX);
        let var_files = crate::rules::code(crate::rules::VARS, "files").unwrap_or(u8::MAX);
        let var_files_names =
            crate::rules::code(crate::rules::VARS, "files_names").unwrap_or(u8::MAX);
        let var_xml = crate::rules::code(crate::rules::VARS, "xml").unwrap_or(u8::MAX);
        let var_xml_attr =
            crate::rules::code(crate::rules::VARS, "xml_attributes").unwrap_or(u8::MAX);

        let mut body_rules = false;
        let mut raw_body_rules = false;
        let mut parsed_body_rules = false;

        for i in 0..tables.n_rules() {
            if let Some(r) = tables.rule(i)
                && r.stage == body
            {
                body_rules = true;
                for ci in r.cond_first..r.cond_first + r.cond_count {
                    if let Some(c) = tables.cond(ci) {
                        for ti in c.target_first..c.target_first + c.target_count {
                            if let Some(t) = tables.target(ti) {
                                if t.var == var_req_body {
                                    raw_body_rules = true;
                                } else if t.var == var_args
                                    || t.var == var_args_post
                                    || t.var == var_args_names
                                    || t.var == var_files
                                    || t.var == var_files_names
                                    || t.var == var_xml
                                    || t.var == var_xml_attr
                                {
                                    parsed_body_rules = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // the signature vouches for the compiler, which checked these
        // patterns; a refusal here is a bundle this build cannot run
        let regexes = crate::eval::Regexes::build(&tables).map_err(|_| {
            (
                E_BUNDLE,
                "bundle has an rx pattern this build cannot compile",
            )
        })?;
        let operators =
            crate::operators::CompiledOperators::build(&tables).map_err(|e| (E_BUNDLE, e))?;
        let prefilter = crate::eval::Prefilter::build(&tables, &regexes);
        let id = NEXT_ENGINE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let n_policies = info.n_policies as usize;
        let n_rules_for_costs = tables.n_rules();
        let engine = Engine {
            id,
            bytes: bundle,
            info,
            body_rules,
            raw_body_rules,
            parsed_body_rules,
            regexes,
            operators,
            prefilter,
            prefilter_on: true,
            privacy,
            exceptions,
            disabled: std::sync::RwLock::new(std::sync::Arc::from([])),
            replay: std::sync::RwLock::new(None),
            counters: crate::counters::PolicyCounters::new(n_policies),
            rule_costs: crate::rulecost::RuleCosts::new(n_rules_for_costs),
        };
        // map runs off the request path (the connector's thread pool): the
        // first request no longer compiles them, which made it fail open
        // with the full package (#49)
        engine.precompile_hot_regexes();
        Ok(engine)
    }

    /// Requests and inspection gaps per policy (RV-N-01).
    pub fn counters(&self) -> &crate::counters::PolicyCounters {
        &self.counters
    }

    /// Sampled time by rule (W13-R-02).
    pub fn rule_costs(&self) -> &crate::rulecost::RuleCosts {
        &self.rule_costs
    }

    /// Privacy settings of the policy at `index`, if it has some.
    pub fn exceptions(&self, index: u32) -> &[crate::exceptions::Exception] {
        self.exceptions
            .get(index as usize)
            .map_or(&[], Vec::as_slice)
    }

    pub fn privacy(&self, index: u32) -> Option<&crate::privacy::Privacy> {
        self.privacy.get(index as usize).and_then(Option::as_ref)
    }

    /// Switches off the rules `ids` (emergency kill switch): they no longer
    /// match in transactions started from now on; an empty list switches
    /// every rule back on. Replaces the previous list. The list belongs to
    /// this engine: the connector applies it again to the engine of a new
    /// bundle.
    pub fn set_disabled_rules(&self, ids: &[u32]) -> Result<(), &'static str> {
        if ids.len() > MAX_DISABLED_RULES {
            return Err("too many rule ids");
        }
        let mut v = ids.to_vec();
        v.sort_unstable();
        v.dedup();
        let mut cur = self.disabled.write().unwrap_or_else(|e| e.into_inner());
        *cur = std::sync::Arc::from(v);
        Ok(())
    }

    /// Samples a share of the transactions started from now on for replay
    /// (W12-N-01): anonymized at once with the connector group's key
    /// (`crate::anon`). None switches sampling off.
    pub fn set_replay(&self, cfg: Option<ReplayConfig>) -> Result<(), &'static str> {
        if let Some(c) = &cfg {
            if c.rate_bp > 10_000 {
                return Err("rate above 100%");
            }
            if c.key_id.is_empty()
                || c.key_id.len() > MAX_KEY_ID
                || !c
                    .key_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err("bad key id");
            }
        }
        let cfg = cfg.filter(|c| c.rate_bp > 0).map(std::sync::Arc::new);
        *self.replay.write().unwrap_or_else(|e| e.into_inner()) = cfg;
        Ok(())
    }

    /// The sampling in force.
    pub fn replay(&self) -> Option<std::sync::Arc<ReplayConfig>> {
        self.replay
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The rules switched off, sorted.
    pub fn disabled_rules(&self) -> std::sync::Arc<[u32]> {
        self.disabled
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Unique engine instance ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// rx patterns evaluated without Hyperscan.
    pub fn regexes(&self) -> &crate::eval::Regexes {
        &self.regexes
    }

    /// Evaluates every rule on every request, as engines before W09 did: the
    /// reference the prefilter differential test compares with.
    pub fn disable_prefilter(&mut self) {
        self.prefilter = crate::eval::Prefilter::default();
        self.prefilter_on = false;
    }

    /// The Hyperscan prefilter of the rules (None once disabled).
    pub fn prefilter_if_on(&self) -> Option<&crate::eval::Prefilter> {
        self.prefilter_on.then_some(&self.prefilter)
    }

    /// The Hyperscan prefilter of the rules.
    pub fn prefilter(&self) -> &crate::eval::Prefilter {
        &self.prefilter
    }

    /// Pre-compiled operator structures (byte ranges, ip match sets).
    pub fn operators(&self) -> &crate::operators::CompiledOperators {
        &self.operators
    }

    /// Whether some rule runs at stage request_body.
    pub fn has_body_rules(&self) -> bool {
        self.body_rules
    }

    /// Whether some rule runs at stage request_body and inspects the raw body directly.
    pub fn has_raw_body_rules(&self) -> bool {
        self.raw_body_rules
    }

    /// Whether some rule runs at stage request_body and inspects parsed body fields (args, xml, files).
    pub fn has_parsed_body_rules(&self) -> bool {
        self.parsed_body_rules
    }

    pub fn info(&self) -> &Info {
        &self.info
    }

    /// The Hyperscan database of the bundle, validated at map time.
    pub fn hyperscan(&self) -> Option<MappedDb<'_>> {
        self.tables()
            .hyperscan()
            .map(|h| MappedDb::assume_valid_with_id(h.image, self.id))
    }

    /// The block-mode copy of the database (HYPERSCAN_BLOCK), validated at
    /// map time; its scratch ID is the one `eval` gives it.
    pub fn hyperscan_block(&self) -> Option<MappedDb<'_>> {
        self.tables()
            .hyperscan_block()
            .map(|h| MappedDb::assume_valid_with_id(h.image, self.id | crate::eval::BLOCK_DB_ID))
    }

    /// Compiles fallback regexes without a selective input gate, including
    /// method-only gates; `map` calls it (#49), outside request evaluation.
    /// Returns how many. Selectively gated rules stay lazy.
    pub fn precompile_hot_regexes(&self) -> usize {
        let tables = self.tables();
        self.prefilter
            .startup_conditions(&tables)
            .filter_map(|ci| self.regexes.get(ci))
            .filter(|fb| fb.compiled().is_some())
            .count()
    }

    /// Warms up thread-local Hyperscan scratch and stream state.
    pub fn warm_thread(&self) {
        if let Some(db) = self.hyperscan() {
            let _ = db.warm_thread();
        }
        if let Some(db) = self.hyperscan_block() {
            let _ = db.warm_block();
        }
    }

    /// Prepare caches on the connector's worker thread before it accepts
    /// requests or publishes a new bundle. Does not create a transaction,
    /// record traffic, or change detection/budget policy.
    pub fn prepare_thread(&self) -> Result<(), String> {
        if let Some(db) = self.hyperscan() {
            db.warm_thread()
                .map_err(|e| format!("stream scratch: {e:?}"))?;
        }
        if let Some(db) = self.hyperscan_block() {
            db.warm_block()
                .map_err(|e| format!("block scratch: {e:?}"))?;
        }
        let tables = self.tables();
        for ci in self.prefilter.startup_conditions(&tables) {
            if let Some((re, _)) = self.regexes.get(ci).and_then(|fb| fb.compiled()) {
                // A bounded nonempty search primes the regex library's
                // worker-local pool; compiling on the loader thread alone
                // does not populate the calling worker's cache.
                let _ = re.is_match(
                    b"ordinary request cache preparation ordinary request cache preparation",
                );
            }
        }
        Ok(())
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

    /// Read policy by its table index directly from the mapping.
    pub fn policy_by_index(&self, index: u32) -> Option<Policy<'_>> {
        bundle::policy_by_index((*self.bytes).as_ref(), &self.info, index)
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
                PolicySpec {
                    canary: 1000,
                    ..PolicySpec::new("example-canary", Mode::Enforce, Oversize::Pass)
                },
                PolicySpec {
                    snippet: crate::bundle::SnippetSize::Kb4,
                    ..PolicySpec::new("example-snippet", Mode::Enforce, Oversize::Pass)
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
        assert_eq!(e.info().n_policies, 5);
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
