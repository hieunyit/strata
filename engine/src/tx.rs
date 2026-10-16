//! Transaction state: runs the detectors and turns violations into a verdict.
//!
//! Every violation adds its rule id and score; the request is blocked when a
//! violation blocks alone (ambiguous requests) or the total score reaches
//! `BLOCK_THRESHOLD`. Detectors: the protocol layer, and the stub rule that
//! fires when the URI, query or body contains `STRATA-TEST-BLOCK` (body
//! matching works across chunks by keeping the last `NEEDLE.len() - 1`
//! bytes of the previous chunk).
#![forbid(unsafe_code)]

use std::sync::Arc;

use crate::block_id::{self, Kind};
use crate::bundle::Response;
use crate::detectors::response::{self, cccd, db_errors, jwt, pan};
use crate::detectors::{Violation, protocol};
use crate::engine::Engine;
use crate::eval;
use crate::event;
use crate::guard::{self, Feed, Guard};
use crate::verdict::*;

pub(crate) const NEEDLE: &[u8] = b"STRATA-TEST-BLOCK";
/// Rule id reported by the stub rule (organization range 800000–899999).
pub(crate) const STUB_RULE_ID: u32 = 899_001;
const STUB_SCORE: i32 = 100;
/// Total score that blocks. Provisional: policies will carry per-route
/// thresholds.
pub const BLOCK_THRESHOLD: i32 = 100;
const TAIL: usize = NEEDLE.len() - 1;

#[cfg(feature = "test-hooks")]
pub(crate) const PANIC_NEEDLE: &[u8] = b"STRATA-TEST-PANIC";
/// test-hooks: masked in responses, like a data guard detector would
#[cfg(feature = "test-hooks")]
pub(crate) const MASK_NEEDLE: &[u8] = b"STRATA-TEST-MASK";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    New,
    Line,
    Headers,
    BodyDone,
    Response,
}

/// Copy of the request line, kept from `request_line` until the headers
/// arrive (connector buffers are only borrowed per call). Made only when
/// the bundle has rules to evaluate.
#[derive(Debug, Default)]
struct Line {
    buf: Vec<u8>,
    /// method, raw_uri, uri, args, proto, client_addr
    ends: [usize; 6],
}

impl Line {
    fn part(&self, i: usize) -> &[u8] {
        let start = if i == 0 { 0 } else { self.ends[i - 1] };
        &self.buf[start..self.ends[i]]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MatchEntry {
    pub rule_id: u32,
    pub layer: &'static str,
    pub field: String,
    pub snippet: Vec<u8>,
}

#[derive(Debug)]
pub struct Tx {
    engine: Option<Arc<Engine>>,
    client_addr: [u8; 64],
    client_addr_len: usize,
    line: Option<Line>,
    node: u16,
    shadow: bool,
    /// Canary group from `set_policy` (W12-G2-01).
    canary: crate::event::CanaryGroup,
    json: bool,
    /// the policy blocks request bodies larger than what is inspected
    oversize_block: bool,
    /// response layer switches of the policy
    response: Response,
    /// longest snippet of a match in the event (the policy's
    /// max_snippet_size)
    snippet_max: usize,
    /// response body scanner (data guard, detectors), when one is on
    guard: Option<Guard>,
    stage: Stage,
    error: Rc,
    /// blocked (or would be, in shadow)
    matched: bool,
    rules: [u32; MAX_RULES],
    n_rules: usize,
    score: i32,
    headers: protocol::Headers,
    /// Request headers kept for the request_body rules (only when the
    /// bundle has some); afterwards they stay for the event's context.
    kept_headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// Request headers for the event's context (RV-G2-01) when the bundle
    /// has no request_body rule: copied, bounded, only once the request
    /// has an Event or Block ID at the headers stage.
    event_headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// the connector reported body bytes it did not pass (RV-N-01)
    body_skipped: bool,
    /// the policy's max_args (0 = the engine's limit), and whether some
    /// arguments were left out (rule 100021, #28)
    max_args: usize,
    args_left_out: bool,
    /// #98: the policy fails closed when the budget runs out on findings
    fail_on_findings: bool,
    /// W13-R-02: this transaction is sampled for the cost of each rule;
    /// the times of its evaluations, by rule index (None: the scans)
    cost_sampled: bool,
    costs: crate::rulecost::Samples,
    /// Body bytes for the request_body rules, at most MAX_BODY_KEEP.
    body: Vec<u8>,
    /// test-hooks only: what the connector passed, for integration tests
    #[cfg(feature = "test-hooks")]
    echo: Option<(String, bool)>,
    id: Option<[u8; block_id::ID_LEN]>,
    /// engine time spent on this request, in nanoseconds
    elapsed_ns: u64,
    tail: [u8; TAIL],
    tail_len: usize,
    node_id: [u8; 64],
    node_id_len: usize,
    policy_index: Option<u32>,
    unmatched_policy: [u8; 64],
    unmatched_policy_len: usize,
    bundle_version: u64,
    identity: [u8; 128],
    identity_len: usize,
    request_id: [u8; 64],
    request_id_len: usize,
    host: [u8; 255],
    host_len: usize,
    method: [u8; 16],
    method_len: usize,
    path: [u8; 1024],
    path_len: usize,
    status: u32,
    layer_scores: [i32; 6],
    protocol_score: i32,
    matches: Vec<MatchEntry>,
    budget: Option<crate::budget::TxBudget>,
    degraded: bool,
    /// signature pack of the policy (RV-S-01); in shadow its rules keep
    /// their own score and never block
    signatures: crate::bundle::Signatures,
    sig_score: i32,
    sig_matched: bool,
    /// rules switched off on the engine when the transaction started
    disabled: Arc<[u32]>,
    /// what a sampled transaction keeps for replay (W12-N-01)
    sample: Option<Box<SampleData>>,
    has_body_rules: bool,
    buffer_body: bool,
    tail_has_s: bool,
}

/// Body bytes a replay sample keeps: a sample travels as one datagram of
/// the event socket (8 KB) and anonymization makes values longer.
pub const SAMPLE_MAX_BODY: usize = 4096;
/// Request line fields and header bytes a sample keeps.
const SAMPLE_MAX_FIELD: usize = 2048;
const SAMPLE_MAX_HEADERS: usize = 4096;

/// What a sampled transaction keeps until the sample is encoded.
struct SampleData {
    cfg: Arc<crate::engine::ReplayConfig>,
    ts_ms: i64,
    method: Vec<u8>,
    raw_uri: Vec<u8>,
    uri: Vec<u8>,
    args: Vec<u8>,
    proto: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    header_bytes: usize,
    body: Vec<u8>,
    body_len: usize,
}

// neither the key nor the request in debug output
impl std::fmt::Debug for SampleData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SampleData")
            .field("key_id", &self.cfg.key_id)
            .finish_non_exhaustive()
    }
}

impl SampleData {
    fn new(cfg: Arc<crate::engine::ReplayConfig>) -> Self {
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        SampleData {
            cfg,
            ts_ms,
            method: vec![],
            raw_uri: vec![],
            uri: vec![],
            args: vec![],
            proto: vec![],
            headers: vec![],
            header_bytes: 0,
            body: vec![],
            body_len: 0,
        }
    }

    /// Headers in arrival order while they fit SAMPLE_MAX_HEADERS.
    fn add_headers(&mut self, headers: &[(&[u8], &[u8])]) {
        for (k, v) in headers {
            if self.header_bytes + k.len() + v.len() > SAMPLE_MAX_HEADERS {
                return;
            }
            self.header_bytes += k.len() + v.len();
            self.headers.push((k.to_vec(), v.to_vec()));
        }
    }
}

/// Body bytes the request_body rules see at most; the connector's
/// strata_request_body_limit (1 MB by default) is normally lower.
const MAX_BODY_KEEP: usize = 8 << 20;

static NEEDLE_FINDER: std::sync::LazyLock<memchr::memmem::Finder<'static>> =
    std::sync::LazyLock::new(|| memchr::memmem::Finder::new(NEEDLE));

#[cfg(feature = "test-hooks")]
static PANIC_FINDER: std::sync::LazyLock<memchr::memmem::Finder<'static>> =
    std::sync::LazyLock::new(|| memchr::memmem::Finder::new(PANIC_NEEDLE));

fn contains_needle(hay: &[u8]) -> bool {
    hay.len() >= NEEDLE.len() && NEEDLE_FINDER.find(hay).is_some()
}

#[cfg(feature = "test-hooks")]
fn contains_panic(hay: &[u8]) -> bool {
    hay.len() >= PANIC_NEEDLE.len() && PANIC_FINDER.find(hay).is_some()
}

fn contains_ignore_case(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len()
        && hay
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

impl Tx {
    /// Without an engine (no bundle loaded) the transaction starts in
    /// `E_BUNDLE`, so the connector applies its fail mode but still
    /// gets an Event ID.
    pub fn new(engine: Option<Arc<Engine>>, node_id: &[u8], flags: u32) -> Tx {
        let missing = engine.is_none();
        let version = engine.as_ref().map_or(0, |e| e.info().version);
        let has_body_rules = engine.as_ref().is_some_and(|e| e.has_body_rules());
        let disabled = engine
            .as_ref()
            .map_or_else(|| Arc::from([]), |e| e.disabled_rules());
        let node_id_bounded = &node_id[..node_id.len().min(64)];
        let mut node_buf = [0u8; 64];
        node_buf[..node_id_bounded.len()].copy_from_slice(node_id_bounded);
        let mut tx = Tx {
            engine,
            client_addr: [0u8; 64],
            client_addr_len: 0,
            line: None,
            node: block_id::node_hash(node_id),
            shadow: flags & TXF_FORCE_SHADOW != 0,
            canary: crate::event::CanaryGroup::None,
            json: false,
            oversize_block: false,
            response: Response::default(),
            guard: None,
            stage: Stage::New,
            error: OK,
            matched: false,
            rules: [0; MAX_RULES],
            n_rules: 0,
            score: 0,
            headers: protocol::Headers::default(),
            kept_headers: Vec::new(),
            snippet_max: crate::event::MAX_SNIPPET_LEN,
            event_headers: Vec::new(),
            body_skipped: false,
            max_args: 0,
            fail_on_findings: false,
            args_left_out: false,
            cost_sampled: !missing && crate::rulecost::should_sample(),
            costs: std::cell::RefCell::new(Vec::new()),
            body: Vec::new(),
            #[cfg(feature = "test-hooks")]
            echo: None,
            id: None,
            elapsed_ns: 0,
            tail: [0; TAIL],
            tail_len: 0,
            node_id: node_buf,
            node_id_len: node_id_bounded.len(),
            policy_index: None,
            unmatched_policy: [0u8; 64],
            unmatched_policy_len: 0,
            bundle_version: version,
            identity: [0u8; 128],
            identity_len: 0,
            request_id: [0u8; 64],
            request_id_len: 0,
            host: [0u8; 255],
            host_len: 0,
            method: [0u8; 16],
            method_len: 0,
            path: [0u8; 1024],
            path_len: 0,
            status: 0,
            layer_scores: [0; 6],
            protocol_score: 0,
            matches: Vec::new(),
            budget: None,
            degraded: flags & TXF_DEGRADED != 0,
            signatures: crate::bundle::Signatures::Shadow,
            sig_score: 0,
            sig_matched: false,
            disabled,
            sample: None,
            has_body_rules,
            buffer_body: has_body_rules,
            tail_has_s: false,
        };
        if missing {
            tx.fail(E_BUNDLE);
        }
        if let Some(cfg) = tx.engine.as_ref().and_then(|e| e.replay())
            && block_id::next_rand() % 10_000 < u32::from(cfg.rate_bp)
        {
            tx.sample = Some(Box::new(SampleData::new(cfg)));
        }
        tx
    }

    /// The transaction is sampled for replay.
    pub fn sampled(&self) -> bool {
        self.sample.is_some()
    }

    pub fn set_budget(&mut self, cpu_budget_us: u64) {
        if cpu_budget_us > 0 {
            self.budget = Some(crate::budget::TxBudget::new(cpu_budget_us));
        }
    }

    pub fn budget_elapsed_us(&self) -> u64 {
        self.budget.as_ref().map_or(0, |b| b.elapsed_us())
    }

    /// Warms up thread-local engine resources (Hyperscan scratch, etc.)
    pub fn warm_engine(&self) {
        if let Some(e) = self.engine.as_ref() {
            e.warm_thread();
        }
    }

    pub fn set_degraded(&mut self, degraded: bool) {
        self.degraded = degraded;
    }

    pub fn budget_enter(&mut self) -> Result<(), crate::budget::BudgetExceeded> {
        if let Some(bgt) = self.budget.as_mut() {
            match bgt.enter() {
                Ok(()) => {}
                Err(e) => {
                    self.set_budget_exceeded();
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub fn budget_enter_lazy(&mut self) -> Result<(), crate::budget::BudgetExceeded> {
        if let Some(bgt) = self.budget.as_mut() {
            match bgt.enter_lazy() {
                Ok(()) => {}
                Err(e) => {
                    self.set_budget_exceeded();
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub fn budget_enter_at(
        &mut self,
        now: std::time::Instant,
    ) -> Result<(), crate::budget::BudgetExceeded> {
        if let Some(bgt) = self.budget.as_mut() {
            match bgt.enter_at(now) {
                Ok(()) => {}
                Err(e) => {
                    self.set_budget_exceeded();
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub fn budget_exit(&mut self) {
        if let Some(bgt) = self.budget.as_mut() {
            bgt.exit();
            if bgt.is_exceeded() {
                self.set_budget_exceeded();
            }
        }
    }

    pub fn budget_exit_with_ns(&mut self, nanos: u64) {
        if let Some(bgt) = self.budget.as_mut() {
            bgt.exit_with_ns(nanos);
            if bgt.is_exceeded() {
                self.set_budget_exceeded();
            }
        }
    }

    pub fn budget_exit_with(&mut self, elapsed: std::time::Duration) {
        if let Some(bgt) = self.budget.as_mut() {
            bgt.exit_with(elapsed);
            if bgt.is_exceeded() {
                self.set_budget_exceeded();
            }
        }
    }

    pub fn set_budget_exceeded(&mut self) {
        if self.matched {
            return;
        }
        if self.error == OK {
            self.error = E_BUDGET;
        }
        if self.id.is_none() {
            self.id = Some(block_id::generate(Kind::Event, self.node));
        }
    }

    /// Applies the policy's settings: its signed mode (a shadow policy
    /// never blocks, whatever the connector asks), its enforce canary (a
    /// client outside the canary group runs in shadow, `crate::canary`),
    /// oversize handling and response layer. An unknown policy keeps the
    /// defaults. Call after `set_identity` and `set_client_addr`: the
    /// canary group comes from them.
    pub fn set_policy(&mut self, name: &[u8]) {
        let len = name.len().min(self.unmatched_policy.len());
        self.unmatched_policy[..len].copy_from_slice(&name[..len]);
        self.unmatched_policy_len = len;
        if let Some(p) = self.engine.as_ref().and_then(|e| e.policy(name)) {
            self.policy_index = Some(p.index);
            // Only towards shadow: nothing lifts TXF_FORCE_SHADOW.
            self.shadow |= p.mode == crate::bundle::Mode::Shadow;
            let key = crate::canary::key(
                &self.identity[..self.identity_len],
                &self.client_addr[..self.client_addr_len],
            );
            let enforced = crate::canary::enforced(name, key, p.canary);
            self.shadow |= !enforced;
            // the group follows the hash, also under TXF_FORCE_SHADOW: the
            // control plane compares the two sides (W12-G2-01)
            self.canary = match (p.canary, enforced) {
                (0, _) => crate::event::CanaryGroup::None,
                (_, true) => crate::event::CanaryGroup::Enforce,
                (_, false) => crate::event::CanaryGroup::Shadow,
            };
            self.oversize_block = p.oversize == crate::bundle::Oversize::Block;
            self.response = p.response;
            self.signatures = p.signatures;
            self.snippet_max = p.snippet.bytes();
            self.max_args = p.max_args;
            self.fail_on_findings = p.fail_on_findings;
        } else {
            self.policy_index = None;
            self.canary = crate::event::CanaryGroup::None;
        }
    }

    /// Canary group of the transaction (W12-G2-01).
    pub fn canary(&self) -> crate::event::CanaryGroup {
        self.canary
    }

    /// Client identity for event reporting (at most 128 bytes).
    pub fn set_identity(&mut self, identity: &[u8]) {
        let len = identity.len().min(self.identity.len());
        self.identity[..len].copy_from_slice(&identity[..len]);
        self.identity_len = len;
    }

    /// Request id for event reporting (at most 64 bytes).
    pub fn set_request_id(&mut self, request_id: &[u8]) {
        let len = request_id.len().min(self.request_id.len());
        self.request_id[..len].copy_from_slice(&request_id[..len]);
        self.request_id_len = len;
    }

    /// The connector inspected only part of the body: `bytes` were not
    /// passed. Rule 100020, blocking or recorded per the policy's
    /// `oversize`.
    pub fn request_body_skipped(&mut self, bytes: u64) -> Rc {
        if let Err(rc) = self.check(Stage::Headers, Stage::BodyDone) {
            return rc;
        }
        if bytes > 0 {
            self.body_skipped = true;
            self.add(Violation {
                signature: false,
                rule: protocol::BODY_OVER_LIMIT,
                score: 0,
                block_alone: self.oversize_block,
                layer: "protocol",
                field: "REQUEST_BODY".to_string(),
                snippet: Vec::new(),
            });
        }
        OK
    }

    /// Client address for rules on `remote_addr` (copied up to 64 bytes).
    pub fn set_client_addr(&mut self, addr: &[u8]) {
        let len = addr.len().min(self.client_addr.len());
        self.client_addr[..len].copy_from_slice(&addr[..len]);
        self.client_addr_len = len;
    }

    fn has_rules(&self) -> bool {
        self.engine.as_ref().is_some_and(|e| e.n_rules() > 0)
    }

    /// Adds engine time measured by the caller around one call.
    pub fn add_time(&mut self, d: std::time::Duration) {
        self.elapsed_ns = self
            .elapsed_ns
            .saturating_add(d.as_nanos().min(u64::MAX as u128) as u64);
    }

    pub fn add_time_ns(&mut self, nanos: u64) {
        self.elapsed_ns = self.elapsed_ns.saturating_add(nanos);
    }

    /// Engine time spent on this request so far, in microseconds.
    pub fn time_us(&self) -> u64 {
        self.elapsed_ns / 1000
    }

    /// Whether this request has already matched a blocking or logging rule.
    pub fn is_matched(&self) -> bool {
        self.matched
    }

    /// Marks the transaction broken; the first error wins. A request already
    /// matched by security rules retains its block decision.
    pub fn fail(&mut self, rc: Rc) {
        if self.matched {
            return;
        }
        if self.error == OK {
            self.error = rc;
        }
        if self.id.is_none() {
            self.id = Some(block_id::generate(Kind::Event, self.node));
        }
    }

    fn check(&self, at_least: Stage, before: Stage) -> Result<(), Rc> {
        if self.error != OK {
            return Err(self.error);
        }
        if self.stage < at_least || self.stage >= before {
            return Err(E_STATE);
        }
        Ok(())
    }

    fn hit(&mut self) {
        if !self.matched {
            self.matched = true;
            let kind = if self.shadow {
                Kind::Event
            } else {
                Kind::Block
            };
            self.id = Some(block_id::generate(kind, self.node));
        }
    }

    /// The snippet an event keeps for a violation: masked (built-in masks
    /// and the policy's privacy settings) and cut to the policy's
    /// max_snippet_size. Every path that records a match goes through it.
    fn event_snippet(&self, field: &str, raw: &[u8]) -> Vec<u8> {
        let privacy = self
            .engine
            .as_deref()
            .zip(self.policy_index)
            .and_then(|(e, i)| e.privacy(i));
        crate::event::prepare_snippet_with(field, raw, self.snippet_max, privacy)
    }

    /// Records a violation once; decides when it blocks alone or the
    /// total reaches the threshold.
    fn is_disabled(&self, rule: u32) -> bool {
        !self.disabled.is_empty() && self.disabled.binary_search(&rule).is_ok()
    }

    fn add(&mut self, mut v: Violation) {
        if self.rules[..self.n_rules].contains(&v.rule) || self.is_disabled(v.rule) {
            return;
        }
        if v.rule == protocol::BODY_UNPARSED
            && (self.body_skipped
                || self.rules[..self.n_rules].contains(&protocol::BODY_OVER_LIMIT))
        {
            // a body cut at the connector's limit never parses to its
            // end: 100020 already says so
            return;
        }
        if v.rule == protocol::ARGS_OVER_LIMIT
            || v.rule == protocol::BODY_UNPARSED
            || v.rule == protocol::BODY_ENCODED
        {
            // like a body over the limit (100020): the policy's oversize
            v.block_alone = self.oversize_block;
            self.args_left_out = true;
        }
        if self.n_rules < MAX_RULES {
            self.rules[self.n_rules] = v.rule;
            self.n_rules += 1;
        }
        let sig_shadow = v.signature && self.signatures == crate::bundle::Signatures::Shadow;
        if sig_shadow {
            // reported, never blocks: a would-be block of the signature
            // pack is logged with an Event ID, like a shadow policy
            self.sig_score = self.sig_score.saturating_add(v.score);
            if self.matches.len() < MAX_RULES {
                let snippet = self.event_snippet(&v.field, &v.snippet);
                self.matches.push(MatchEntry {
                    rule_id: v.rule,
                    layer: v.layer,
                    field: v.field,
                    snippet,
                });
            }
            if (v.block_alone || self.sig_score >= BLOCK_THRESHOLD) && !self.sig_matched {
                self.sig_matched = true;
                if self.id.is_none() {
                    self.id = Some(block_id::generate(Kind::Event, self.node));
                }
            }
            return;
        }
        self.score = self.score.saturating_add(v.score);
        match v.layer {
            "pre" => self.layer_scores[0] = self.layer_scores[0].saturating_add(v.score),
            "protocol" => {
                self.layer_scores[1] = self.layer_scores[1].saturating_add(v.score);
                self.protocol_score = self.layer_scores[1];
            }
            "rate" => self.layer_scores[2] = self.layer_scores[2].saturating_add(v.score),
            "managed" => self.layer_scores[3] = self.layer_scores[3].saturating_add(v.score),
            "custom-post" => self.layer_scores[4] = self.layer_scores[4].saturating_add(v.score),
            "response" => self.layer_scores[5] = self.layer_scores[5].saturating_add(v.score),
            _ => {}
        }
        if self.matches.len() < MAX_RULES {
            let snippet = self.event_snippet(&v.field, &v.snippet);
            self.matches.push(MatchEntry {
                rule_id: v.rule,
                layer: v.layer,
                field: v.field,
                snippet,
            });
        }
        if v.block_alone || self.score >= BLOCK_THRESHOLD {
            self.hit();
        }
    }

    /// Records a response-layer finding: listed with the rules, but the
    /// decision was taken with the request; an Event ID identifies it.
    fn record(&mut self, rule: u32) {
        if self.rules[..self.n_rules].contains(&rule) || self.is_disabled(rule) {
            return;
        }
        if self.n_rules < MAX_RULES {
            self.rules[self.n_rules] = rule;
            self.n_rules += 1;
        }
        let (field, raw_snippet) = match rule {
            response::STATUS_NOT_ALLOWED => ("RESPONSE_STATUS".to_string(), Vec::new()),
            cccd::RULE => ("RESPONSE_BODY".to_string(), b"************".to_vec()),
            jwt::RULE => ("RESPONSE_BODY".to_string(), b"***".to_vec()),
            pan::RULE => ("RESPONSE_BODY".to_string(), b"****************".to_vec()),
            _ => ("RESPONSE_BODY".to_string(), Vec::new()),
        };
        if self.matches.len() < MAX_RULES {
            let snippet = self.event_snippet(&field, &raw_snippet);
            self.matches.push(MatchEntry {
                rule_id: rule,
                layer: "response",
                field,
                snippet,
            });
        }
        if self.id.is_none() {
            self.id = Some(block_id::generate(Kind::Event, self.node));
        }
    }

    fn stub_rule(&mut self, field: &str, data: &[u8]) {
        // add() masks and cuts it to the policy's size
        let snippet = data[..data.len().min(event::MASK_WINDOW)].to_vec();
        self.add(Violation {
            signature: false,
            rule: STUB_RULE_ID,
            score: STUB_SCORE,
            block_alone: false,
            layer: "managed",
            field: field.to_string(),
            snippet,
        });
    }

    fn scan(&mut self, data: &[u8], field: &str) {
        // The test hooks stand for the full engine: degraded mode skips them.
        if self.degraded {
            return;
        }
        #[cfg(feature = "test-hooks")]
        if contains_panic(data) {
            panic!("test hook: deliberate panic");
        }
        if !self.matched && contains_needle(data) {
            self.stub_rule(field, data);
        }
    }

    pub fn request_line(
        &mut self,
        _method: &[u8],
        raw_uri: &[u8],
        norm_uri: &[u8],
        args: &[u8],
        _proto: &[u8],
    ) -> Rc {
        if let Err(rc) = self.check(Stage::New, Stage::Line) {
            return rc;
        }
        self.stage = Stage::Line;
        if let Some(s) = self.sample.as_mut() {
            for (dst, src) in [
                (&mut s.method, _method),
                (&mut s.raw_uri, raw_uri),
                (&mut s.uri, norm_uri),
                (&mut s.args, args),
                (&mut s.proto, _proto),
            ] {
                dst.extend_from_slice(&src[..src.len().min(SAMPLE_MAX_FIELD)]);
            }
        }
        let m_len = _method.len().min(self.method.len());
        self.method[..m_len].copy_from_slice(&_method[..m_len]);
        self.method_len = m_len;

        let p = if !norm_uri.is_empty() {
            norm_uri
        } else {
            raw_uri
        };
        let p_no_query = match p.iter().position(|&b| b == b'?') {
            Some(idx) => &p[..idx],
            None => p,
        };
        let p_len = p_no_query.len().min(self.path.len());
        self.path[..p_len].copy_from_slice(&p_no_query[..p_len]);
        self.path_len = p_len;

        #[cfg(feature = "test-hooks")]
        {
            let e = |b: &[u8]| b.escape_ascii().to_string();
            self.echo = Some((
                format!(
                    "strata-test-echo method=\"{}\" raw=\"{}\" norm=\"{}\" args=\"{}\" proto=\"{}\" headers=",
                    e(_method),
                    e(raw_uri),
                    e(norm_uri),
                    e(args),
                    e(_proto)
                ),
                false,
            ));
        }
        if self.has_rules() {
            let mut line = Line::default();
            for (i, part) in [
                _method,
                raw_uri,
                norm_uri,
                args,
                _proto,
                &self.client_addr[..self.client_addr_len],
            ]
            .iter()
            .enumerate()
            {
                line.buf.extend_from_slice(part);
                line.ends[i] = line.buf.len();
            }
            self.line = Some(line);
        }
        protocol::check_uri(raw_uri, &mut |v| self.add(v));
        self.scan(raw_uri, "URI_RAW");
        self.scan(norm_uri, "URI");
        self.scan(args, "ARGS");
        OK
    }

    pub fn request_header(&mut self, key: &[u8], val: &[u8]) -> Rc {
        if let Err(rc) = self.check(Stage::Line, Stage::Headers) {
            return rc;
        }
        if key.eq_ignore_ascii_case(b"host") && self.host_len == 0 {
            let len = val.len().min(self.host.len());
            self.host[..len].copy_from_slice(&val[..len]);
            self.host_len = len;
        }
        self.headers.header(key, val);
        #[cfg(feature = "test-hooks")]
        if !self.degraded && (contains_panic(key) || contains_panic(val)) {
            panic!("test hook: deliberate panic");
        }
        #[cfg(feature = "test-hooks")]
        if let Some((line, on)) = &mut self.echo {
            line.push_str(&format!("[{}: {}]", key.escape_ascii(), val.escape_ascii()));
            *on |= key.eq_ignore_ascii_case(b"x-strata-test-echo");
        }
        if key.eq_ignore_ascii_case(b"accept")
            && contains_ignore_case(val, b"json")
            && !contains_ignore_case(val, b"text/html")
        {
            self.json = true;
        }
        OK
    }

    pub fn request_headers_done(&mut self) -> Rc {
        if let Err(rc) = self.check(Stage::Line, Stage::Headers) {
            return rc;
        }
        self.stage = Stage::Headers;
        // Test hook: print what libstrata received (stderr is the NGINX
        // error log). Compiled only with the test-hooks feature.
        #[cfg(feature = "test-hooks")]
        if let Some((line, true)) = self.echo.take() {
            eprintln!("{line}");
        }
        let headers = std::mem::take(&mut self.headers);
        headers.finish(&mut |v| self.add(v));
        OK
    }

    /// All headers in one call: protocol checks, then the rules of stage
    /// `request_headers` over the request line and these headers.
    pub fn request_headers(&mut self, headers: &[(&[u8], &[u8])]) -> Rc {
        if let Some(s) = self.sample.as_mut() {
            s.add_headers(headers);
        }
        for (k, v) in headers {
            let rc = self.request_header(k, v);
            if rc != OK {
                return rc;
            }
        }
        let rc = self.request_headers_done();
        if rc != OK {
            return rc;
        }
        if let (Some(engine), Some(line)) = (self.engine.clone(), self.line.take()) {
            let req = eval::Request {
                method: line.part(0),
                raw_uri: line.part(1),
                uri: line.part(2),
                args: line.part(3),
                proto: line.part(4),
                client_addr: line.part(5),
                headers,
                body: b"",
                max_args: self.max_args,
                costs: self.cost_sampled.then_some(&self.costs),
            };
            let stage = crate::rules::code(crate::rules::STAGES, "request_headers").unwrap_or(0);
            let mut found = vec![];
            let res = eval::evaluate_with_budget(
                engine.id(),
                &engine.tables(),
                engine.hyperscan(),
                engine.regexes(),
                engine.operators(),
                engine.prefilter_if_on(),
                &req,
                stage,
                self.degraded,
                self.signatures != crate::bundle::Signatures::Off,
                &self.disabled,
                self.policy_index
                    .map(|index| (index, engine.exceptions(index))),
                self.budget.as_mut(),
                &mut |v| found.push(v),
            );
            if res.is_err() {
                self.set_budget_exceeded();
                return E_BUDGET;
            }
            for v in found {
                self.add(v);
            }
            let ct = eval::content_type(headers);
            let proc = eval::body_processor(ct);
            self.buffer_body =
                engine.has_raw_body_rules() || (engine.has_parsed_body_rules() && !proc.is_empty());
            self.has_body_rules = engine.has_body_rules();

            if self.has_body_rules {
                self.kept_headers = headers
                    .iter()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect();
                self.line = Some(line);
            }
        }
        // an event already (blocked, or would be, or an error): keep its
        // context; clean requests copy nothing more
        if self.id.is_some() && self.kept_headers.is_empty() {
            self.event_headers = keep_for_event(headers);
        }
        OK
    }

    /// Runs the request_body rules over the line, the headers and the body.
    fn evaluate_body_bytes(&mut self, body: &[u8]) {
        let (Some(engine), Some(line)) = (self.engine.clone(), self.line.take()) else {
            return;
        };
        let headers: Vec<(&[u8], &[u8])> = self
            .kept_headers
            .iter()
            .map(|(k, v)| (&k[..], &v[..]))
            .collect();
        let req = eval::Request {
            method: line.part(0),
            raw_uri: line.part(1),
            uri: line.part(2),
            args: line.part(3),
            proto: line.part(4),
            client_addr: line.part(5),
            headers: &headers,
            body,
            max_args: self.max_args,
            costs: self.cost_sampled.then_some(&self.costs),
        };
        let stage = crate::rules::code(crate::rules::STAGES, "request_body").unwrap_or(0);
        let mut found = vec![];
        let res = eval::evaluate_with_budget(
            engine.id(),
            &engine.tables(),
            engine.hyperscan(),
            engine.regexes(),
            engine.operators(),
            engine.prefilter_if_on(),
            &req,
            stage,
            self.degraded,
            self.signatures != crate::bundle::Signatures::Off,
            &self.disabled,
            self.policy_index
                .map(|index| (index, engine.exceptions(index))),
            self.budget.as_mut(),
            &mut |v| found.push(v),
        );
        drop(headers);
        if res.is_err() {
            self.set_budget_exceeded();
        } else {
            for v in found {
                self.add(v);
            }
        }
        self.body = Vec::new();
        // the headers stay for the event's context (moved, not copied)
    }

    fn evaluate_body(&mut self) {
        let body = std::mem::take(&mut self.body);
        self.evaluate_body_bytes(&body);
    }

    pub fn request_body_chunk(&mut self, data: &[u8], last: bool) -> Rc {
        if let Err(rc) = self.check(Stage::Headers, Stage::BodyDone) {
            return rc;
        }
        if let Some(s) = self.sample.as_mut() {
            let room = SAMPLE_MAX_BODY.saturating_sub(s.body.len());
            s.body.extend_from_slice(&data[..data.len().min(room)]);
            s.body_len += data.len();
        }
        if self.matched {
            if last {
                self.stage = Stage::BodyDone;
            }
            return OK;
        }
        let has_s = memchr::memchr(b'S', data).is_some();
        #[cfg(feature = "test-hooks")]
        if has_s && !self.degraded && contains_panic(data) {
            panic!("test hook: deliberate panic");
        }
        if !self.matched && !self.degraded {
            let head = &data[..data.len().min(TAIL)];
            let head_has_s = has_s && memchr::memchr(b'S', head).is_some();
            if self.tail_has_s || head_has_s {
                let tail = &self.tail[..self.tail_len];
                let mut window = [0u8; 2 * TAIL];
                window[..self.tail_len].copy_from_slice(tail);
                window[self.tail_len..self.tail_len + head.len()].copy_from_slice(head);
                if contains_needle(&window[..self.tail_len + head.len()]) {
                    self.stub_rule("REQUEST_BODY", data);
                }
            }
            if has_s && data.len() > TAIL && contains_needle(data) {
                self.stub_rule("REQUEST_BODY", data);
            }
            // Keep the last TAIL bytes of (tail + data).
            let total = self.tail_len + data.len();
            if data.len() >= TAIL {
                self.tail.copy_from_slice(&data[data.len() - TAIL..]);
                self.tail_len = TAIL;
                self.tail_has_s = has_s && memchr::memchr(b'S', &self.tail).is_some();
            } else {
                let keep_old = TAIL.min(total) - data.len();
                self.tail
                    .copy_within(self.tail_len - keep_old..self.tail_len, 0);
                self.tail[keep_old..keep_old + data.len()].copy_from_slice(data);
                self.tail_len = keep_old + data.len();
                self.tail_has_s = memchr::memchr(b'S', &self.tail[..self.tail_len]).is_some();
            }
        }
        if last {
            self.stage = Stage::BodyDone;
            if self.has_body_rules && !self.matched {
                if self.body.is_empty() {
                    let to_take = data.len().min(MAX_BODY_KEEP);
                    self.evaluate_body_bytes(&data[..to_take]);
                } else {
                    if self.buffer_body && self.body.len() < MAX_BODY_KEEP {
                        let room = MAX_BODY_KEEP - self.body.len();
                        let to_take = data.len().min(room);
                        self.body.extend_from_slice(&data[..to_take]);
                    }
                    self.evaluate_body();
                }
                if self.error == E_BUDGET {
                    return E_BUDGET;
                }
            }
        } else if self.buffer_body && !self.matched && self.body.len() < MAX_BODY_KEEP {
            let room = MAX_BODY_KEEP - self.body.len();
            let to_take = data.len().min(room);
            self.body.extend_from_slice(&data[..to_take]);
        }
        OK
    }

    /// Response body scanners of the policy (and the test-hooks literal).
    fn response_matchers(&self) -> Vec<Box<dyn guard::Matcher>> {
        let mut m: Vec<Box<dyn guard::Matcher>> = Vec::new();
        #[cfg(feature = "test-hooks")]
        m.push(Box::new(guard::Literal(MASK_NEEDLE)));
        if self.response.has(Response::GUARD_CCCD) {
            m.push(Box::new(cccd::Cccd));
        }
        if self.response.has(Response::GUARD_JWT) {
            m.push(Box::new(jwt::Jwt::new()));
        }
        if self.response.has(Response::GUARD_PAN) {
            m.push(Box::new(pan::Pan));
        }
        if self.response.has(Response::DB_ERRORS) {
            m.push(Box::new(db_errors::DbErrors));
        }
        m
    }

    /// Whether the response body is worth passing (`need_response`).
    fn wants_body(&self) -> bool {
        cfg!(feature = "test-hooks") || self.response.0 & !Response::STATUS != 0
    }

    pub fn response_headers(&mut self, status: u16) -> Rc {
        self.status = status as u32;
        if self.error == E_BUDGET {
            if self.stage >= Stage::Response {
                return E_STATE;
            }
        } else {
            if self.stage < Stage::Headers || self.stage >= Stage::Response {
                return E_STATE;
            }
            if self.error != OK {
                return self.error;
            }
        }
        self.stage = Stage::Response;
        if self.response.has(Response::STATUS) && !response::status_allowed(status) {
            self.record(response::STATUS_NOT_ALLOWED);
        }
        let matchers = self.response_matchers();
        if !matchers.is_empty() {
            // the data guard masks in enforce only: shadow never changes
            // the traffic
            self.guard = Some(Guard::new(matchers, !self.shadow));
        }
        OK
    }

    /// One response body chunk. `Some(bytes)`: send these instead of the
    /// chunk (masked, and with the held tail moved: same total length);
    /// `None`: send the chunk unchanged.
    pub fn response_body_chunk(&mut self, data: &[u8], last: bool) -> (Rc, Option<Vec<u8>>) {
        self.response_feed(data, if last { Feed::Last } else { Feed::More })
    }

    /// The connector flushes the response: `Some(bytes)` held back by the
    /// data guard, to send now; `None`: nothing to send.
    pub fn response_body_flush(&mut self) -> (Rc, Option<Vec<u8>>) {
        self.response_feed(&[], Feed::Flush)
    }

    fn response_feed(&mut self, data: &[u8], feed: Feed) -> (Rc, Option<Vec<u8>>) {
        if self.error != OK && self.error != E_BUDGET {
            return (self.error, None);
        }
        if self.stage != Stage::Response {
            return (E_STATE, None);
        }
        #[cfg(feature = "test-hooks")]
        if !self.degraded && contains_panic(data) {
            panic!("test hook: deliberate panic");
        }
        let Some(g) = self.guard.as_mut() else {
            return (OK, None);
        };
        let out = g.chunk(data, feed);
        let found: Vec<u32> = g.found().to_vec();
        for rule in found {
            self.record(rule);
        }
        (OK, out)
    }

    /// Sets fixed Block/Event ID for deterministic testing
    pub fn set_id_for_test(&mut self, id: [u8; block_id::ID_LEN]) {
        self.id = Some(id);
    }

    pub fn verdict(&self) -> Verdict {
        let mut v = Verdict::allow();
        v.error = self.error;
        v.json = self.json;
        v.score = self.score;
        v.n_rules = self.n_rules as u32;
        v.rules = self.rules;
        if self.matched {
            if self.shadow {
                v.action = ACTION_LOG;
            } else {
                v.action = ACTION_BLOCK;
                v.status = 403;
            }
        } else {
            if self.sig_matched {
                v.action = ACTION_LOG;
            }
            if self.error == OK && self.stage < Stage::BodyDone {
                v.need_body = true;
            }
        }
        // the connector inspects the response only when something can be
        // found or rewritten in it
        v.need_response = (self.error == OK || self.error == E_BUDGET) && self.wants_body();
        v.id = self.id;
        v.canary = self.canary;
        // #98: the budget ran out on an enforced request that already has
        // findings (score above 0: rules matched below the threshold; the
        // signature pack in shadow and score-0 rules do not count)
        v.fail_closed = self.fail_on_findings
            && self.error == E_BUDGET
            && !self.matched
            && !self.shadow
            && self.score > 0;
        v
    }

    /// The replay sample of a sampled transaction (W12-N-01): anonymized
    /// with the group's key, as one datagram (SAMPLE_MAGIC, then event.proto
    /// ReplaySample) of at most 8 KB; the body kept shrinks until it fits.
    /// None when not sampled, or when even without a body it does not fit.
    pub fn encode_sample(&self) -> Option<Vec<u8>> {
        let s = self.sample.as_ref()?;
        let policy: &[u8] = match (self.engine.as_ref(), self.policy_index) {
            (Some(e), Some(i)) => e.policy_by_index(i).map_or(&[][..], |p| p.name),
            _ => &self.unmatched_policy[..self.unmatched_policy_len],
        };
        let v = self.verdict();
        let action: &[u8] = if v.error != OK {
            b"error"
        } else {
            match v.action {
                ACTION_BLOCK => b"block",
                ACTION_LOG => b"log",
                ACTION_ALLOW => b"allow",
                _ => b"challenge",
            }
        };
        let req = crate::anon::Request {
            ts_ms: s.ts_ms,
            node_id: &self.node_id[..self.node_id_len],
            policy,
            method: &s.method,
            raw_uri: &s.raw_uri,
            uri: &s.uri,
            args: &s.args,
            proto: &s.proto,
            client: &self.client_addr[..self.client_addr_len],
            headers: s
                .headers
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect(),
            body: &s.body,
            body_len: Some(s.body_len),
            action,
            rules: &self.rules[..self.n_rules],
        };
        let mut a = crate::anon::Anonymizer::new(&s.cfg.key, &s.cfg.key_id)?;
        // the policy's own sensitive fields and patterns too (P-01 §1, #75)
        if let Some(p) = self
            .engine
            .as_ref()
            .zip(self.policy_index)
            .and_then(|(e, i)| e.privacy(i))
        {
            a.set_privacy(p.fields(), p.patterns());
        }
        let mut max = SAMPLE_MAX_BODY;
        loop {
            // max_body 0 is the default (64 KB) for the anonymizer: keep 1 byte
            a.max_body = max.max(1);
            let r = a.anonymize(&req);
            let out =
                crate::event::encode_sample(&r, &s.cfg.key_id, self.canary, self.bundle_version);
            if out.len() <= crate::event::MAX_DATAGRAM {
                return Some(out);
            }
            if max <= 1 {
                return None;
            }
            max /= 2;
        }
    }

    /// Inspection completeness, using the same classification as emitted events.
    pub fn inspection(&self) -> crate::event::Inspection {
        if self.error == E_BUDGET || self.args_left_out {
            crate::event::Inspection::Partial
        } else if self.body_skipped || self.error == E_INCOMPLETE {
            crate::event::Inspection::BodySkipped
        } else {
            crate::event::Inspection::Full
        }
    }

    /// Why this request was not fully inspected, if it was not (RV-N-01): the
    /// same classes as the event's `inspection`, plus other engine errors.
    fn gap(&self) -> crate::counters::Gap {
        use crate::counters::Gap;
        // arguments past the policy's max_args (#28) are not inspected
        // either: PARTIAL, as the event's inspection field says
        if self.error == E_BUDGET || self.args_left_out {
            Gap::Partial
        } else if self.body_skipped || self.error == E_INCOMPLETE {
            Gap::BodySkipped
        } else if self.error != OK {
            Gap::Error
        } else {
            Gap::None
        }
    }

    /// The engine's per-policy counts (RV-N-01) when about a second passed
    /// since it last sent them: COUNTERS_MAGIC + event.proto
    /// `PolicyCounters`, at most MAX_DATAGRAM bytes (what does not fit waits
    /// for the next time). This transaction is not in them yet (it counts
    /// when dropped).
    pub fn encode_counters(&self) -> Option<Vec<u8>> {
        let e = self.engine.as_ref()?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let counts = e.counters().take_due(now_ms)?;
        if counts.is_empty() {
            return None;
        }
        let unknown = e.counters().unknown_slot();
        let entries: Vec<(&[u8], [u64; crate::counters::N])> = counts
            .iter()
            .map(|&(slot, v)| {
                let name = if slot == unknown {
                    &b""[..]
                } else {
                    e.policy_by_index(slot as u32).map_or(&b""[..], |p| p.name)
                };
                (name, v)
            })
            .collect();
        let node = std::str::from_utf8(&self.node_id[..self.node_id_len]).unwrap_or("");
        // W13-R-02: the rule costs sampled since the last counters
        let (taken, requests, engine_ns) = e.rule_costs().take();
        let tables = e.tables();
        let costs = crate::event::RuleCostTake {
            costs: taken
                .iter()
                .map(|&(index, n, total, max)| {
                    let id = index
                        .and_then(|i| tables.rule(i as usize))
                        .map_or(crate::rulecost::RULE_SCAN, |r| r.id);
                    (id, n, total, max)
                })
                .collect(),
            requests,
            engine_ns,
        };
        let ((out, n), r) = crate::event::encode_counters_with(
            now_ms,
            node,
            self.bundle_version,
            &entries,
            &costs,
            crate::event::MAX_DATAGRAM,
        );
        for &(slot, v) in &counts[n..] {
            e.counters().give_back(slot, v);
        }
        for &(index, n, total, max) in &taken[r..] {
            e.rule_costs().give_back(index, n, total, max);
        }
        (n > 0).then_some(out)
    }

    /// Encodes the event for this transaction into a protobuf datagram (at most 8 KB).
    /// Returns None when there is no event (clean requests without findings).
    pub fn encode_event(&self) -> Option<Vec<u8>> {
        let id = self.id?;
        if self.error == OK && !self.matched && self.n_rules == 0 {
            return None;
        }
        let (_, bits) = block_id::parse(&id)?;
        let time_unix_ms = (bits >> 38) as u64;

        let action = if self.matched {
            if self.shadow {
                crate::event::Action::Log
            } else {
                crate::event::Action::Block
            }
        } else if self.error != OK || self.n_rules > 0 {
            crate::event::Action::Log
        } else {
            crate::event::Action::Allow
        };

        let block_id_str = std::str::from_utf8(&id).unwrap_or("");
        let node_id_str = std::str::from_utf8(&self.node_id[..self.node_id_len]).unwrap_or("");
        let req_id_str = std::str::from_utf8(&self.request_id[..self.request_id_len]).unwrap_or("");
        let client_ip_str =
            std::str::from_utf8(&self.client_addr[..self.client_addr_len]).unwrap_or("");
        let identity_str = std::str::from_utf8(&self.identity[..self.identity_len]).unwrap_or("");
        let method_str = std::str::from_utf8(&self.method[..self.method_len]).unwrap_or("");
        let host_str = std::str::from_utf8(&self.host[..self.host_len]).unwrap_or("");
        let path_str = std::str::from_utf8(&self.path[..self.path_len]).unwrap_or("");

        let policy_id_str = if let (Some(engine), Some(idx)) =
            (self.engine.as_ref(), self.policy_index)
        {
            engine
                .policy_by_index(idx)
                .and_then(|p| std::str::from_utf8(p.name).ok())
                .unwrap_or("")
        } else {
            std::str::from_utf8(&self.unmatched_policy[..self.unmatched_policy_len]).unwrap_or("")
        };

        let mut layer_scores_arr = [("", 0i32); 8];
        let mut n_scores = 0;
        layer_scores_arr[n_scores] = ("anomaly", self.score);
        n_scores += 1;
        if self.protocol_score > 0 {
            layer_scores_arr[n_scores] = ("protocol", self.protocol_score);
            n_scores += 1;
        }
        for (i, &layer_name) in crate::rules::LAYERS.iter().enumerate() {
            if layer_name == "protocol" {
                continue;
            }
            let s = self.layer_scores[i];
            if s > 0 {
                layer_scores_arr[n_scores] = (layer_name, s);
                n_scores += 1;
            }
        }

        let status = if self.status != 0 {
            self.status
        } else if action == crate::event::Action::Block {
            403
        } else {
            0
        };

        let match_datas: Vec<crate::event::MatchData<'_>> = self
            .matches
            .iter()
            .map(|m| crate::event::MatchData {
                rule_id: m.rule_id,
                layer: m.layer,
                field: &m.field,
                snippet: &m.snippet,
            })
            .collect();

        // the request's context, masked (RV-G2-01)
        let kept = if self.event_headers.is_empty() {
            &self.kept_headers
        } else {
            &self.event_headers
        };
        let refs: Vec<(&[u8], &[u8])> = kept.iter().map(|(k, v)| (&k[..], &v[..])).collect();
        let privacy = self
            .engine
            .as_deref()
            .zip(self.policy_index)
            .and_then(|(e, i)| e.privacy(i));
        let ctx = crate::event::context_with(&refs, privacy);
        // identity: hmac (P-01 §1): the value itself never leaves the node
        let identity = privacy
            .and_then(|p| p.identity(&self.identity[..self.identity_len]))
            .unwrap_or_else(|| identity_str.to_string());
        let ctx_headers: Vec<(&[u8], &[u8])> =
            ctx.headers.iter().map(|(k, v)| (&k[..], &v[..])).collect();
        let inspection = self.inspection();

        let ev = crate::event::EventData {
            block_id: block_id_str,
            time_unix_ms,
            node_id: node_id_str,
            request_id: req_id_str,
            policy_id: policy_id_str,
            bundle_version: self.bundle_version,
            client_ip: client_ip_str,
            identity: &identity,
            method: method_str,
            host: host_str,
            path: path_str,
            status,
            action,
            layer_scores: &layer_scores_arr[..n_scores],
            rule_ids: &self.rules[..self.n_rules],
            matches: &match_datas,
            user_agent: &ctx.user_agent,
            referer: &ctx.referer,
            headers: &ctx_headers,
            inspection,
            // a would-be block of the signature pack in shadow counts too
            would_block: self.matched || self.sig_matched,
            canary: self.canary,
        };

        let mut out = crate::event::encode(&ev);
        if self.cost_sampled {
            crate::event::append_rule_costs(
                &self.request_costs(),
                crate::event::MAX_DATAGRAM,
                &mut out,
            );
        }
        Some(out)
    }

    /// This sampled transaction's rules by time (W13-R-02), most expensive
    /// first, at most EVENT_RULES: (Rule ID, evaluations, total ns, max ns),
    /// Rule ID 0 for the prefilter's scans.
    pub fn request_costs(&self) -> Vec<crate::rulecost::Cost> {
        let Some(e) = self.engine.as_ref() else {
            return vec![];
        };
        let tables = e.tables();
        let mut by: Vec<(Option<u32>, crate::rulecost::Cost)> = vec![];
        for &(index, ns) in self.costs.borrow().iter() {
            match by.iter_mut().find(|(i, _)| *i == index) {
                Some((_, c)) => {
                    c.1 += 1;
                    c.2 += ns;
                    c.3 = c.3.max(ns);
                }
                None => {
                    let id = index
                        .and_then(|i| tables.rule(i as usize))
                        .map_or(crate::rulecost::RULE_SCAN, |r| r.id);
                    by.push((index, (id, 1, ns, ns)));
                }
            }
        }
        let mut out: Vec<crate::rulecost::Cost> = by.into_iter().map(|(_, c)| c).collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.2));
        out.truncate(crate::rulecost::EVENT_RULES);
        out
    }
}

/// A bounded copy of the request headers for an event's context: what
/// `event::context` reads at most (the window it masks, per value).
fn keep_for_event(headers: &[(&[u8], &[u8])]) -> Vec<(Vec<u8>, Vec<u8>)> {
    headers
        .iter()
        .take(crate::event::MAX_HEADERS + 3) // + Host, User-Agent, Referer
        .map(|(k, v)| {
            let v = &v[..v
                .len()
                .min(crate::event::MAX_UA_LEN.max(crate::event::MAX_HEADERS_BYTES))];
            (k[..k.len().min(256)].to_vec(), v.to_vec())
        })
        .collect()
}

/// Each transaction counts once for its policy (RV-N-01).
impl Drop for Tx {
    fn drop(&mut self) {
        if let Some(e) = self.engine.as_ref() {
            e.counters()
                .count(self.policy_index, self.gap(), self.degraded);
            if self.cost_sampled {
                let rc = e.rule_costs();
                for &(index, ns) in self.costs.borrow().iter() {
                    rc.add(index, ns);
                }
                rc.add_request(self.elapsed_ns);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tests::test_engine;
    use crate::event::CanaryGroup;

    fn tx() -> Tx {
        Tx::new(Some(Arc::new(test_engine())), b"node-a", 0)
    }

    fn id_str(v: &Verdict) -> String {
        v.id.map(|id| String::from_utf8_lossy(&id).into_owned())
            .unwrap_or_default()
    }

    fn line(t: &mut Tx, uri: &[u8]) {
        assert_eq!(t.request_line(b"GET", uri, uri, b"", b"HTTP/1.1"), OK);
        assert_eq!(t.request_headers_done(), OK);
    }

    #[test]
    fn allows_clean_request() {
        let mut t = tx();
        line(&mut t, b"/index.html");
        let v = t.verdict();
        assert_eq!(v.action, ACTION_ALLOW);
        assert!(v.need_body);
        assert_eq!(t.request_body_chunk(b"", true), OK);
        let v = t.verdict();
        assert!(!v.need_body);
        assert_eq!(id_str(&v), "");
    }

    #[test]
    fn response_flush_needs_the_response_stage() {
        let mut t = tx();
        assert_eq!(t.response_body_flush(), (E_STATE, None));
        let mut t = tx();
        line(&mut t, b"/");
        assert_eq!(t.request_body_chunk(b"", true), OK);
        assert_eq!(t.response_headers(200), OK);
        let (rc, out) = t.response_body_flush();
        assert_eq!(rc, OK);
        // a data guard exists only when there is something to mask
        assert_eq!(out.is_some(), cfg!(feature = "test-hooks"));
    }

    #[test]
    fn blocks_uri() {
        let mut t = tx();
        line(&mut t, b"/a?STRATA-TEST-BLOCK");
        let v = t.verdict();
        assert_eq!(v.action, ACTION_BLOCK);
        assert_eq!(v.status, 403);
        assert_eq!(v.rules[0], STUB_RULE_ID);
        assert!(!v.need_body);
        assert!(id_str(&v).starts_with("STR-"));
        // Stable across calls.
        assert_eq!(id_str(&v), id_str(&t.verdict()));
    }

    #[test]
    fn blocks_body_split_byte_by_byte() {
        let mut t = tx();
        line(&mut t, b"/upload");
        let body = b"xxSTRATA-TEST-BLOCKyy";
        for b in body.chunks(1) {
            assert_eq!(t.request_body_chunk(b, false), OK);
        }
        assert_eq!(t.request_body_chunk(b"", true), OK);
        assert_eq!(t.verdict().action, ACTION_BLOCK);
    }

    #[test]
    fn blocks_body_across_every_split_point() {
        let body = b"0123456789STRATA-TEST-BLOCK0123456789";
        for split in 0..=body.len() {
            for split2 in split..=body.len() {
                let mut t = tx();
                line(&mut t, b"/");
                t.request_body_chunk(&body[..split], false);
                t.request_body_chunk(&body[split..split2], false);
                t.request_body_chunk(&body[split2..], true);
                assert_eq!(t.verdict().action, ACTION_BLOCK, "{split} {split2}");
            }
        }
    }

    #[test]
    fn no_false_match_on_partial_needle() {
        let mut t = tx();
        line(&mut t, b"/");
        t.request_body_chunk(b"STRATA-TEST-BLOC", false);
        t.request_body_chunk(b"STRATA-TEST-BLOC", true);
        assert_eq!(t.verdict().action, ACTION_ALLOW);
    }

    #[test]
    fn shadow_logs_with_event_id() {
        let e = Arc::new(test_engine());
        let mut t = Tx::new(Some(e), b"n", TXF_FORCE_SHADOW);
        line(&mut t, b"/STRATA-TEST-BLOCK");
        let v = t.verdict();
        assert_eq!(v.action, ACTION_LOG);
        assert_eq!(v.status, 0);
        assert!(id_str(&v).starts_with("EVT-"));
    }

    #[test]
    fn missing_engine_reports_bundle_error_with_event_id() {
        let mut t = Tx::new(None, b"n", 0);
        assert_eq!(
            t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1"),
            E_BUNDLE
        );
        let v = t.verdict();
        assert_eq!(v.error, E_BUNDLE);
        assert!(id_str(&v).starts_with("EVT-"));
    }

    #[test]
    fn out_of_order_calls_fail() {
        let mut t = tx();
        assert_eq!(t.request_body_chunk(b"x", false), E_STATE);
        assert_eq!(t.request_headers_done(), E_STATE);
        line(&mut t, b"/");
        assert_eq!(t.request_line(b"GET", b"/", b"/", b"", b""), E_STATE);
    }

    #[test]
    fn json_preference_from_accept() {
        let mut t = tx();
        t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1");
        t.request_header(b"ACCEPT", b"application/json");
        t.request_headers_done();
        assert!(t.verdict().json);

        let mut t = tx();
        t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1");
        t.request_header(b"accept", b"text/html,application/json");
        t.request_headers_done();
        assert!(!t.verdict().json);
    }

    fn headers(t: &mut Tx, h: &[(&[u8], &[u8])]) {
        for (k, v) in h {
            assert_eq!(t.request_header(k, v), OK);
        }
        assert_eq!(t.request_headers_done(), OK);
    }

    fn rules(v: &Verdict) -> Vec<u32> {
        v.rules[..v.n_rules as usize].to_vec()
    }

    #[test]
    fn protocol_cl_te_blocks_before_the_body() {
        let mut t = tx();
        t.request_line(b"POST", b"/upload", b"/upload", b"", b"HTTP/1.1");
        headers(
            &mut t,
            &[
                (b"Content-Length", b"10"),
                (b"Transfer-Encoding", b"chunked"),
            ],
        );
        let v = t.verdict();
        assert_eq!(v.action, ACTION_BLOCK);
        assert_eq!(rules(&v), [protocol::CL_TE_CONFLICT]);
        assert!(!v.need_body);
        assert!(id_str(&v).starts_with("STR-"));
    }

    #[test]
    fn protocol_below_threshold_is_reported_but_allowed() {
        let mut t = tx();
        t.request_line(
            b"GET",
            b"/app;jsessionid=1/x",
            b"/app;jsessionid=1/x",
            b"",
            b"HTTP/1.1",
        );
        headers(&mut t, &[]);
        let v = t.verdict();
        assert_eq!(v.action, ACTION_ALLOW);
        assert_eq!(rules(&v), [protocol::MATRIX_PARAMETER]);
        assert_eq!(v.score, 20);
        assert!(v.need_body);
        assert_eq!(id_str(&v), "");
    }

    #[test]
    fn protocol_scores_add_up_to_the_threshold() {
        let mut t = tx();
        // 50 (double encoding) + 50 (control character) = 100
        t.request_line(b"GET", b"/a/%2541\x01", b"/a", b"", b"HTTP/1.1");
        headers(&mut t, &[]);
        let v = t.verdict();
        assert_eq!(v.score, 100);
        assert_eq!(v.action, ACTION_BLOCK);
        assert_eq!(
            rules(&v),
            [protocol::DOUBLE_ENCODING, protocol::CONTROL_CHAR]
        );
    }

    #[test]
    fn protocol_encoded_traversal_blocks() {
        let mut t = tx();
        t.request_line(b"GET", b"/a/%2e%2e/b?x=1", b"/b", b"x=1", b"HTTP/1.1");
        headers(&mut t, &[]);
        let v = t.verdict();
        assert_eq!(v.action, ACTION_BLOCK);
        assert_eq!(rules(&v), [protocol::ENCODED_DOT_SEGMENT]);
    }

    #[test]
    fn protocol_same_rule_from_uri_and_header_counts_once() {
        let mut t = tx();
        t.request_line(b"GET", b"/a%00", b"/a", b"", b"HTTP/1.1");
        headers(&mut t, &[(b"X-A", b"\x00")]);
        let v = t.verdict();
        assert_eq!(rules(&v), [protocol::NULL_BYTE]);
        assert_eq!(v.score, 100);
    }

    #[test]
    fn protocol_in_shadow_logs() {
        let mut t = Tx::new(Some(Arc::new(test_engine())), b"n", TXF_FORCE_SHADOW);
        t.request_line(b"POST", b"/", b"/", b"", b"HTTP/1.1");
        headers(
            &mut t,
            &[(b"Content-Length", b"1"), (b"Content-Length", b"2")],
        );
        let v = t.verdict();
        assert_eq!(v.action, ACTION_LOG);
        assert_eq!(rules(&v), [protocol::CL_INVALID]);
        assert!(id_str(&v).starts_with("EVT-"));
    }

    #[test]
    fn protocol_and_stub_rule_together() {
        let mut t = tx();
        t.request_line(
            b"GET",
            b"/x;y?STRATA-TEST-BLOCK",
            b"/x;y",
            b"STRATA-TEST-BLOCK",
            b"HTTP/1.1",
        );
        headers(&mut t, &[]);
        let v = t.verdict();
        assert_eq!(rules(&v), [protocol::MATRIX_PARAMETER, STUB_RULE_ID]);
        assert_eq!(v.score, 120);
    }

    fn with_policy(policy: &[u8], flags: u32) -> Tx {
        let mut t = Tx::new(Some(Arc::new(test_engine())), b"n", flags);
        t.set_policy(policy);
        line(&mut t, b"/upload");
        t
    }

    #[test]
    fn oversize_blocks_when_the_policy_says_so() {
        let mut t = with_policy(b"example-api", 0); // oversize: block
        assert_eq!(t.request_body_chunk(b"inspected part", false), OK);
        assert_eq!(t.request_body_skipped(4096), OK);
        assert_eq!(t.request_body_chunk(b"", true), OK);
        let v = t.verdict();
        assert_eq!(v.action, ACTION_BLOCK);
        assert_eq!(v.rules[..v.n_rules as usize], [protocol::BODY_OVER_LIMIT]);
        assert!(id_str(&v).starts_with("STR-"));
    }

    #[test]
    fn oversize_is_recorded_when_the_policy_passes() {
        for policy in [&b"example-web"[..], b"unknown-policy", b""] {
            let mut t = with_policy(policy, 0);
            assert_eq!(t.request_body_skipped(1), OK);
            assert_eq!(t.request_body_chunk(b"", true), OK);
            let v = t.verdict();
            assert_eq!(v.action, ACTION_ALLOW, "{policy:?}");
            assert_eq!(
                (v.rules[0], v.n_rules, v.score),
                (protocol::BODY_OVER_LIMIT, 1, 0)
            );
        }
    }

    // A policy in shadow in the bundle logs instead of blocking, with an
    // Event ID; the enforcing policy blocks the same request.
    #[test]
    fn shadow_policy_logs_and_enforce_policy_blocks() {
        for (policy, action, prefix) in [
            (&b"example-web"[..], ACTION_LOG, "EVT-"),
            (&b"example-api"[..], ACTION_BLOCK, "STR-"),
        ] {
            let mut t = Tx::new(Some(Arc::new(test_engine())), b"n", 0);
            t.set_policy(policy);
            line(&mut t, b"/STRATA-TEST-BLOCK");
            let v = t.verdict();
            assert_eq!(v.action, action, "{}", String::from_utf8_lossy(policy));
            assert!(id_str(&v).starts_with(prefix));
        }
        // Protocol violations follow the policy too.
        let mut t = Tx::new(Some(Arc::new(test_engine())), b"n", 0);
        t.set_policy(b"example-web");
        t.request_line(b"POST", b"/", b"/", b"", b"HTTP/1.1");
        headers(
            &mut t,
            &[(b"Content-Length", b"1"), (b"Content-Length", b"2")],
        );
        assert_eq!(t.verdict().action, ACTION_LOG);
    }

    // An enforce policy with a 10% canary blocks the clients of its canary
    // group and runs the others in shadow; identity decides over the
    // address, and the same client always gets the same answer.
    #[test]
    fn canary_enforces_its_group_only() {
        let run = |identity: &[u8], addr: &[u8]| {
            let mut t = Tx::new(Some(Arc::new(test_engine())), b"n", 0);
            t.set_client_addr(addr);
            t.set_identity(identity);
            t.set_policy(b"example-canary");
            line(&mut t, b"/STRATA-TEST-BLOCK");
            let v = t.verdict();
            let enforced = crate::canary::enforced(
                b"example-canary",
                crate::canary::key(identity, addr),
                1000,
            );
            // W12-G2-01: the group, in the verdict and in the event
            let want = if enforced {
                CanaryGroup::Enforce
            } else {
                CanaryGroup::Shadow
            };
            assert_eq!((t.canary(), v.canary), (want, want));
            let ev = t.encode_event().unwrap();
            assert!(ev.ends_with(&[0xb0, 0x01, want as u8]), "{ev:?}"); // tag 22, varint
            if enforced {
                assert_eq!(v.action, ACTION_BLOCK);
                assert!(id_str(&v).starts_with("STR-"));
            } else {
                assert_eq!(v.action, ACTION_LOG);
                assert!(id_str(&v).starts_with("EVT-"));
            }
            enforced
        };
        let mut blocked = 0;
        for i in 0..1000 {
            let addr = format!("198.51.{}.{}", i / 256, i % 256);
            let first = run(b"", addr.as_bytes());
            assert_eq!(first, run(b"", addr.as_bytes()), "{addr}");
            blocked += usize::from(first);
        }
        assert!(
            (60..140).contains(&blocked),
            "10% canary blocked {blocked}/1000"
        );

        // the identity, not the address, picks the group
        let in_group = |k: &String| crate::canary::enforced(b"example-canary", k.as_bytes(), 1000);
        let users: Vec<String> = (0..100).map(|i| format!("user-{i}")).collect();
        let inside = users.iter().find(|k| in_group(k)).unwrap();
        let outside = users.iter().find(|k| !in_group(k)).unwrap();
        for addr in [&b"192.0.2.1"[..], b"192.0.2.2", b"192.0.2.3"] {
            assert!(run(inside.as_bytes(), addr));
            assert!(!run(outside.as_bytes(), addr));
        }
    }

    // W12-G2-01: no canary, an unknown policy, and a forced shadow: the
    // group follows the policy's canary and the hash only.
    #[test]
    fn canary_group_of_other_policies() {
        for (policy, flags) in [(&b"example-api"[..], 0), (b"no-such-policy", 0)] {
            let mut t = Tx::new(Some(Arc::new(test_engine())), b"n", flags);
            t.set_client_addr(b"192.0.2.1");
            t.set_policy(policy);
            line(&mut t, b"/STRATA-TEST-BLOCK");
            assert_eq!(t.verdict().canary, CanaryGroup::None);
            let ev = t.encode_event().unwrap();
            assert!(!ev.windows(2).any(|w| w == [0xb0, 0x01]), "no field 22");
        }
        let addr = (0..1000)
            .map(|i| format!("198.51.{}.{}", i / 256, i % 256))
            .find(|a| {
                crate::canary::enforced(
                    b"example-canary",
                    crate::canary::key(b"", a.as_bytes()),
                    1000,
                )
            })
            .unwrap();
        let mut t = Tx::new(Some(Arc::new(test_engine())), b"n", TXF_FORCE_SHADOW);
        t.set_client_addr(addr.as_bytes());
        t.set_policy(b"example-canary");
        line(&mut t, b"/STRATA-TEST-BLOCK");
        let v = t.verdict();
        assert_eq!((v.action, v.canary), (ACTION_LOG, CanaryGroup::Enforce));
    }

    // Degraded mode (circuit breaker): the protocol layer still blocks,
    // the rules of the full engine (here the stub rule) do not run.
    #[test]
    fn degraded_runs_the_protocol_layer_only() {
        let mut t = Tx::new(Some(Arc::new(test_engine())), b"n", TXF_DEGRADED);
        t.set_policy(b"example-api");
        line(&mut t, b"/STRATA-TEST-BLOCK");
        t.request_body_chunk(b"xxSTRATA-TEST-BLOCKyy", true);
        assert_eq!(t.verdict().action, ACTION_ALLOW);

        let mut t = Tx::new(Some(Arc::new(test_engine())), b"n", TXF_DEGRADED);
        t.set_policy(b"example-api");
        t.request_line(b"POST", b"/", b"/", b"", b"HTTP/1.1");
        headers(
            &mut t,
            &[
                (b"Content-Length", b"1"),
                (b"Transfer-Encoding", b"chunked"),
            ],
        );
        let v = t.verdict();
        assert_eq!(v.action, ACTION_BLOCK);
        assert_eq!(rules(&v), [protocol::CL_TE_CONFLICT]);
    }

    // W12-R-02: a disabled rule no longer matches, built-in detectors
    // included; a transaction keeps the list of its start; an empty list
    // switches the rules back on.
    #[test]
    fn disabled_rules_do_not_match() {
        let e = Arc::new(test_engine());
        // the protocol layer (encoded dot segment) and the stub rule
        let run = |e: &Arc<Engine>, raw: &[u8]| {
            let mut t = Tx::new(Some(e.clone()), b"n", 0);
            t.set_policy(b"example-api");
            t.request_line(b"GET", raw, b"/b", b"", b"HTTP/1.1");
            headers(&mut t, &[]);
            t.verdict()
        };
        let dot = &b"/a/%2e%2e/b"[..];
        let stub = &b"/STRATA-TEST-BLOCK"[..];
        assert_eq!(rules(&run(&e, dot)), [protocol::ENCODED_DOT_SEGMENT]);
        assert_eq!(rules(&run(&e, stub)), [STUB_RULE_ID]);

        let before = Tx::new(Some(e.clone()), b"n", 0);
        e.set_disabled_rules(&[STUB_RULE_ID, protocol::ENCODED_DOT_SEGMENT, 42])
            .unwrap();
        for raw in [dot, stub] {
            let v = run(&e, raw);
            assert_eq!((v.action, v.n_rules), (ACTION_ALLOW, 0));
        }
        assert!(
            before.disabled.is_empty(),
            "a running transaction keeps its list"
        );

        e.set_disabled_rules(&[protocol::ENCODED_DOT_SEGMENT])
            .unwrap();
        assert_eq!(run(&e, dot).n_rules, 0);
        assert_eq!(rules(&run(&e, stub)), [STUB_RULE_ID]);

        e.set_disabled_rules(&[]).unwrap();
        assert_eq!(run(&e, dot).action, ACTION_BLOCK);
        assert!(
            e.set_disabled_rules(&vec![1; crate::engine::MAX_DISABLED_RULES + 1])
                .is_err()
        );
    }

    // strata_mode shadow on an enforcing policy stays shadow.
    #[test]
    fn forced_shadow_is_not_lifted_by_an_enforcing_policy() {
        let mut t = Tx::new(Some(Arc::new(test_engine())), b"n", TXF_FORCE_SHADOW);
        t.set_policy(b"example-api");
        line(&mut t, b"/STRATA-TEST-BLOCK");
        assert_eq!(t.verdict().action, ACTION_LOG);
    }

    #[test]
    fn oversize_in_shadow_logs() {
        let mut t = with_policy(b"example-api", TXF_FORCE_SHADOW);
        t.request_body_skipped(10);
        t.request_body_chunk(b"", true);
        assert_eq!(t.verdict().action, ACTION_LOG);
    }

    #[test]
    fn oversize_after_the_last_chunk_is_out_of_order() {
        let mut t = with_policy(b"example-api", 0);
        t.request_body_chunk(b"", true);
        assert_eq!(t.request_body_skipped(1), E_STATE);
        let mut t = with_policy(b"example-api", 0);
        assert_eq!(t.request_body_skipped(0), OK);
        t.request_body_chunk(b"", true);
        assert_eq!(t.verdict().n_rules, 0);
    }

    #[test]
    fn connector_reported_failure_is_sticky_with_event_id() {
        let mut t = tx();
        line(&mut t, b"/");
        t.fail(E_INCOMPLETE);
        let v = t.verdict();
        assert_eq!(v.error, E_INCOMPLETE);
        assert!(id_str(&v).starts_with("EVT-"));
        assert_eq!(t.request_body_chunk(b"", true), E_INCOMPLETE);
    }

    #[test]
    fn test_tx_caps_at_16_matches() {
        let mut t = tx();
        line(&mut t, b"/");
        for i in 0..25 {
            t.add(Violation {
                signature: false,
                rule: 700_000 + i,
                score: 1,
                block_alone: false,
                layer: "managed",
                field: format!("ARGS:arg_{i}"),
                snippet: vec![b'A'; 10],
            });
        }
        let v = t.verdict();
        assert_eq!(v.n_rules, 16);
        assert_eq!(t.matches.len(), 16);
    }

    #[test]
    fn test_path_excludes_query() {
        let mut t = tx();
        assert_eq!(
            t.request_line(
                b"GET",
                b"/api/test?foo=bar&baz=1",
                b"/api/test?foo=bar&baz=1",
                b"foo=bar&baz=1",
                b"HTTP/1.1"
            ),
            OK
        );
        assert_eq!(t.request_headers_done(), OK);
        assert_eq!(&t.path[..t.path_len], b"/api/test");
        t.stub_rule("URI", b"/api/test");
        let ev_bytes = t.encode_event().expect("should produce event");
        assert!(!ev_bytes.windows(b"foo=bar".len()).any(|w| w == b"foo=bar"));
    }

    fn has(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// RV-G2-01: a blocked request's event carries its User-Agent, Referer
    /// and headers, masked; RV-N-01: and how much was inspected.
    #[test]
    fn event_carries_the_masked_context() {
        let mut t = tx();
        t.set_policy(b"example-api");
        let uri = b"/a?q=STRATA-TEST-BLOCK";
        assert_eq!(
            t.request_line(b"GET", uri, b"/a", b"q=STRATA-TEST-BLOCK", b"HTTP/1.1"),
            OK
        );
        let headers: [(&[u8], &[u8]); 7] = [
            (b"Host", b"api.example.test"),
            (b"User-Agent", b"sqlmap/1.8 (https://sqlmap.org)"),
            (
                b"Referer",
                b"https://app.example.test/cb?code=1&access_token=eyJzecret.x.y#top",
            ),
            (b"Authorization", b"Bearer secret-bearer-value"),
            (b"Cookie", b"sid=secret-cookie-value"),
            (b"X-Customer", b"cccd 001203012345 card 4111111111111111"),
            (b"Accept", b"*/*"),
        ];
        assert_eq!(t.request_headers(&headers), OK);
        let ev = t.encode_event().expect("blocked: an event");
        assert!(has(&ev, b"sqlmap/1.8 (https://sqlmap.org)"));
        assert!(has(
            &ev,
            b"https://app.example.test/cb?code=1&access_token=[MASKED]#top"
        ));
        for secret in [
            &b"secret-bearer-value"[..],
            b"secret-cookie-value",
            b"001203012345",
            b"4111111111111111",
            b"eyJzecret",
        ] {
            assert!(!has(&ev, secret), "{}", String::from_utf8_lossy(secret));
        }
        assert!(has(&ev, b"Authorization") && has(&ev, b"[MASKED]") && has(&ev, b"X-Customer"));
        assert!(has(&ev, b"Accept"));
        // field 20 (inspection) = FULL: tag 0xa0 0x01, value 1
        assert!(has(&ev, &[0xa0, 0x01, 0x01]));
        // field 21 (would_block, #57) = true: tag 0xa8 0x01, value 1
        assert!(has(&ev, &[0xa8, 0x01, 0x01]));
    }

    /// #57: an engine error is an event that would not have blocked.
    #[test]
    fn error_events_would_not_block() {
        let mut t = tx();
        assert_eq!(t.request_line(b"GET", b"/a", b"/a", b"", b"HTTP/1.1"), OK);
        t.set_budget_exceeded();
        let ev = t.encode_event().expect("an error event");
        assert!(!has(&ev, &[0xa8, 0x01]), "would_block is false, left out");
        assert!(has(&ev, &[0xa0, 0x01, 0x02]), "inspection PARTIAL");
    }

    /// P-01 §1b: the policy's max_snippet_size sets how much of the input
    /// the event keeps, masked first.
    #[test]
    fn snippet_size_follows_the_policy() {
        let mut input = b"q=STRATA-TEST-BLOCK card 4111111111111111 ".to_vec();
        input.resize(6000, b'x');
        for (policy, want) in [(&b"example-api"[..], 128usize), (b"example-snippet", 4096)] {
            let mut t = tx();
            t.set_policy(policy);
            let uri = [b"/a?".as_slice(), &input].concat();
            assert_eq!(t.request_line(b"GET", &uri, b"/a", &input, b"HTTP/1.1"), OK);
            let m = &t.matches[0];
            assert_eq!(m.snippet.len(), want, "{}", String::from_utf8_lossy(policy));
            assert!(!has(&m.snippet, b"4111111111111111"));
            let ev = t.encode_event().unwrap();
            assert!(ev.len() <= crate::event::MAX_DATAGRAM);
        }
    }

    /// Clean requests keep no copy of their headers.
    #[test]
    fn clean_requests_copy_no_context() {
        let mut t = tx();
        assert_eq!(t.request_line(b"GET", b"/a", b"/a", b"", b"HTTP/1.1"), OK);
        assert_eq!(t.request_headers(&[(b"User-Agent", b"curl/8")]), OK);
        assert!(t.event_headers.is_empty() && t.kept_headers.is_empty());
        assert!(t.encode_event().is_none());
    }

    /// A body the connector did not pass is reported as such (here a
    /// policy that blocks oversize bodies, so the request has an event).
    #[test]
    fn arguments_left_out_count_as_partial() {
        // #28: the Overview's share (RV-N-01) agrees with the event flag
        let mut t = tx();
        assert_eq!(t.gap(), crate::counters::Gap::None);
        t.args_left_out = true;
        assert_eq!(t.gap(), crate::counters::Gap::Partial);
    }

    #[test]
    fn skipped_body_is_reported() {
        let mut t = tx();
        t.set_policy(b"example-api");
        assert_eq!(t.request_line(b"POST", b"/a", b"/a", b"", b"HTTP/1.1"), OK);
        assert_eq!(t.request_headers(&[(b"User-Agent", b"curl/8")]), OK);
        assert_eq!(t.request_body_skipped(4096), OK);
        let ev = t.encode_event().expect("rule 100020: an event");
        assert!(has(&ev, &[0xa0, 0x01, 0x03]), "inspection BODY_SKIPPED");
    }
}
