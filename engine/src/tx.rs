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
use crate::detectors::response::{self, cccd, db_errors, jwt};
use crate::detectors::{Violation, protocol};
use crate::engine::Engine;
use crate::eval;
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

#[derive(Debug)]
pub struct Tx {
    engine: Option<Arc<Engine>>,
    client_addr: Vec<u8>,
    line: Option<Line>,
    node: u16,
    shadow: bool,
    json: bool,
    /// the policy blocks request bodies larger than what is inspected
    oversize_block: bool,
    /// response layer switches of the policy
    response: Response,
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
    /// test-hooks only: what the connector passed, for integration tests
    #[cfg(feature = "test-hooks")]
    echo: Option<(String, bool)>,
    id: Option<[u8; block_id::ID_LEN]>,
    /// engine time spent on this request, in nanoseconds
    elapsed_ns: u64,
    tail: [u8; TAIL],
    tail_len: usize,
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
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
        let mut tx = Tx {
            engine,
            client_addr: Vec::new(),
            line: None,
            node: block_id::node_hash(node_id),
            shadow: flags & TXF_FORCE_SHADOW != 0,
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
            #[cfg(feature = "test-hooks")]
            echo: None,
            id: None,
            elapsed_ns: 0,
            tail: [0; TAIL],
            tail_len: 0,
        };
        if missing {
            tx.fail(E_BUNDLE);
        }
        tx
    }

    /// Applies the policy's settings: its signed mode (a shadow policy
    /// never blocks, whatever the connector asks), oversize handling and
    /// response layer. An unknown policy keeps the defaults.
    pub fn set_policy(&mut self, name: &[u8]) {
        if let Some(p) = self.engine.as_ref().and_then(|e| e.policy(name)) {
            // Only towards shadow: nothing lifts TXF_FORCE_SHADOW.
            self.shadow |= p.mode == crate::bundle::Mode::Shadow;
            self.oversize_block = p.oversize == crate::bundle::Oversize::Block;
            self.response = p.response;
        }
    }

    /// The connector inspected only part of the body: `bytes` were not
    /// passed. Rule 100020, blocking or recorded per the policy's
    /// `oversize`.
    pub fn request_body_skipped(&mut self, bytes: u64) -> Rc {
        if let Err(rc) = self.check(Stage::Headers, Stage::BodyDone) {
            return rc;
        }
        if bytes > 0 {
            self.add(Violation {
                rule: protocol::BODY_OVER_LIMIT,
                score: 0,
                block_alone: self.oversize_block,
            });
        }
        OK
    }

    /// Client address for rules on `remote_addr` (copied only when the
    /// bundle has rules).
    pub fn set_client_addr(&mut self, addr: &[u8]) {
        if self.has_rules() {
            self.client_addr = addr.to_vec();
        }
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

    /// Engine time spent on this request so far, in microseconds.
    pub fn time_us(&self) -> u64 {
        self.elapsed_ns / 1000
    }

    /// Marks the transaction broken; the first error wins.
    pub fn fail(&mut self, rc: Rc) {
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

    /// Records a violation once; decides when it blocks alone or the
    /// total reaches the threshold.
    fn add(&mut self, v: Violation) {
        if self.rules[..self.n_rules].contains(&v.rule) {
            return;
        }
        if self.n_rules < MAX_RULES {
            self.rules[self.n_rules] = v.rule;
            self.n_rules += 1;
        }
        self.score = self.score.saturating_add(v.score);
        if v.block_alone || self.score >= BLOCK_THRESHOLD {
            self.hit();
        }
    }

    /// Records a response-layer finding: listed with the rules, but the
    /// decision was taken with the request; an Event ID identifies it.
    fn record(&mut self, rule: u32) {
        if self.rules[..self.n_rules].contains(&rule) {
            return;
        }
        if self.n_rules < MAX_RULES {
            self.rules[self.n_rules] = rule;
            self.n_rules += 1;
        }
        if self.id.is_none() {
            self.id = Some(block_id::generate(Kind::Event, self.node));
        }
    }

    fn stub_rule(&mut self) {
        self.add(Violation {
            rule: STUB_RULE_ID,
            score: STUB_SCORE,
            block_alone: false,
        });
    }

    fn scan(&mut self, data: &[u8]) {
        #[cfg(feature = "test-hooks")]
        if contains(data, PANIC_NEEDLE) {
            panic!("test hook: deliberate panic");
        }
        if !self.matched && contains(data, NEEDLE) {
            self.stub_rule();
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
                &self.client_addr[..],
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
        for part in [raw_uri, norm_uri, args] {
            self.scan(part);
        }
        OK
    }

    pub fn request_header(&mut self, key: &[u8], val: &[u8]) -> Rc {
        if let Err(rc) = self.check(Stage::Line, Stage::Headers) {
            return rc;
        }
        self.headers.header(key, val);
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
            };
            let stage = crate::rules::code(crate::rules::STAGES, "request_headers").unwrap_or(0);
            let mut found = vec![];
            eval::evaluate(
                &engine.tables(),
                engine.hyperscan(),
                &req,
                stage,
                &mut |v| found.push(v),
            );
            for v in found {
                self.add(v);
            }
        }
        OK
    }

    pub fn request_body_chunk(&mut self, data: &[u8], last: bool) -> Rc {
        if let Err(rc) = self.check(Stage::Headers, Stage::BodyDone) {
            return rc;
        }
        #[cfg(feature = "test-hooks")]
        if contains(data, PANIC_NEEDLE) {
            panic!("test hook: deliberate panic");
        }
        if !self.matched {
            // Match spanning the previous chunk and this one.
            let head = &data[..data.len().min(TAIL)];
            let mut window = [0u8; 2 * TAIL];
            window[..self.tail_len].copy_from_slice(&self.tail[..self.tail_len]);
            window[self.tail_len..self.tail_len + head.len()].copy_from_slice(head);
            if contains(&window[..self.tail_len + head.len()], NEEDLE) || contains(data, NEEDLE) {
                self.stub_rule();
            }
            // Keep the last TAIL bytes of (tail + data).
            let total = self.tail_len + data.len();
            if data.len() >= TAIL {
                self.tail.copy_from_slice(&data[data.len() - TAIL..]);
                self.tail_len = TAIL;
            } else {
                let keep_old = TAIL.min(total) - data.len();
                self.tail
                    .copy_within(self.tail_len - keep_old..self.tail_len, 0);
                self.tail[keep_old..keep_old + data.len()].copy_from_slice(data);
                self.tail_len = keep_old + data.len();
            }
        }
        if last {
            self.stage = Stage::BodyDone;
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
        if let Err(rc) = self.check(Stage::Headers, Stage::Response) {
            return rc;
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
        if self.error != OK {
            return (self.error, None);
        }
        if self.stage != Stage::Response {
            return (E_STATE, None);
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
        } else if self.error == OK && self.stage < Stage::BodyDone {
            v.need_body = true;
        }
        // the connector inspects the response only when something can be
        // found or rewritten in it
        v.need_response = self.error == OK && self.wants_body();
        v.id = self.id;
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tests::test_engine;

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
}
