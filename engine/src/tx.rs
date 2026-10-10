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
use crate::detectors::{Violation, protocol};
use crate::engine::Engine;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    New,
    Line,
    Headers,
    BodyDone,
    Response,
}

#[derive(Debug)]
pub struct Tx {
    _engine: Option<Arc<Engine>>,
    node: u16,
    shadow: bool,
    json: bool,
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
            _engine: engine,
            node: block_id::node_hash(node_id),
            shadow: flags & TXF_FORCE_SHADOW != 0,
            json: false,
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

    pub fn response_headers(&mut self, _status: u16) -> Rc {
        if let Err(rc) = self.check(Stage::Headers, Stage::Response) {
            return rc;
        }
        self.stage = Stage::Response;
        OK
    }

    pub fn response_body_chunk(&mut self, _data: &[u8], _last: bool) -> Rc {
        if self.error != OK {
            return self.error;
        }
        if self.stage != Stage::Response {
            return E_STATE;
        }
        OK
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
}
