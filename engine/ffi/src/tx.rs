//! Transaction state and the stub detection logic.
//!
//! Stub rule: block when the raw URI, normalized URI, query or request body
//! contains `STRATA-TEST-BLOCK`. Body matching works across chunk boundaries
//! by keeping only the last `NEEDLE.len() - 1` bytes of the previous chunk.
#![forbid(unsafe_code)]

use std::sync::Arc;

use crate::abi::*;
use crate::block_id::{self, Kind};
use crate::engine::Engine;

pub(crate) const NEEDLE: &[u8] = b"STRATA-TEST-BLOCK";
/// Rule id reported by the stub rule (organization range 800000–899999).
pub(crate) const STUB_RULE_ID: u32 = 899_001;
const STUB_SCORE: i32 = 100;
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
    error: strata_rc_t,
    matched: bool,
    id: Option<[u8; block_id::ID_LEN]>,
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
    /// `STRATA_E_BUNDLE`, so the connector applies its fail mode but still
    /// gets an Event ID.
    pub fn new(engine: Option<Arc<Engine>>, node_id: &[u8], flags: u32) -> Tx {
        let missing = engine.is_none();
        let mut tx = Tx {
            _engine: engine,
            node: block_id::node_hash(node_id),
            shadow: flags & STRATA_TXF_FORCE_SHADOW != 0,
            json: false,
            stage: Stage::New,
            error: STRATA_OK,
            matched: false,
            id: None,
            tail: [0; TAIL],
            tail_len: 0,
        };
        if missing {
            tx.fail(STRATA_E_BUNDLE);
        }
        tx
    }

    /// Marks the transaction broken; the first error wins.
    pub fn fail(&mut self, rc: strata_rc_t) {
        if self.error == STRATA_OK {
            self.error = rc;
        }
        if self.id.is_none() {
            self.id = Some(block_id::generate(Kind::Event, self.node));
        }
    }

    fn check(&self, at_least: Stage, before: Stage) -> Result<(), strata_rc_t> {
        if self.error != STRATA_OK {
            return Err(self.error);
        }
        if self.stage < at_least || self.stage >= before {
            return Err(STRATA_E_STATE);
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

    fn scan(&mut self, data: &[u8]) {
        #[cfg(feature = "test-hooks")]
        if contains(data, PANIC_NEEDLE) {
            panic!("test hook: deliberate panic");
        }
        if !self.matched && contains(data, NEEDLE) {
            self.hit();
        }
    }

    pub fn request_line(
        &mut self,
        _method: &[u8],
        raw_uri: &[u8],
        norm_uri: &[u8],
        args: &[u8],
        _proto: &[u8],
    ) -> strata_rc_t {
        if let Err(rc) = self.check(Stage::New, Stage::Line) {
            return rc;
        }
        self.stage = Stage::Line;
        for part in [raw_uri, norm_uri, args] {
            self.scan(part);
        }
        STRATA_OK
    }

    pub fn request_header(&mut self, key: &[u8], val: &[u8]) -> strata_rc_t {
        if let Err(rc) = self.check(Stage::Line, Stage::Headers) {
            return rc;
        }
        if key.eq_ignore_ascii_case(b"accept")
            && contains_ignore_case(val, b"json")
            && !contains_ignore_case(val, b"text/html")
        {
            self.json = true;
        }
        STRATA_OK
    }

    pub fn request_headers_done(&mut self) -> strata_rc_t {
        if let Err(rc) = self.check(Stage::Line, Stage::Headers) {
            return rc;
        }
        self.stage = Stage::Headers;
        STRATA_OK
    }

    pub fn request_body_chunk(&mut self, data: &[u8], last: bool) -> strata_rc_t {
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
                self.hit();
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
        STRATA_OK
    }

    pub fn response_headers(&mut self, _status: u16) -> strata_rc_t {
        if let Err(rc) = self.check(Stage::Headers, Stage::Response) {
            return rc;
        }
        self.stage = Stage::Response;
        STRATA_OK
    }

    pub fn response_body_chunk(&mut self, _data: &[u8], _last: bool) -> strata_rc_t {
        if self.error != STRATA_OK {
            return self.error;
        }
        if self.stage != Stage::Response {
            return STRATA_E_STATE;
        }
        STRATA_OK
    }

    pub fn verdict(&self) -> strata_verdict_t {
        let mut v = strata_verdict_t::empty();
        v.error = self.error;
        if self.json {
            v.flags |= STRATA_VF_JSON;
        }
        if self.matched {
            v.score = STUB_SCORE;
            v.n_rules = 1;
            v.rules[0] = STUB_RULE_ID;
            if self.shadow {
                v.action = STRATA_ACTION_LOG;
            } else {
                v.action = STRATA_ACTION_BLOCK;
                v.status = 403;
            }
        } else if self.error == STRATA_OK && self.stage < Stage::BodyDone {
            v.flags |= STRATA_VF_NEED_BODY;
        }
        if let Some(id) = &self.id {
            write_c_str(&mut v.block_id, id);
        }
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

    fn id_str(v: &strata_verdict_t) -> String {
        v.block_id
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect()
    }

    fn line(t: &mut Tx, uri: &[u8]) {
        assert_eq!(
            t.request_line(b"GET", uri, uri, b"", b"HTTP/1.1"),
            STRATA_OK
        );
        assert_eq!(t.request_headers_done(), STRATA_OK);
    }

    #[test]
    fn allows_clean_request() {
        let mut t = tx();
        line(&mut t, b"/index.html");
        let v = t.verdict();
        assert_eq!(v.action, STRATA_ACTION_ALLOW);
        assert_ne!(v.flags & STRATA_VF_NEED_BODY, 0);
        assert_eq!(t.request_body_chunk(b"", true), STRATA_OK);
        let v = t.verdict();
        assert_eq!(v.flags & STRATA_VF_NEED_BODY, 0);
        assert_eq!(id_str(&v), "");
    }

    #[test]
    fn blocks_uri() {
        let mut t = tx();
        line(&mut t, b"/a?STRATA-TEST-BLOCK");
        let v = t.verdict();
        assert_eq!(v.action, STRATA_ACTION_BLOCK);
        assert_eq!(v.status, 403);
        assert_eq!(v.rules[0], STUB_RULE_ID);
        assert_eq!(v.flags & STRATA_VF_NEED_BODY, 0);
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
            assert_eq!(t.request_body_chunk(b, false), STRATA_OK);
        }
        assert_eq!(t.request_body_chunk(b"", true), STRATA_OK);
        assert_eq!(t.verdict().action, STRATA_ACTION_BLOCK);
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
                assert_eq!(t.verdict().action, STRATA_ACTION_BLOCK, "{split} {split2}");
            }
        }
    }

    #[test]
    fn no_false_match_on_partial_needle() {
        let mut t = tx();
        line(&mut t, b"/");
        t.request_body_chunk(b"STRATA-TEST-BLOC", false);
        t.request_body_chunk(b"STRATA-TEST-BLOC", true);
        assert_eq!(t.verdict().action, STRATA_ACTION_ALLOW);
    }

    #[test]
    fn shadow_logs_with_event_id() {
        let e = Arc::new(test_engine());
        let mut t = Tx::new(Some(e), b"n", STRATA_TXF_FORCE_SHADOW);
        line(&mut t, b"/STRATA-TEST-BLOCK");
        let v = t.verdict();
        assert_eq!(v.action, STRATA_ACTION_LOG);
        assert_eq!(v.status, 0);
        assert!(id_str(&v).starts_with("EVT-"));
    }

    #[test]
    fn missing_engine_reports_bundle_error_with_event_id() {
        let mut t = Tx::new(None, b"n", 0);
        assert_eq!(
            t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1"),
            STRATA_E_BUNDLE
        );
        let v = t.verdict();
        assert_eq!(v.error, STRATA_E_BUNDLE);
        assert!(id_str(&v).starts_with("EVT-"));
    }

    #[test]
    fn out_of_order_calls_fail() {
        let mut t = tx();
        assert_eq!(t.request_body_chunk(b"x", false), STRATA_E_STATE);
        assert_eq!(t.request_headers_done(), STRATA_E_STATE);
        line(&mut t, b"/");
        assert_eq!(t.request_line(b"GET", b"/", b"/", b"", b""), STRATA_E_STATE);
    }

    #[test]
    fn json_preference_from_accept() {
        let mut t = tx();
        t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1");
        t.request_header(b"ACCEPT", b"application/json");
        t.request_headers_done();
        assert_ne!(t.verdict().flags & STRATA_VF_JSON, 0);

        let mut t = tx();
        t.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1");
        t.request_header(b"accept", b"text/html,application/json");
        t.request_headers_done();
        assert_eq!(t.verdict().flags & STRATA_VF_JSON, 0);
    }
}
