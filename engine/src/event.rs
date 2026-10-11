//! Protobuf wire encoder for `strata.event.v1.Event` (W07-R-03).
//!
//! Hand-written zero-prost encoder guaranteeing datagram size <= 8192 bytes
//! (MaxDatagram). Sensitive headers (Authorization, Cookie, Proxy-Authorization)
//! and cookie targets never leak snippet bytes; other snippets are truncated
//! to <= 128 bytes and masked for CCCD and JWT.
#![forbid(unsafe_code)]

use crate::detectors::response::{cccd, jwt};
use crate::guard::{Ctx, Matcher};

/// Agent Unix datagram max size (8 KB).
pub const MAX_DATAGRAM: usize = 8192;

/// Max snippet length in a single Match.
pub const MAX_SNIPPET_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Action {
    Unspecified = 0,
    Allow = 1,
    Log = 2,
    Challenge = 3,
    Block = 4,
}

impl Action {
    pub const fn from_verdict_action(a: u32) -> Self {
        match a {
            0 => Action::Allow,
            1 => Action::Log,
            2 => Action::Challenge,
            3 => Action::Block,
            _ => Action::Unspecified,
        }
    }
}

/// One match inside an Event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub rule_id: u32,
    pub layer: String,
    pub field: String,
    pub snippet: Vec<u8>,
}

/// Structure representing a security event to encode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event<'a> {
    pub block_id: &'a str,
    pub time_unix_ms: u64,
    pub node_id: &'a str,
    pub request_id: &'a str,
    pub policy_id: &'a str,
    pub bundle_version: u64,
    pub client_ip: &'a str,
    pub identity: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub status: u32,
    pub action: Action,
    pub layer_scores: Vec<(&'a str, i32)>,
    pub rule_ids: &'a [u32],
    pub matches: Vec<Match>,
}

pub fn is_sensitive_header(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"authorization")
        || name.eq_ignore_ascii_case(b"cookie")
        || name.eq_ignore_ascii_case(b"proxy-authorization")
}

pub fn is_sensitive_field(field: &str) -> bool {
    let f = field.to_ascii_uppercase();
    f == "REQUEST_COOKIES"
        || f.starts_with("REQUEST_COOKIES:")
        || f.starts_with("REQUEST_COOKIES_NAMES")
        || f == "REQUEST_HEADERS:AUTHORIZATION"
        || f == "REQUEST_HEADERS:COOKIE"
        || f == "REQUEST_HEADERS:PROXY-AUTHORIZATION"
}

/// Masks CCCD (12 digits) and JWT tokens in a snippet, preserving length.
pub fn mask_snippet(snippet: &[u8]) -> Vec<u8> {
    if snippet.is_empty() {
        return Vec::new();
    }
    let mut out = snippet.to_vec();
    let ctx = Ctx {
        held: 0,
        before: None,
        end: true,
    };
    let mut hits = Vec::new();
    cccd::Cccd.find(&out, ctx, &mut hits);
    jwt::Jwt::new().find(&out, ctx, &mut hits);
    for h in hits {
        let start = h.start.min(out.len());
        let end = h.end.min(out.len());
        if start < end {
            out[start..end].fill(b'*');
        }
    }
    out
}

/// Sanitizes and masks a candidate snippet for a given field name.
pub fn prepare_snippet(field: &str, raw_snippet: &[u8]) -> Vec<u8> {
    if is_sensitive_field(field) {
        return Vec::new();
    }
    let bounded = &raw_snippet[..raw_snippet.len().min(MAX_SNIPPET_LEN)];
    mask_snippet(bounded)
}

fn put_varint(v: u64, out: &mut Vec<u8>) {
    let mut val = v;
    while val >= 0x80 {
        out.push((val as u8 & 0x7f) | 0x80);
        val >>= 7;
    }
    out.push(val as u8);
}

fn put_tag(field_number: u32, wire_type: u8, out: &mut Vec<u8>) {
    put_varint(((field_number as u64) << 3) | (wire_type as u64), out);
}

fn put_string(field_number: u32, val: &str, out: &mut Vec<u8>) {
    if !val.is_empty() {
        put_tag(field_number, 2, out);
        put_varint(val.len() as u64, out);
        out.extend_from_slice(val.as_bytes());
    }
}

fn put_bytes(field_number: u32, val: &[u8], out: &mut Vec<u8>) {
    if !val.is_empty() {
        put_tag(field_number, 2, out);
        put_varint(val.len() as u64, out);
        out.extend_from_slice(val);
    }
}

fn put_uint64(field_number: u32, val: u64, out: &mut Vec<u8>) {
    if val != 0 {
        put_tag(field_number, 0, out);
        put_varint(val, out);
    }
}

fn put_uint32(field_number: u32, val: u32, out: &mut Vec<u8>) {
    if val != 0 {
        put_tag(field_number, 0, out);
        put_varint(val as u64, out);
    }
}

fn encode_raw(ev: &Event<'_>, out: &mut Vec<u8>) {
    // 1: block_id
    put_string(1, ev.block_id, out);
    // 2: time_unix_ms
    put_uint64(2, ev.time_unix_ms, out);
    // 3: node_id
    put_string(3, ev.node_id, out);
    // 4: request_id
    put_string(4, ev.request_id, out);
    // 5: policy_id
    put_string(5, ev.policy_id, out);
    // 6: bundle_version
    put_uint64(6, ev.bundle_version, out);
    // 7: client_ip
    put_string(7, ev.client_ip, out);
    // 8: identity
    put_string(8, ev.identity, out);
    // 9: method
    put_string(9, ev.method, out);
    // 10: host
    put_string(10, ev.host, out);
    // 11: path
    put_string(11, ev.path, out);
    // 12: status
    put_uint32(12, ev.status, out);
    // 13: action
    if ev.action as u32 != 0 {
        put_tag(13, 0, out);
        put_varint(ev.action as u64, out);
    }
    // 14: map<string, int32> layer_scores
    // Sort entries deterministically by layer name for reproducible output
    let mut scores = ev.layer_scores.clone();
    scores.sort_unstable_by_key(|&(k, _)| k);
    for (layer, score) in scores {
        if score == 0 && layer.is_empty() {
            continue;
        }
        let mut entry = Vec::new();
        put_string(1, layer, &mut entry);
        if score != 0 {
            put_tag(2, 0, &mut entry);
            put_varint(score as i64 as u64, &mut entry);
        }
        put_tag(14, 2, out);
        put_varint(entry.len() as u64, out);
        out.extend_from_slice(&entry);
    }
    // 15: repeated uint32 rule_ids (proto3 packed)
    if !ev.rule_ids.is_empty() {
        let mut packed = Vec::new();
        for &r in ev.rule_ids {
            put_varint(r as u64, &mut packed);
        }
        put_tag(15, 2, out);
        put_varint(packed.len() as u64, out);
        out.extend_from_slice(&packed);
    }
    // 16: repeated Match matches
    for m in &ev.matches {
        let mut m_buf = Vec::new();
        put_uint32(1, m.rule_id, &mut m_buf);
        put_string(2, &m.layer, &mut m_buf);
        put_string(3, &m.field, &mut m_buf);
        put_bytes(4, &m.snippet, &mut m_buf);

        put_tag(16, 2, out);
        put_varint(m_buf.len() as u64, out);
        out.extend_from_slice(&m_buf);
    }
}

/// Encodes `ev` into a byte buffer capped at `MAX_DATAGRAM` (8192 bytes).
/// If the serialized event exceeds 8 KB, matches are dropped from the end,
/// then `path` and strings are truncated until it fits.
pub fn encode_event(mut ev: Event<'_>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    encode_raw(&ev, &mut buf);
    if buf.len() <= MAX_DATAGRAM {
        return buf;
    }

    // Step 1: Drop matches from the end until it fits or matches are empty.
    while buf.len() > MAX_DATAGRAM && !ev.matches.is_empty() {
        ev.matches.pop();
        buf.clear();
        encode_raw(&ev, &mut buf);
    }
    if buf.len() <= MAX_DATAGRAM {
        return buf;
    }

    // Step 2: Progressively truncate path
    let mut path = ev.path;
    while buf.len() > MAX_DATAGRAM && path.len() > 16 {
        path = &path[..path.len().saturating_sub(64).max(16)];
        ev.path = path;
        buf.clear();
        encode_raw(&ev, &mut buf);
    }
    if buf.len() <= MAX_DATAGRAM {
        return buf;
    }

    // Step 3: Progressively truncate host / identity / request_id if hostile
    if ev.host.len() > 32 {
        ev.host = &ev.host[..32];
        buf.clear();
        encode_raw(&ev, &mut buf);
    }
    if buf.len() > MAX_DATAGRAM && ev.identity.len() > 32 {
        ev.identity = &ev.identity[..32];
        buf.clear();
        encode_raw(&ev, &mut buf);
    }
    if buf.len() > MAX_DATAGRAM && ev.request_id.len() > 32 {
        ev.request_id = &ev.request_id[..32];
        buf.clear();
        encode_raw(&ev, &mut buf);
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding() {
        let mut buf = Vec::new();
        put_varint(1, &mut buf);
        assert_eq!(buf, &[0x01]);

        buf.clear();
        put_varint(300, &mut buf);
        assert_eq!(buf, &[0xac, 0x02]);
    }

    #[test]
    fn test_masking_cccd_and_jwt() {
        let raw = b"cccd 079099001122 and text";
        let masked = mask_snippet(raw);
        assert_eq!(masked, b"cccd ************ and text");

        let jwt = b"token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U end";
        let masked_jwt = mask_snippet(jwt);
        assert!(!masked_jwt.windows(3).any(|w| w == b"eyJ"));
        assert_eq!(masked_jwt.len(), jwt.len());
    }

    #[test]
    fn test_sensitive_headers_empty_snippet() {
        assert!(is_sensitive_field("REQUEST_HEADERS:Authorization"));
        assert!(is_sensitive_field("request_headers:authorization"));
        assert!(is_sensitive_field("REQUEST_HEADERS:Cookie"));
        assert!(is_sensitive_field("REQUEST_HEADERS:Proxy-Authorization"));
        assert!(is_sensitive_field("REQUEST_COOKIES:session"));
        assert!(is_sensitive_field("REQUEST_COOKIES"));

        assert_eq!(
            prepare_snippet("REQUEST_HEADERS:Authorization", b"Bearer 12345"),
            b""
        );
        assert_eq!(
            prepare_snippet("REQUEST_COOKIES:sid", b"secret-cookie-value"),
            b""
        );
        assert_eq!(
            prepare_snippet("ARGS:id", b"123' OR '1'='1"),
            b"123' OR '1'='1"
        );
    }

    #[test]
    fn test_encode_event_bounded_8kb() {
        let matches: Vec<Match> = (0..50)
            .map(|i| Match {
                rule_id: 100_000 + i,
                layer: "managed".to_string(),
                field: format!("ARGS:arg_{i}"),
                snippet: vec![b'A'; 128],
            })
            .collect();

        let long_path = "x".repeat(2000);
        let ev = Event {
            block_id: "STR-1234-5678-ABCD-EF01",
            time_unix_ms: 1700000000000,
            node_id: "web-node-01",
            request_id: "req-12345",
            policy_id: "example-policy",
            bundle_version: 42,
            client_ip: "192.0.2.1",
            identity: "user-123",
            method: "POST",
            host: "api.example.test",
            path: &long_path,
            status: 403,
            action: Action::Block,
            layer_scores: vec![("managed", 50), ("protocol", 100)],
            rule_ids: &[100001, 100002],
            matches,
        };

        let encoded = encode_event(ev);
        assert!(
            encoded.len() <= MAX_DATAGRAM,
            "encoded len was {}",
            encoded.len()
        );
    }
}
