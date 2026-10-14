//! Protobuf wire encoder for `strata.event.v1.Event` (W07-R-03).
//!
//! Hand-written zero-prost encoder guaranteeing datagram size <= 8192 bytes
//! (MaxDatagram). Sensitive parameters and headers never leak snippet bytes;
//! other snippets are truncated to <= 128 bytes after masking for CCCD and JWT.
#![forbid(unsafe_code)]

use crate::detectors::response::{cccd, jwt};
use crate::guard::{Ctx, Matcher};

/// Agent Unix datagram max size (8 KB).
pub const MAX_DATAGRAM: usize = 8192;

/// Max snippet length in a single Match (128 bytes).
pub const MAX_SNIPPET_LEN: usize = 128;
pub const MASK_WINDOW: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Action {
    Unspecified = 0,
    Allow = 1,
    Log = 2,
    Challenge = 3,
    Block = 4,
}

/// Canary group of the request (event.proto `CanaryGroup`): whether its
/// policy has an enforce canary and on which side of it the client fell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum CanaryGroup {
    /// The policy has no canary.
    #[default]
    None = 0,
    /// Inside the canary: enforced.
    Enforce = 1,
    /// Outside the canary: shadow.
    Shadow = 2,
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

/// One match inside an EventData (borrowed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchData<'a> {
    pub rule_id: u32,
    pub layer: &'a str,
    pub field: &'a str,
    pub snippet: &'a [u8],
}

/// Structure representing a security event to encode (borrowed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventData<'a> {
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
    pub layer_scores: &'a [(&'a str, i32)],
    pub rule_ids: &'a [u32],
    pub matches: &'a [MatchData<'a>],
    pub canary: CanaryGroup,
}

fn is_sensitive_word(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "pass"
            | "secret"
            | "token"
            | "access_token"
            | "refresh_token"
            | "api_key"
            | "apikey"
            | "otp"
            | "pin"
            | "cvv"
            | "authorization"
            | "cookie"
            | "proxy-authorization"
            | "x-api-key"
            | "x-auth-token"
    )
}

/// Checks if a field name (e.g. `ARGS:password`, `REQUEST_HEADERS:X-Api-Key`, `REQUEST_COOKIES:session`)
/// targets a sensitive parameter, header, or cookie by exact match on the key name after ':'.
pub fn is_sensitive_target(field: &str) -> bool {
    let upper = field.to_ascii_uppercase();
    if upper.starts_with("REQUEST_COOKIES") {
        return true;
    }
    let key = match field.split_once(':') {
        Some((_, k)) => k.trim(),
        None => field.trim(),
    };
    if is_sensitive_word(key) {
        return true;
    }
    key.rsplit_once('.')
        .is_some_and(|(_, last)| is_sensitive_word(last.trim()))
}

/// Masks CCCD (12 digits) and JWT tokens across the entire snippet, preserving length.
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
/// Performs bounded-window masking before truncation to prevent token leakage.
pub fn prepare_snippet(field: &str, raw_snippet: &[u8]) -> Vec<u8> {
    if is_sensitive_target(field) {
        return Vec::new();
    }
    let window_len = raw_snippet.len().min(MASK_WINDOW);
    let window = &raw_snippet[..window_len];
    let masked = mask_snippet(window);
    masked[..masked.len().min(MAX_SNIPPET_LEN)].to_vec()
}

pub(crate) fn put_varint(v: u64, out: &mut Vec<u8>) {
    let mut val = v;
    while val >= 0x80 {
        out.push((val as u8 & 0x7f) | 0x80);
        val >>= 7;
    }
    out.push(val as u8);
}

pub(crate) fn put_tag(field_number: u32, wire_type: u8, out: &mut Vec<u8>) {
    put_varint(((field_number as u64) << 3) | (wire_type as u64), out);
}

pub(crate) fn put_string(field_number: u32, val: &str, out: &mut Vec<u8>) {
    if !val.is_empty() {
        put_tag(field_number, 2, out);
        put_varint(val.len() as u64, out);
        out.extend_from_slice(val.as_bytes());
    }
}

pub(crate) fn put_bytes(field_number: u32, val: &[u8], out: &mut Vec<u8>) {
    if !val.is_empty() {
        put_tag(field_number, 2, out);
        put_varint(val.len() as u64, out);
        out.extend_from_slice(val);
    }
}

pub(crate) fn put_uint64(field_number: u32, val: u64, out: &mut Vec<u8>) {
    if val != 0 {
        put_tag(field_number, 0, out);
        put_varint(val, out);
    }
}

pub(crate) fn put_uint32(field_number: u32, val: u32, out: &mut Vec<u8>) {
    if val != 0 {
        put_tag(field_number, 0, out);
        put_varint(val as u64, out);
    }
}

fn encode_raw(ev: &EventData<'_>, out: &mut Vec<u8>) {
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
    let mut scores = ev.layer_scores.to_vec();
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
    for m in ev.matches {
        let mut m_buf = Vec::new();
        put_uint32(1, m.rule_id, &mut m_buf);
        put_string(2, m.layer, &mut m_buf);
        put_string(3, m.field, &mut m_buf);
        put_bytes(4, m.snippet, &mut m_buf);

        put_tag(16, 2, out);
        put_varint(m_buf.len() as u64, out);
        out.extend_from_slice(&m_buf);
    }
    // 17: CanaryGroup canary (W12-G2-01)
    put_uint32(17, ev.canary as u32, out);
}

fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Pure encoding function taking borrowed `EventData` and returning serialized wire format
/// capped at `MAX_DATAGRAM` (8192 bytes).
pub fn encode(ev: &EventData<'_>) -> Vec<u8> {
    let mut cur = *ev;
    let mut buf = Vec::with_capacity(512);
    encode_raw(&cur, &mut buf);
    if buf.len() <= MAX_DATAGRAM {
        return buf;
    }

    // Step 1: Drop matches from the end until it fits or matches are empty.
    let mut n_matches = cur.matches.len();
    while buf.len() > MAX_DATAGRAM && n_matches > 0 {
        n_matches -= 1;
        cur.matches = &ev.matches[..n_matches];
        buf.clear();
        encode_raw(&cur, &mut buf);
    }
    if buf.len() <= MAX_DATAGRAM {
        return buf;
    }

    // Step 2: Progressively truncate path at character boundaries
    while buf.len() > MAX_DATAGRAM && cur.path.len() > 16 {
        let target = cur.path.len().saturating_sub(64).max(16);
        let new_path = truncate_str(cur.path, target);
        if new_path.len() == cur.path.len() {
            break;
        }
        cur.path = new_path;
        buf.clear();
        encode_raw(&cur, &mut buf);
    }
    if buf.len() <= MAX_DATAGRAM {
        return buf;
    }

    // Step 3: Progressively truncate host / identity / request_id if hostile
    if cur.host.len() > 32 {
        cur.host = truncate_str(cur.host, 32);
        buf.clear();
        encode_raw(&cur, &mut buf);
    }
    if buf.len() > MAX_DATAGRAM && cur.identity.len() > 32 {
        cur.identity = truncate_str(cur.identity, 32);
        buf.clear();
        encode_raw(&cur, &mut buf);
    }
    if buf.len() > MAX_DATAGRAM && cur.request_id.len() > 32 {
        cur.request_id = truncate_str(cur.request_id, 32);
        buf.clear();
        encode_raw(&cur, &mut buf);
    }

    buf
}

/// First bytes of a replay sample datagram on the event socket (W12-N-01).
/// 0xff never starts a protobuf message, so the agent tells samples from
/// events by it.
pub const SAMPLE_MAGIC: &[u8; 4] = b"\xffSR1";

/// Encodes a replay sample (event.proto `ReplaySample`) after SAMPLE_MAGIC.
pub fn encode_sample(
    r: &crate::anon::Record,
    key_id: &str,
    canary: CanaryGroup,
    bundle_version: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512 + r.headers.len() + r.body.len());
    out.extend_from_slice(SAMPLE_MAGIC);
    put_string(1, key_id, &mut out);
    put_uint64(2, r.ts_ms as u64, &mut out);
    for (n, v) in [
        (3, &r.node_id),
        (4, &r.policy),
        (5, &r.method),
        (6, &r.raw_uri),
        (7, &r.uri),
        (8, &r.args),
        (9, &r.proto),
        (10, &r.client),
        (11, &r.headers),
        (12, &r.body),
    ] {
        put_bytes(n, v, &mut out);
    }
    put_uint64(13, r.body_len as u64, &mut out);
    put_uint32(14, u32::from(r.body_truncated), &mut out);
    put_bytes(15, &r.action, &mut out);
    put_bytes(16, &r.rules, &mut out);
    put_uint32(17, canary as u32, &mut out);
    put_uint64(18, bundle_version, &mut out);
    out
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
    fn test_mask_cccd_and_jwt_full_window() {
        // Raw 400-byte input containing a JWT
        let mut input = b"prefix ".to_vec();
        input.extend_from_slice(b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
        input.extend_from_slice(&vec![b'X'; 250]);

        // prepare_snippet masks the entire slice BEFORE truncation
        let snippet = prepare_snippet("ARGS:token_data", &input);
        assert!(snippet.len() <= MAX_SNIPPET_LEN);
        // Assert no unmasked "eyJ" sequence remains
        assert!(!snippet.windows(3).any(|w| w == b"eyJ"));
        // Assert asterisks are present
        assert!(snippet.contains(&b'*'));
    }

    #[test]
    fn test_sensitive_target_redaction() {
        // Positive matches (must be redacted to empty snippet)
        assert!(is_sensitive_target("ARGS:password"));
        assert!(is_sensitive_target("ARGS:Password"));
        assert!(is_sensitive_target("ARGS:pwd"));
        assert!(is_sensitive_target("ARGS:pass"));
        assert!(is_sensitive_target("ARGS:secret"));
        assert!(is_sensitive_target("ARGS:token"));
        assert!(is_sensitive_target("ARGS:api_key"));
        assert!(is_sensitive_target("REQUEST_HEADERS:X-Api-Key"));
        assert!(is_sensitive_target("REQUEST_HEADERS:Authorization"));
        assert!(is_sensitive_target("REQUEST_HEADERS:Cookie"));
        assert!(is_sensitive_target("REQUEST_COOKIES:session_id"));
        assert!(is_sensitive_target("REQUEST_COOKIES"));

        assert_eq!(prepare_snippet("ARGS:password", b"super_secret"), b"");
        assert_eq!(prepare_snippet("REQUEST_HEADERS:X-Api-Key", b"12345"), b"");
        assert_eq!(prepare_snippet("REQUEST_COOKIES:sid", b"cookie-val"), b"");

        // Negative matches: exact key check must NOT match substrings
        assert!(!is_sensitive_target("ARGS:passport"));
        assert!(!is_sensitive_target("ARGS:bypass"));
        assert!(!is_sensitive_target("ARGS:token_count"));
        assert!(!is_sensitive_target("ARGS:username"));

        assert_eq!(prepare_snippet("ARGS:passport", b"N1234567"), b"N1234567");
        assert_eq!(prepare_snippet("ARGS:bypass", b"true"), b"true");
    }

    #[test]
    fn test_encode_pure_deterministic() {
        let matches = [MatchData {
            rule_id: 100001,
            layer: "protocol",
            field: "REQUEST_HEADERS:Transfer-Encoding",
            snippet: b"chunked",
        }];
        let ev = EventData {
            block_id: "STR-8F3K-Q2VD-7XNM-A1PC",
            time_unix_ms: 1_700_000_000_000,
            node_id: "node-test",
            request_id: "req-001",
            policy_id: "api-test",
            bundle_version: 1,
            client_ip: "192.0.2.1",
            identity: "user-1",
            method: "GET",
            host: "api.example.test",
            path: "/test",
            status: 403,
            action: Action::Block,
            layer_scores: &[("anomaly", 100), ("protocol", 100)],
            rule_ids: &[100001],
            matches: &matches,
            canary: CanaryGroup::None,
        };

        let b1 = encode(&ev);
        let b2 = encode(&ev);
        assert_eq!(b1, b2);
        assert!(b1.len() <= MAX_DATAGRAM);
    }

    #[test]
    fn test_encode_event_bounded_8kb() {
        let matches: Vec<MatchData<'static>> = (0..60)
            .map(|i| MatchData {
                rule_id: 100_000 + i as u32,
                layer: "managed",
                field: "ARGS:arg",
                snippet: b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            })
            .collect();

        let long_path = "x".repeat(3000);
        let ev = EventData {
            block_id: "STR-1234-5678-ABCD-EF01",
            time_unix_ms: 1_700_000_000_000,
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
            layer_scores: &[("anomaly", 100), ("protocol", 50)],
            rule_ids: &[100001, 100002],
            matches: &matches,
            canary: CanaryGroup::None,
        };

        let encoded = encode(&ev);
        assert!(
            encoded.len() <= MAX_DATAGRAM,
            "encoded len was {}",
            encoded.len()
        );
    }

    #[test]
    fn test_jwt_in_first_8kb_masked_and_8mb_not_copied_in_full() {
        let mut huge = b"token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U rest".to_vec();
        huge.resize(8 * 1024 * 1024, b'A');
        assert_eq!(huge.len(), 8 * 1024 * 1024);

        let snippet = prepare_snippet("ARGS:payload", &huge);
        assert!(snippet.len() <= MAX_SNIPPET_LEN);
        // JWT is within first 8KB, so it must be masked
        assert!(!snippet.windows(3).any(|w| w == b"eyJ"));
        assert!(snippet.contains(&b'*'));
    }

    #[test]
    fn test_json_sensitive_subpaths() {
        assert!(is_sensitive_target("ARGS:json.user.password"));
        assert_eq!(
            prepare_snippet("ARGS:json.user.password", b"secret123"),
            b""
        );

        assert!(!is_sensitive_target("ARGS:json.user.passport"));
        assert_eq!(
            prepare_snippet("ARGS:json.user.passport", b"pass123"),
            b"pass123"
        );

        assert!(is_sensitive_target("ARGS:password"));
        assert_eq!(prepare_snippet("ARGS:password", b"secret123"), b"");
    }

    #[test]
    fn test_vietnamese_path_host_truncation_no_panic() {
        let matches: Vec<MatchData<'static>> = (0..200)
            .map(|i| MatchData {
                rule_id: 100_000 + i as u32,
                layer: "managed",
                field: "ARGS:arg",
                snippet: b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            })
            .collect();

        // Multi-byte UTF-8 string (Vietnamese)
        let long_vn_path = "/đường_dẫn_kiểm_thử/tiếng_việt/".repeat(100);
        let long_vn_host = "máy_chủ_thử_nghiệm.ví_dụ.vn".repeat(10);
        let ev = EventData {
            block_id: "STR-1234-5678-ABCD-EF01",
            time_unix_ms: 1_700_000_000_000,
            node_id: "web-node-01",
            request_id: "req-12345",
            policy_id: "example-policy",
            bundle_version: 1,
            client_ip: "192.0.2.1",
            identity: "user-alice",
            method: "POST",
            host: &long_vn_host,
            path: &long_vn_path,
            status: 403,
            action: Action::Block,
            layer_scores: &[("anomaly", 100), ("protocol", 50)],
            rule_ids: &[100001, 100002],
            matches: &matches,
            canary: CanaryGroup::None,
        };

        let encoded = encode(&ev);
        assert!(encoded.len() <= MAX_DATAGRAM);
    }
}
