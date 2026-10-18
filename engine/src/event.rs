//! Protobuf wire encoder for `strata.event.v1.Event` (W07-R-03).
//!
//! Hand-written zero-prost encoder guaranteeing datagram size <= 8192 bytes
//! (MaxDatagram). Sensitive parameters and headers never leak snippet bytes;
//! other snippets are truncated to <= 128 bytes after masking for CCCD,
//! JWT and payment card numbers.
#![forbid(unsafe_code)]

use crate::detectors::response::{cccd, jwt, pan};
use crate::guard::{Ctx, Matcher};
use crate::privacy::Privacy;

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

/// How much of the request the engine inspected (RV-N-01); the values of
/// `strata.event.v1.Inspection`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum Inspection {
    #[default]
    Unspecified = 0,
    Full = 1,
    /// the CPU budget ran out
    Partial = 2,
    /// the body, or part of it, was not inspected
    BodySkipped = 3,
}

/// Longest User-Agent and Referer kept in an event.
pub const MAX_UA_LEN: usize = 512;
/// Headers kept in an event: at most this many, names and values together
/// at most `MAX_HEADERS_BYTES`.
pub const MAX_HEADERS: usize = 32;
pub const MAX_HEADERS_BYTES: usize = 2048;
/// What a masked header value becomes.
pub const MASKED: &[u8] = b"[MASKED]";

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
    /// masked already (`context`)
    pub user_agent: &'a [u8],
    pub referer: &'a [u8],
    pub headers: &'a [(&'a [u8], &'a [u8])],
    pub inspection: Inspection,
    /// #57: blocked, or would be in shadow
    pub would_block: bool,
    /// W12-G2-01
    pub canary: CanaryGroup,
    /// FoxIO JA4 TLS client fingerprint (RV-N-02).
    pub ja4: &'a str,
}

/// Request context of an event (RV-G2-01), masked and bounded: the
/// User-Agent and the Referer apart, then the other headers in order.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub user_agent: Vec<u8>,
    pub referer: Vec<u8>,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Masks the request headers for an event. Sensitive headers (by name, as
/// for snippets) keep their name and lose their value; other values are
/// masked like snippets (CCCD, JWT, card numbers); the Referer also loses
/// the values of sensitive query parameters. Host is already in the
/// event. Linear in the bytes kept.
pub fn context(headers: &[(&[u8], &[u8])]) -> Context {
    context_with(headers, None)
}

/// As `context`, with the policy's privacy settings: its field names are
/// sensitive headers too, its patterns masked like the built-in ones.
pub fn context_with(headers: &[(&[u8], &[u8])], privacy: Option<&Privacy>) -> Context {
    let mut c = Context::default();
    let mut room = MAX_HEADERS_BYTES;
    for &(name, value) in headers {
        let n = String::from_utf8_lossy(name);
        if n.eq_ignore_ascii_case("user-agent") {
            if c.user_agent.is_empty() {
                c.user_agent = utf8_cut(&bounded_mask(value, MAX_UA_LEN, privacy), MAX_UA_LEN);
            }
            continue;
        }
        if n.eq_ignore_ascii_case("referer") {
            if c.referer.is_empty() {
                c.referer = utf8_cut(
                    &mask_query(&bounded_mask(value, MAX_UA_LEN, privacy)),
                    MAX_UA_LEN,
                );
            }
            continue;
        }
        if n.eq_ignore_ascii_case("host") || c.headers.len() >= MAX_HEADERS || name.len() >= room {
            continue;
        }
        // the name is a proto string: valid UTF-8, or the agent's decoder
        // refuses the whole event; the value is bytes
        let name = utf8_cut(name, room);
        let sensitive = is_sensitive_word(n.trim())
            || privacy.is_some_and(|p| p.sensitive(&format!("REQUEST_HEADERS:{}", n.trim())));
        let v = if sensitive {
            MASKED.to_vec()
        } else {
            bounded_mask(value, room.saturating_sub(name.len()), privacy)
        };
        room = room.saturating_sub(name.len() + v.len());
        c.headers.push((name, v));
    }
    c
}

/// `b` as valid UTF-8 (invalid bytes replaced), at most `max` bytes, cut on
/// a character boundary: proto strings must be UTF-8.
pub fn utf8_cut(b: &[u8], max: usize) -> Vec<u8> {
    let s = String::from_utf8_lossy(b);
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.as_bytes()[..end].to_vec()
}

/// `v` masked (on its first MASK_WINDOW bytes, before cutting) and cut to
/// `max` bytes.
fn bounded_mask(v: &[u8], max: usize, privacy: Option<&Privacy>) -> Vec<u8> {
    let mut m = mask_snippet(&v[..v.len().min(MASK_WINDOW)]);
    if let Some(p) = privacy {
        p.mask(&mut m);
    }
    m.truncate(max);
    m
}

/// The values of sensitive query parameters of a URL replaced by
/// [MASKED] (`?access_token=...`, `&password=...`).
pub fn mask_query(url: &[u8]) -> Vec<u8> {
    let Some(q) = url.iter().position(|&c| c == b'?') else {
        return url.to_vec();
    };
    let mut out = url[..=q].to_vec();
    let (query, fragment) = match url[q + 1..].iter().position(|&c| c == b'#') {
        Some(f) => (&url[q + 1..q + 1 + f], &url[q + 1 + f..]),
        None => (&url[q + 1..], &b""[..]),
    };
    for (i, pair) in query.split(|&c| c == b'&').enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        match pair.iter().position(|&c| c == b'=') {
            Some(e) if is_sensitive_word(&String::from_utf8_lossy(&pair[..e])) => {
                out.extend_from_slice(&pair[..=e]);
                out.extend_from_slice(MASKED);
            }
            _ => out.extend_from_slice(pair),
        }
    }
    out.extend_from_slice(fragment);
    out
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
            // P-01 §1: Vietnamese names, cards, keys and sessions
            | "matkhau"
            | "mat_khau"
            | "card_number"
            | "cardnumber"
            | "pan"
            | "cvc"
            | "cvv2"
            | "so_the"
            | "sothe"
            | "so_cccd"
            | "private_key"
            | "client_secret"
            | "id_token"
            | "session"
            | "set-cookie"
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
    // a value inspected decoded (b64.rs) is as sensitive as its field
    let key = key.strip_suffix(crate::b64::SUFFIX_STR).unwrap_or(key);
    if is_sensitive_word(key) {
        return true;
    }
    key.rsplit_once('.')
        .is_some_and(|(_, last)| is_sensitive_word(last.trim()))
}

/// Masks CCCD (12 digits), JWT tokens and payment card numbers (PAN)
/// across the entire snippet, preserving length.
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
    pan::Pan.find(&out, ctx, &mut hits);
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
    prepare_snippet_max(field, raw_snippet, MAX_SNIPPET_LEN)
}

/// As `prepare_snippet`, cut to `max` bytes (the policy's
/// max_snippet_size, at most MASK_WINDOW).
pub fn prepare_snippet_max(field: &str, raw_snippet: &[u8], max: usize) -> Vec<u8> {
    prepare_snippet_with(field, raw_snippet, max, None)
}

/// As `prepare_snippet_max`, with the policy's privacy settings: its
/// field names keep no snippet, its patterns are masked on the window
/// before the cut, so a value across the cut never shows in part.
pub fn prepare_snippet_with(
    field: &str,
    raw_snippet: &[u8],
    max: usize,
    privacy: Option<&Privacy>,
) -> Vec<u8> {
    if is_sensitive_target(field) || privacy.is_some_and(|p| p.sensitive(field)) {
        return Vec::new();
    }
    let window_len = raw_snippet.len().min(MASK_WINDOW);
    let window = &raw_snippet[..window_len];
    let mut masked = mask_snippet(window);
    if let Some(p) = privacy {
        p.mask(&mut masked);
    }
    masked[..masked.len().min(max.min(MASK_WINDOW))].to_vec()
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
    // 17, 18: user_agent, referer (valid UTF-8 is not required by the
    // decoders the agent uses, but lossy text keeps ClickHouse strings
    // printable)
    put_bytes(17, ev.user_agent, out);
    put_bytes(18, ev.referer, out);
    // 19: repeated Header headers
    for (name, value) in ev.headers {
        let mut h = Vec::with_capacity(name.len() + value.len() + 4);
        put_bytes(1, name, &mut h);
        put_bytes(2, value, &mut h);
        put_tag(19, 2, out);
        put_varint(h.len() as u64, out);
        out.extend_from_slice(&h);
    }
    // 20: inspection
    put_uint32(20, ev.inspection as u32, out);
    // 21: would_block
    put_uint32(21, ev.would_block as u32, out);
    // 22: CanaryGroup canary (W12-G2-01)
    put_uint32(22, ev.canary as u32, out);
    // 24: ja4 (RV-N-02)
    put_string(24, ev.ja4, out);
}

/// The first `max` bytes of UTF-8 `b`, cut on a character boundary.
fn str_prefix(b: &[u8], max: usize) -> &[u8] {
    match std::str::from_utf8(b) {
        Ok(s) => truncate_str(s, max).as_bytes(),
        Err(_) => &b[..0],
    }
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

    // Step 0 (RV-G2-01): the context goes first: headers from the end,
    // then long snippets cut to the default size, before any match.
    let mut n_headers = cur.headers.len();
    while buf.len() > MAX_DATAGRAM && n_headers > 0 {
        n_headers -= 1;
        cur.headers = &ev.headers[..n_headers];
        buf.clear();
        encode_raw(&cur, &mut buf);
    }
    if buf.len() <= MAX_DATAGRAM {
        return buf;
    }
    let short: Vec<MatchData<'_>> = ev
        .matches
        .iter()
        .map(|m| MatchData {
            snippet: &m.snippet[..m.snippet.len().min(MAX_SNIPPET_LEN)],
            ..*m
        })
        .collect();
    cur.matches = &short;
    buf.clear();
    encode_raw(&cur, &mut buf);
    if buf.len() <= MAX_DATAGRAM {
        return buf;
    }

    // Step 1: Drop matches from the end until it fits or matches are empty.
    let mut n_matches = cur.matches.len();
    while buf.len() > MAX_DATAGRAM && n_matches > 0 {
        n_matches -= 1;
        cur.matches = &short[..n_matches];
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

    // Step 3: Progressively truncate the context, host / identity /
    // request_id if hostile
    if cur.user_agent.len() > 64 || cur.referer.len() > 64 {
        cur.user_agent = str_prefix(cur.user_agent, 64);
        cur.referer = str_prefix(cur.referer, 64);
        buf.clear();
        encode_raw(&cur, &mut buf);
    }
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

/// One RuleCost message (W13-R-02) as field `field_number`.
fn put_rule_cost(field_number: u32, c: &crate::rulecost::Cost, out: &mut Vec<u8>) {
    let mut m = Vec::with_capacity(24);
    put_uint32(1, c.0, &mut m);
    put_uint64(2, c.1, &mut m);
    put_uint64(3, c.2, &mut m);
    put_uint64(4, c.3, &mut m);
    put_tag(field_number, 2, out);
    put_varint(m.len() as u64, out);
    out.extend_from_slice(&m);
}

/// Appends the rule costs of a sampled transaction to its event
/// (`Event.rule_costs`, field 23), as many as fit `max` bytes in all.
pub fn append_rule_costs(costs: &[crate::rulecost::Cost], max: usize, out: &mut Vec<u8>) {
    for c in costs {
        let mut item = Vec::with_capacity(32);
        put_rule_cost(23, c, &mut item);
        if out.len() + item.len() > max {
            break;
        }
        out.extend_from_slice(&item);
    }
}

/// First bytes of a counters datagram on the event socket (RV-N-01,
/// `crate::counters`).
pub const COUNTERS_MAGIC: &[u8; 4] = b"\xffSC1";

/// Encodes per-policy counts (event.proto `PolicyCounters`) after
/// COUNTERS_MAGIC, as many entries as fit `max` bytes; returns the datagram
/// and how many entries it holds.
pub fn encode_counters(
    time_unix_ms: u64,
    node_id: &str,
    bundle_version: u64,
    entries: &[(&[u8], [u64; crate::counters::N])],
    max: usize,
) -> (Vec<u8>, usize) {
    encode_counters_with(
        time_unix_ms,
        node_id,
        bundle_version,
        entries,
        &RuleCostTake::default(),
        max,
    )
    .0
}

/// Rule costs to send with the counters (W13-R-02): the rules, and the
/// sampled transactions with their engine time.
#[derive(Debug, Default)]
pub struct RuleCostTake {
    pub costs: Vec<crate::rulecost::Cost>,
    pub requests: u64,
    pub engine_ns: u64,
}

/// Rules a counters datagram carries at most; the others wait.
pub const COUNTERS_RULES: usize = 64;

/// As `encode_counters`, with the rule costs after the policies: returns
/// the datagram, how many policies and how many rules it holds.
pub fn encode_counters_with(
    time_unix_ms: u64,
    node_id: &str,
    bundle_version: u64,
    entries: &[(&[u8], [u64; crate::counters::N])],
    costs: &RuleCostTake,
    max: usize,
) -> ((Vec<u8>, usize), usize) {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(COUNTERS_MAGIC);
    put_uint64(1, time_unix_ms, &mut out);
    put_string(2, node_id, &mut out);
    put_uint64(3, bundle_version, &mut out);
    let mut n = 0;
    for (name, v) in entries {
        let mut e = Vec::with_capacity(name.len() + 32);
        put_bytes(1, name, &mut e);
        for (k, x) in v.iter().enumerate() {
            put_uint64(k as u32 + 2, *x, &mut e);
        }
        let mut item = Vec::with_capacity(e.len() + 4);
        put_tag(4, 2, &mut item);
        put_varint(e.len() as u64, &mut item);
        item.extend_from_slice(&e);
        if out.len() + item.len() > max {
            break;
        }
        out.extend_from_slice(&item);
        n += 1;
    }
    let mut r = 0;
    if costs.requests > 0 {
        put_uint64(6, costs.requests, &mut out);
        put_uint64(7, costs.engine_ns, &mut out);
    }
    for c in costs.costs.iter().take(COUNTERS_RULES) {
        let mut item = Vec::with_capacity(32);
        put_rule_cost(5, c, &mut item);
        if out.len() + item.len() > max {
            break;
        }
        out.extend_from_slice(&item);
        r += 1;
    }
    ((out, n), r)
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
    fn test_mask_pan_in_snippets() {
        // P-01 §1: a card number in a field with an ordinary name
        let s = prepare_snippet("ARGS:data", b"pay with 4111 1111 1111 1111 now");
        assert_eq!(s, b"pay with ******************* now");
        let s = prepare_snippet("ARGS_NAMES", br#"{"q":{"n":"5500000000000004"}}"#);
        assert_eq!(s, br#"{"q":{"n":"****************"}}"#);
        // order numbers and timestamps stay readable
        assert_eq!(
            prepare_snippet("ARGS:t", b"1791907725413"),
            b"1791907725413"
        );
    }

    #[test]
    fn test_context_bounds_and_utf8() {
        let long = vec![b'a'; 5000];
        let bad_utf8: &[u8] = b"Mozilla \xff\xfe ok";
        let mut hs: Vec<(&[u8], &[u8])> = vec![(b"User-Agent", bad_utf8), (b"Referer", &long)];
        let names: Vec<String> = (0..50).map(|i| format!("X-H{i}")).collect();
        for n in &names {
            hs.push((n.as_bytes(), b"0123456789012345678901234567890123456789"));
        }
        let c = context(&hs);
        assert!(
            std::str::from_utf8(&c.user_agent).is_ok(),
            "user agent is UTF-8"
        );
        assert!(c.user_agent.starts_with(b"Mozilla "));
        assert_eq!(c.referer.len(), MAX_UA_LEN);
        assert!(c.headers.len() <= MAX_HEADERS);
        let bytes: usize = c.headers.iter().map(|(k, v)| k.len() + v.len()).sum();
        assert!(bytes <= MAX_HEADERS_BYTES, "{bytes}");
        // a sensitive header keeps its name, never its value
        let c = context(&[
            (b"X-Api-Key", b"k-123"),
            (b"Proxy-Authorization", b"Basic xyz"),
        ]);
        assert_eq!(
            c.headers,
            vec![
                (b"X-Api-Key".to_vec(), MASKED.to_vec()),
                (b"Proxy-Authorization".to_vec(), MASKED.to_vec())
            ]
        );
    }

    #[test]
    fn test_mask_query() {
        assert_eq!(mask_query(b"https://x.test/p"), b"https://x.test/p");
        assert_eq!(
            mask_query(b"https://x.test/p?a=1&Password=p&token=t&b#f?x=1"),
            b"https://x.test/p?a=1&Password=[MASKED]&token=[MASKED]&b#f?x=1"
        );
    }

    #[test]
    fn test_context_is_shed_before_matches() {
        // a full datagram: headers go first, then long snippets are cut,
        // and only then matches
        let big = vec![b'v'; 4000];
        let matches: Vec<MatchData<'_>> = (0..3)
            .map(|i| MatchData {
                rule_id: 942100 + i,
                layer: "managed",
                field: "ARGS:q",
                snippet: &big,
            })
            .collect();
        let hs: Vec<(&[u8], &[u8])> = (0..32).map(|_| (&b"X-Long"[..], &big[..60])).collect();
        let ev = EventData {
            block_id: "STR-AAAA-BBBB-CCCC-DDDD",
            time_unix_ms: 1,
            node_id: "n",
            request_id: "",
            policy_id: "example-api",
            bundle_version: 1,
            client_ip: "192.0.2.1",
            identity: "",
            method: "GET",
            host: "api.example.test",
            path: "/",
            status: 403,
            action: Action::Block,
            layer_scores: &[],
            rule_ids: &[942100, 942101, 942102],
            matches: &matches,
            user_agent: b"ua",
            referer: b"",
            headers: &hs,
            inspection: Inspection::Full,
            would_block: false,
            canary: CanaryGroup::None,
            ja4: "",
        };
        let out = encode(&ev);
        assert!(out.len() <= MAX_DATAGRAM);
        // the three rules stay, with cut snippets
        for r in [942100u32, 942101, 942102] {
            let mut tag = vec![0x08];
            put_varint(r as u64, &mut tag);
            assert!(out.windows(tag.len()).any(|w| w == &tag[..]), "rule {r}");
        }
    }

    #[test]
    fn test_p01_sensitive_names() {
        for f in [
            "ARGS:mat_khau",
            "ARGS:MatKhau",
            "ARGS:so_the",
            "ARGS:card_number",
            "ARGS:user.client_secret",
            "REQUEST_HEADERS:Set-Cookie",
            "ARGS:id_token",
        ] {
            assert!(is_sensitive_target(f), "{f}");
            assert_eq!(prepare_snippet(f, b"value"), b"", "{f}");
        }
        assert!(!is_sensitive_target("ARGS:sessionless_query"));
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
            user_agent: b"",
            referer: b"",
            headers: &[],
            inspection: Default::default(),
            would_block: false,
            canary: CanaryGroup::None,
            ja4: "",
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
            user_agent: b"",
            referer: b"",
            headers: &[],
            inspection: Default::default(),
            would_block: false,
            canary: CanaryGroup::None,
            ja4: "",
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
            user_agent: b"",
            referer: b"",
            headers: &[],
            inspection: Default::default(),
            would_block: false,
            canary: CanaryGroup::None,
            ja4: "",
        };

        let encoded = encode(&ev);
        assert!(encoded.len() <= MAX_DATAGRAM);
    }
}
