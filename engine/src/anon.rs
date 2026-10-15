//! Anonymization of replay samples, format 1 (docs/spec/replay-sample.md;
//! W12-N-01): the connector side of `control-plane/replay/anonymize.go`.
//! Only sensitive values are replaced by keyed hashes (PO decision
//! 14/10/2026); the structure of the request and the ordinary values stay,
//! so that content rules still run on replay.
//!
//! Both writers must give the same records for the same request
//! (docs/spec/examples/replay-anon-v1.json and the differential corpus of
//! engine/tests/fixtures), so this module follows the Go code step by step,
//! including the parts of Go's standard library it relies on: `net/url`
//! escaping, `mime.ParseMediaType`, `mime/multipart` and `net/textproto`
//! header reading, and `encoding/json`. Values are bytes, as Go strings
//! are. Parsers are loops with bounded depth; regexes are linear (`regex`).

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::bytes::Regex;
use sha2::{Digest, Sha256};

/// Body kept per request by default (the control plane's writer).
pub const DEFAULT_MAX_BODY: usize = 64 << 10;

/// One request as the sampler saw it (not anonymized).
#[derive(Clone, Debug, Default)]
pub struct Request<'a> {
    pub ts_ms: i64,
    pub node_id: &'a [u8],
    pub policy: &'a [u8],
    pub method: &'a [u8],
    pub raw_uri: &'a [u8],
    pub uri: &'a [u8],
    pub args: &'a [u8],
    pub proto: &'a [u8],
    pub client: &'a [u8],
    pub headers: Vec<(&'a [u8], &'a [u8])>,
    pub body: &'a [u8],
    /// The body was longer than what the sampler kept (its full length).
    pub body_len: Option<usize>,
    pub action: &'a [u8],
    pub rules: &'a [u32],
}

/// One row of a sample file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub ts_ms: i64,
    pub node_id: Vec<u8>,
    pub policy: Vec<u8>,
    pub method: Vec<u8>,
    pub raw_uri: Vec<u8>,
    pub uri: Vec<u8>,
    pub args: Vec<u8>,
    pub proto: Vec<u8>,
    pub client: Vec<u8>,
    /// JSON `[[name, value], ...]`.
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
    pub body_len: i64,
    pub body_truncated: bool,
    pub action: Vec<u8>,
    pub rules: Vec<u8>,
}

/// Replaces sensitive values with keyed hashes.
pub struct Anonymizer {
    key: Vec<u8>,
    pub key_id: String,
    pub max_body: usize,
    /// The policy's `privacy.sensitive_fields` (#75), lowercase: parameters,
    /// JSON keys, form fields and headers with these names become tokens.
    fields: Vec<Vec<u8>>,
    /// The policy's `privacy.mask_patterns` (#75): matches become tokens.
    patterns: Vec<Regex>,
}

impl Anonymizer {
    /// `key`: at least 32 bytes; `key_id` must not be empty.
    pub fn new(key: &[u8], key_id: &str) -> Option<Anonymizer> {
        (key.len() >= 32 && !key_id.is_empty()).then(|| Anonymizer {
            key: key.to_vec(),
            key_id: key_id.to_string(),
            max_body: DEFAULT_MAX_BODY,
            fields: vec![],
            patterns: vec![],
        })
    }

    /// Adds a policy's privacy settings (P-01 §1, #75) to the built-in
    /// lists: field names (matched whole, ASCII case-insensitive) and
    /// patterns (as the engine compiles them).
    pub fn set_privacy(&mut self, fields: &[String], patterns: &[Regex]) {
        self.fields = fields.iter().map(|f| go_lower(f.as_bytes())).collect();
        self.patterns = patterns.to_vec();
    }

    /// Whether a parameter, JSON key or form field named `name` holds a
    /// sensitive value: the built-in name parts, or the policy's fields.
    fn sensitive(&self, name: &[u8]) -> bool {
        sensitive_name(name) || self.policy_field(name)
    }

    fn policy_field(&self, name: &[u8]) -> bool {
        !self.fields.is_empty() && {
            let n = go_lower(name);
            self.fields.contains(&n)
        }
    }

    /// Token of a sensitive value: `~h:<16 hex>:<class><length>`.
    pub fn token(&self, v: &[u8]) -> Vec<u8> {
        let mac = hmac_sha256(&self.key, v);
        let mut out = b"~h:".to_vec();
        for b in &mac[..8] {
            out.extend_from_slice(format!("{b:02x}").as_bytes());
        }
        out.push(b':');
        out.push(class(v));
        out.extend_from_slice(v.len().to_string().as_bytes());
        out
    }

    /// Replaces the parts of `s` that look like personal data (JWT, email,
    /// Vietnamese phone number, CCCD, card number) with tokens.
    pub fn mask_value(&self, s: &[u8]) -> Vec<u8> {
        let re = regexes();
        let mut spans: Vec<(usize, usize)> = vec![];
        for r in [&re.jwt, &re.email].into_iter().chain(&self.patterns) {
            spans.extend(r.find_iter(s).map(|m| (m.start(), m.end())));
        }
        for m in re.digits.find_iter(s) {
            digit_spans(s, m.start(), m.end(), &mut spans);
        }
        if spans.is_empty() {
            return s.to_vec();
        }
        // earliest first, the longest at one position; drop overlaps
        spans.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        let mut out = Vec::with_capacity(s.len() + 32);
        let mut at = 0;
        for (start, end) in spans {
            if start < at {
                continue;
            }
            out.extend_from_slice(&s[at..start]);
            out.extend_from_slice(&self.token(&s[start..end]));
            at = end;
        }
        out.extend_from_slice(&s[at..]);
        out
    }

    /// Turns a request into a sample record.
    pub fn anonymize(&self, r: &Request<'_>) -> Record {
        let max = if self.max_body == 0 {
            DEFAULT_MAX_BODY
        } else {
            self.max_body
        };
        let full_len = r.body_len.unwrap_or(r.body.len()).max(r.body.len());
        let (body, truncated) = if r.body.len() > max {
            (&r.body[..max], true)
        } else {
            (r.body, full_len > r.body.len())
        };
        let ct = header(&r.headers, b"content-type");
        let anon_body = self.body(ct, body);

        let mut hj = vec![b'['];
        for (i, (name, value)) in r.headers.iter().enumerate() {
            let v = if name.eq_ignore_ascii_case(b"content-length") && !truncated && full_len > 0 {
                // the body changed length: keep the header true to it
                anon_body.len().to_string().into_bytes()
            } else {
                self.header_value(name, value)
            };
            if i > 0 {
                hj.push(b',');
            }
            hj.push(b'[');
            json_string(&mut hj, name, true);
            hj.push(b',');
            json_string(&mut hj, &v, true);
            hj.push(b']');
        }
        hj.push(b']');

        let rules = r
            .rules
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let (path, query) = match r.raw_uri.iter().position(|&c| c == b'?') {
            Some(i) => (&r.raw_uri[..i], Some(&r.raw_uri[i + 1..])),
            None => (r.raw_uri, None),
        };
        let mut raw = self.path(path);
        if let Some(q) = query {
            raw.push(b'?');
            raw.extend_from_slice(&self.query(q));
        }
        Record {
            ts_ms: r.ts_ms,
            node_id: r.node_id.to_vec(),
            policy: r.policy.to_vec(),
            method: r.method.to_vec(),
            raw_uri: raw,
            uri: self.mask_value(r.uri),
            args: self.query(r.args),
            proto: r.proto.to_vec(),
            client: self.token(r.client),
            headers: hj,
            body: anon_body,
            body_len: full_len as i64,
            body_truncated: truncated,
            action: r.action.to_vec(),
            rules: rules.into_bytes(),
        }
    }

    fn header_value(&self, name: &[u8], value: &[u8]) -> Vec<u8> {
        let n = go_lower(name);
        if self.policy_field(name) && !SENSITIVE_HEADERS.contains(&n.as_slice()) {
            return self.token(value);
        }
        if !SENSITIVE_HEADERS.contains(&n.as_slice()) {
            return self.mask_value(value);
        }
        match n.as_slice() {
            b"authorization" | b"proxy-authorization" => {
                if let Some(i) = value.iter().position(|&c| c == b' ') {
                    let scheme = &value[..i];
                    if !scheme.is_empty() && !scheme.iter().any(|&c| c == b'=' || c == b':') {
                        let mut out = scheme.to_vec();
                        out.push(b' ');
                        out.extend_from_slice(&self.token(&value[i + 1..]));
                        return out;
                    }
                }
            }
            b"cookie" => {
                let mut out = vec![];
                for (i, p) in value.split(|&c| c == b';').enumerate() {
                    if i > 0 {
                        out.push(b';');
                    }
                    match p.iter().position(|&c| c == b'=') {
                        Some(j) => {
                            out.extend_from_slice(&p[..j]);
                            out.push(b'=');
                            out.extend_from_slice(&self.token(&p[j + 1..]));
                        }
                        None => out.extend_from_slice(&self.token(p)),
                    }
                }
                return out;
            }
            _ => {}
        }
        self.token(value)
    }

    /// Each segment, decoded for the check, written back as it came unless
    /// a value was replaced.
    fn path(&self, p: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        for (i, s) in p.split(|&c| c == b'/').enumerate() {
            if i > 0 {
                out.push(b'/');
            }
            out.extend_from_slice(&self.encoded(s, false, Mode::PathSegment));
        }
        out
    }

    /// name=value pairs split on '&', names kept.
    fn query(&self, q: &[u8]) -> Vec<u8> {
        if q.is_empty() {
            return vec![];
        }
        let mut out = vec![];
        for (i, p) in q.split(|&c| c == b'&').enumerate() {
            if i > 0 {
                out.push(b'&');
            }
            match p.iter().position(|&c| c == b'=') {
                None => out.extend_from_slice(&self.encoded(p, false, Mode::Query)),
                Some(j) => {
                    let k = &p[..j];
                    let name = unescape(k, Mode::Query).unwrap_or_else(|| k.to_vec());
                    out.extend_from_slice(k);
                    out.push(b'=');
                    out.extend_from_slice(&self.encoded(
                        &p[j + 1..],
                        self.sensitive(&name),
                        Mode::Query,
                    ));
                }
            }
        }
        out
    }

    /// Anonymizes a percent-encoded value. The raw text is kept unless it
    /// changes, so that encodings (double encoding, odd escapes) still reach
    /// the engine on replay.
    fn encoded(&self, raw: &[u8], sensitive: bool, mode: Mode) -> Vec<u8> {
        if raw.is_empty() {
            return vec![];
        }
        let dec = unescape(raw, mode).unwrap_or_else(|| raw.to_vec());
        if sensitive {
            return escape(&self.token(&dec), mode);
        }
        let m = self.mask_value(&dec);
        if m != dec {
            return escape(&m, mode);
        }
        raw.to_vec()
    }

    fn body(&self, ct: &[u8], b: &[u8]) -> Vec<u8> {
        if b.is_empty() {
            return vec![];
        }
        let (mt, params) = parse_media_type(ct).unwrap_or_default();
        if mt == b"application/x-www-form-urlencoded" {
            return self.query(b);
        }
        if mt == b"application/json" || mt.ends_with(b"+json") {
            if let Some(out) = self.json(b) {
                return out;
            }
        } else if mt == b"multipart/form-data"
            && let Some(bd) = params
                .as_ref()
                .and_then(|p| p.get(&b"boundary"[..]))
                .filter(|b| !b.is_empty())
            && let Some(out) = self.multipart(b, bd)
        {
            return out;
        }
        self.mask_value(b)
    }

    /// Rewrites a JSON document compactly, keys in their order; None when
    /// the document is not valid JSON or nested deeper than 64.
    fn json(&self, b: &[u8]) -> Option<Vec<u8>> {
        let mut p = JsonParser { b, i: 0 };
        let mut out = Vec::with_capacity(b.len());
        // containers: (is_object, sensitive, count)
        let mut stack: Vec<(bool, bool, usize)> = vec![];
        p.ws();
        let mut sensitive = false; // of the value about to be read
        loop {
            // a value
            if stack.len() > MAX_JSON_DEPTH {
                return None;
            }
            match p.peek()? {
                b'{' | b'[' => {
                    let obj = p.b[p.i] == b'{';
                    p.i += 1;
                    out.push(if obj { b'{' } else { b'[' });
                    stack.push((obj, sensitive, 0));
                    p.ws();
                    let close = if obj { b'}' } else { b']' };
                    if p.peek() == Some(close) {
                        p.i += 1;
                        out.push(close);
                        stack.pop();
                    } else {
                        if !self.json_next(&mut p, &mut out, &mut stack, &mut sensitive)? {
                            return None;
                        }
                        continue;
                    }
                }
                b'"' => {
                    let s = p.string()?;
                    let v = if sensitive {
                        self.token(&s)
                    } else {
                        self.mask_value(&s)
                    };
                    json_string(&mut out, &v, false);
                }
                b't' => p.literal(b"true", &mut out)?,
                b'f' => p.literal(b"false", &mut out)?,
                b'n' => p.literal(b"null", &mut out)?,
                _ => {
                    let n = p.number()?;
                    let m = self.mask_value(n);
                    if sensitive {
                        json_string(&mut out, &self.token(n), false);
                    } else if m != n {
                        json_string(&mut out, &m, false);
                    } else {
                        out.extend_from_slice(n);
                    }
                }
            }
            // after a value: close containers or go to the next element
            loop {
                p.ws();
                let Some(&(obj, _, _)) = stack.last() else {
                    return (p.i == p.b.len()).then_some(out);
                };
                match p.peek()? {
                    b',' => {
                        p.i += 1;
                        out.push(b',');
                        p.ws();
                        if !self.json_next(&mut p, &mut out, &mut stack, &mut sensitive)? {
                            return None;
                        }
                        break;
                    }
                    c if c == if obj { b'}' } else { b']' } => {
                        p.i += 1;
                        out.push(c);
                        stack.pop();
                    }
                    _ => return None,
                }
            }
        }
    }

    /// Reads what precedes the next element of the innermost container: the
    /// key of an object member. Sets the element's sensitivity.
    fn json_next(
        &self,
        p: &mut JsonParser<'_>,
        out: &mut Vec<u8>,
        stack: &mut [(bool, bool, usize)],
        sensitive: &mut bool,
    ) -> Option<bool> {
        let (obj, sens, n) = stack.last_mut()?;
        *n += 1;
        if !*obj {
            *sensitive = *sens;
            return Some(true);
        }
        if p.peek()? != b'"' {
            return Some(false);
        }
        let k = p.string()?;
        json_string(out, &k, false);
        out.push(b':');
        p.ws();
        if p.peek()? != b':' {
            return Some(false);
        }
        p.i += 1;
        p.ws();
        *sensitive = *sens || self.sensitive(&k);
        Some(true)
    }

    /// Rewrites the parts: headers kept (in a stable order), text fields
    /// anonymized, file contents always a token.
    fn multipart(&self, b: &[u8], boundary: &[u8]) -> Option<Vec<u8>> {
        let mut r = Multipart::new(b, boundary);
        let mut out = vec![];
        while let Some(part) = r.next_part()? {
            out.extend_from_slice(b"--");
            out.extend_from_slice(boundary);
            out.extend_from_slice(b"\r\n");
            let mut keys: Vec<&Vec<u8>> = part.header.keys().collect();
            keys.sort();
            for k in keys {
                for v in &part.header[k] {
                    out.extend_from_slice(k);
                    out.extend_from_slice(b": ");
                    out.extend_from_slice(v);
                    out.extend_from_slice(b"\r\n");
                }
            }
            out.extend_from_slice(b"\r\n");
            let (disposition, dparams) = part
                .header
                .get(&b"Content-Disposition"[..])
                .and_then(|v| v.first())
                .map(|v| match parse_media_type(v) {
                    Ok((d, p)) => (d, p.unwrap_or_default()),
                    Err(_) => (vec![], HashMap::new()),
                })
                .unwrap_or_default();
            let file = dparams.get(&b"filename"[..]).is_some_and(|f| !f.is_empty());
            let form_name: &[u8] = if disposition == b"form-data" {
                dparams.get(&b"name"[..]).map_or(&[], |v| v)
            } else {
                &[]
            };
            if file || self.sensitive(form_name) {
                out.extend_from_slice(&self.token(part.content));
            } else {
                out.extend_from_slice(&self.mask_value(part.content));
            }
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"--");
        out.extend_from_slice(boundary);
        out.extend_from_slice(b"--\r\n");
        Some(out)
    }
}

const MAX_JSON_DEPTH: usize = 64;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(ih);
    outer.finalize().into()
}

fn class(v: &[u8]) -> u8 {
    let (mut digits, mut letters, mut other) = (0, 0, 0);
    for &c in v {
        match c {
            b'0'..=b'9' => digits += 1,
            b'a'..=b'z' | b'A'..=b'Z' => letters += 1,
            _ => other += 1,
        }
    }
    if other > 0 || v.is_empty() {
        b's'
    } else if letters == 0 {
        b'd'
    } else if digits == 0 {
        b'a'
    } else {
        b'x'
    }
}

const SENSITIVE_HEADERS: [&[u8]; 13] = [
    b"authorization",
    b"proxy-authorization",
    b"cookie",
    b"set-cookie",
    b"x-api-key",
    b"x-auth-token",
    b"x-csrf-token",
    b"x-xsrf-token",
    b"x-forwarded-for",
    b"x-real-ip",
    b"forwarded",
    b"true-client-ip",
    b"cf-connecting-ip",
];

const SENSITIVE_NAME_PARTS: [&[u8]; 27] = [
    b"password",
    b"passwd",
    b"pwd",
    b"secret",
    b"token",
    b"otp",
    b"pin",
    b"cvv",
    b"card",
    b"cccd",
    b"cmnd",
    b"ssn",
    b"passport",
    b"apikey",
    b"api_key",
    b"auth",
    b"session",
    b"phone",
    b"mobile",
    b"email",
    b"dob",
    b"birth",
    b"name",
    b"user",
    b"address",
    b"account",
    b"iban",
];

/// Go's `strings.ToLower`: simple case mapping rune by rune, invalid UTF-8
/// bytes as U+FFFD.
fn go_lower(s: &[u8]) -> Vec<u8> {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    let mut out = String::with_capacity(s.len());
    for c in String::from_utf8_lossy(s).chars() {
        let mut l = c.to_lowercase();
        // U+0130 is the one rune whose full lower case is two runes; Go's
        // simple mapping gives 'i'
        match (l.next(), l.next()) {
            (Some(a), None) => out.push(a),
            _ => out.push(if c == '\u{130}' { 'i' } else { c }),
        }
    }
    out.into_bytes()
}

/// Whether a parameter, JSON key or form field named `name` holds a
/// sensitive value.
pub fn sensitive_name(name: &[u8]) -> bool {
    let n = go_lower(name);
    SENSITIVE_NAME_PARTS
        .iter()
        .any(|p| memchr::memmem::find(&n, p).is_some())
}

struct Regexes {
    jwt: Regex,
    email: Regex,
    digits: Regex,
    phone: Regex,
}

fn regexes() -> &'static Regexes {
    static R: OnceLock<Regexes> = OnceLock::new();
    R.get_or_init(|| Regexes {
        jwt: Regex::new(r"(?-u)eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*").expect("regex"),
        email: Regex::new(r"(?-u)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").expect("regex"),
        digits: Regex::new(r"(?-u)\+?[0-9](?:[0-9 -]*[0-9])?").expect("regex"),
        phone: Regex::new(r"(?-u)^(?:\+84|84|0)[35789][0-9]{8}$").expect("regex"),
    })
}

/// The personal numbers in the digit run s[start..end] (which may hold
/// spaces and dashes): the whole run when it is a card number, else each
/// separated group that is a phone, CCCD or card number.
fn digit_spans(s: &[u8], start: usize, end: usize, out: &mut Vec<(usize, usize)>) {
    let run = &s[start..end];
    let digits: Vec<u8> = run
        .iter()
        .copied()
        .filter(|c| !matches!(c, b' ' | b'-' | b'+'))
        .collect();
    if run.iter().any(|&c| c == b' ' || c == b'-') && run.first() != Some(&b'+') && card(&digits) {
        out.push((start, end));
        return;
    }
    let mut i = start;
    while i < end {
        let mut j = i;
        while j < end && s[j] != b' ' && s[j] != b'-' {
            j += 1;
        }
        let g = &s[i..j];
        let d = g.strip_prefix(b"+").unwrap_or(g);
        let all_digits = !d.is_empty() && d.iter().all(u8::is_ascii_digit);
        if all_digits
            && (regexes().phone.is_match(g) || (g.len() == d.len() && (d.len() == 12 || card(d))))
        {
            out.push((i, j));
        }
        i = j + 1;
    }
}

/// 13 to 19 digits passing the Luhn check.
fn card(d: &[u8]) -> bool {
    if !(13..=19).contains(&d.len()) {
        return false;
    }
    let mut sum = 0;
    for (i, &c) in d.iter().rev().enumerate() {
        if !c.is_ascii_digit() {
            return false;
        }
        let mut n = u32::from(c - b'0');
        if i % 2 == 1 {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
    }
    sum % 10 == 0
}

fn header<'a>(hs: &[(&'a [u8], &'a [u8])], name: &[u8]) -> &'a [u8] {
    hs.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map_or(&[], |(_, v)| v)
}

// --- net/url --------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    PathSegment,
    Query,
}

fn unhex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// url.PathUnescape / url.QueryUnescape; None on a bad escape.
fn unescape(s: &[u8], mode: Mode) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'%' => {
                let hi = s.get(i + 1).copied().and_then(unhex)?;
                let lo = s.get(i + 2).copied().and_then(unhex)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' if mode == Mode::Query => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

fn should_escape(c: u8, mode: Mode) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Mode::PathSegment => matches!(c, b'/' | b';' | b',' | b'?'),
            Mode::Query => true,
        },
        _ => true,
    }
}

/// url.PathEscape / url.QueryEscape.
fn escape(s: &[u8], mode: Mode) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        if c == b' ' && mode == Mode::Query {
            out.push(b'+');
        } else if should_escape(c, mode) {
            out.extend_from_slice(&[b'%', HEX[usize::from(c >> 4)], HEX[usize::from(c & 15)]]);
        } else {
            out.push(c);
        }
    }
    out
}

// --- mime.ParseMediaType ---------------------------------------------------

type Params = HashMap<Vec<u8>, Vec<u8>>;

fn is_tspecial(c: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&c)
}

fn is_token_char(c: u8) -> bool {
    c > 0x20 && c < 0x7f && !is_tspecial(c)
}

fn consume_token(v: &[u8]) -> (&[u8], &[u8]) {
    let i = v.iter().position(|&c| !is_token_char(c)).unwrap_or(v.len());
    (&v[..i], &v[i..])
}

/// Go's unicode.IsSpace, rune by rune; an invalid byte is not a space.
fn trim_left_space(v: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < v.len() {
        let n = utf8_len(v[i]);
        match std::str::from_utf8(&v[i..(i + n).min(v.len())])
            .ok()
            .and_then(|s| s.chars().next())
        {
            Some(c) if c.is_whitespace() => i += n,
            _ => break,
        }
    }
    &v[i..]
}

fn trim_right_space(v: &[u8]) -> &[u8] {
    let mut end = v.len();
    while end > 0 {
        let mut start = end - 1;
        while start > 0 && end - start < 4 && v[start] & 0xc0 == 0x80 {
            start -= 1;
        }
        match std::str::from_utf8(&v[start..end])
            .ok()
            .and_then(|s| s.chars().next())
        {
            Some(c) if c.is_whitespace() => end = start,
            _ => break,
        }
    }
    &v[..end]
}

fn utf8_len(b: u8) -> usize {
    match b {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

fn consume_value(v: &[u8]) -> (Vec<u8>, &[u8]) {
    if v.is_empty() {
        return (vec![], v);
    }
    if v[0] != b'"' {
        let (t, rest) = consume_token(v);
        return (t.to_vec(), rest);
    }
    let mut buf = vec![];
    let mut i = 1;
    while i < v.len() {
        let r = v[i];
        if r == b'"' {
            return (buf, &v[i + 1..]);
        }
        if r == b'\\' && i + 1 < v.len() && is_tspecial(v[i + 1]) {
            buf.push(v[i + 1]);
            i += 2;
            continue;
        }
        if r == b'\r' || r == b'\n' {
            return (vec![], v);
        }
        buf.push(r);
        i += 1;
    }
    (vec![], v)
}

fn consume_media_param(v: &[u8]) -> (Vec<u8>, Vec<u8>, &[u8]) {
    let rest = trim_left_space(v);
    let Some(rest) = rest.strip_prefix(b";") else {
        return (vec![], vec![], v);
    };
    let (param, rest) = consume_token(trim_left_space(rest));
    let param = param.to_ascii_lowercase();
    if param.is_empty() {
        return (vec![], vec![], v);
    }
    let Some(rest) = trim_left_space(rest).strip_prefix(b"=") else {
        return (vec![], vec![], v);
    };
    let rest = trim_left_space(rest);
    let (value, rest2) = consume_value(rest);
    if value.is_empty() && rest2.len() == rest.len() {
        return (vec![], vec![], v);
    }
    (param, value, rest2)
}

fn percent_hex_unescape(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'%' {
            out.push(s[i]);
            i += 1;
            continue;
        }
        if i + 2 >= s.len() {
            return None;
        }
        out.push(unhex(s[i + 1])? << 4 | unhex(s[i + 2])?);
        i += 3;
    }
    Some(out)
}

fn decode_2231(v: &[u8]) -> Option<Vec<u8>> {
    let mut sv = v.splitn(3, |&c| c == b'\'');
    let (charset, _lang, enc) = (sv.next()?, sv.next()?, sv.next()?);
    let charset = charset.to_ascii_lowercase();
    if charset != b"us-ascii" && charset != b"utf-8" {
        return None;
    }
    percent_hex_unescape(enc)
}

fn check_media_type(s: &[u8]) -> bool {
    let (typ, rest) = consume_token(s);
    if typ.is_empty() {
        return false;
    }
    if rest.is_empty() {
        return true;
    }
    let Some(rest) = rest.strip_prefix(b"/") else {
        return false;
    };
    let (sub, rest) = consume_token(rest);
    !sub.is_empty() && rest.is_empty()
}

/// mime.ParseMediaType: Err on a bad media type; Ok((type, None)) when
/// only the parameters are bad (Go returns the type with no parameters).
fn parse_media_type(v: &[u8]) -> Result<(Vec<u8>, Option<Params>), ()> {
    let base = v.split(|&c| c == b';').next().unwrap_or(v);
    let mt = trim_right_space(trim_left_space(&go_lower(base))).to_vec();
    if !check_media_type(&mt) {
        return Err(());
    }
    let mut params: Params = HashMap::new();
    let mut continuation: HashMap<Vec<u8>, Params> = HashMap::new();
    let mut v = &v[base.len()..];
    while !v.is_empty() {
        v = trim_left_space(v);
        if v.is_empty() {
            break;
        }
        let (key, value, rest) = consume_media_param(v);
        if key.is_empty() {
            if trim_right_space(trim_left_space(rest)) == b";" {
                break;
            }
            return Ok((mt, None));
        }
        let pmap = match key.iter().position(|&c| c == b'*') {
            Some(i) => continuation.entry(key[..i].to_vec()).or_default(),
            None => &mut params,
        };
        if let Some(old) = pmap.get(&key)
            && *old != value
        {
            return Err(());
        }
        pmap.insert(key, value);
        v = rest;
    }
    for (key, pieces) in continuation {
        let mut single = key.clone();
        single.push(b'*');
        if let Some(v) = pieces.get(&single) {
            if let Some(d) = decode_2231(v) {
                params.insert(key, d);
            }
            continue;
        }
        let mut buf = vec![];
        let mut valid = false;
        for n in 0.. {
            let mut simple = key.clone();
            simple.push(b'*');
            simple.extend_from_slice(n.to_string().as_bytes());
            if let Some(v) = pieces.get(&simple) {
                valid = true;
                buf.extend_from_slice(v);
                continue;
            }
            simple.push(b'*');
            let Some(v) = pieces.get(&simple) else {
                break;
            };
            valid = true;
            if n == 0 {
                if let Some(d) = decode_2231(v) {
                    buf.extend_from_slice(&d);
                }
            } else if let Some(d) = percent_hex_unescape(v) {
                buf.extend_from_slice(&d);
            }
        }
        if valid {
            params.insert(key, buf);
        }
    }
    Ok((mt, Some(params)))
}

// --- encoding/json ----------------------------------------------------------

/// A JSON string as Go's encoder writes it; `html` also escapes <, > and &
/// (json.Marshal does, an Encoder with SetEscapeHTML(false) does not).
fn json_string(out: &mut Vec<u8>, s: &[u8], html: bool) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c < 0x80 {
            match c {
                b'\\' | b'"' => out.extend_from_slice(&[b'\\', c]),
                0x08 => out.extend_from_slice(b"\\b"),
                0x0c => out.extend_from_slice(b"\\f"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b'<' | b'>' | b'&' if html => out.extend_from_slice(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[usize::from(c >> 4)],
                    HEX[usize::from(c & 15)],
                ]),
                0..=0x1f => out.extend_from_slice(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[usize::from(c >> 4)],
                    HEX[usize::from(c & 15)],
                ]),
                _ => out.push(c),
            }
            i += 1;
            continue;
        }
        let n = utf8_len(c);
        match std::str::from_utf8(&s[i..(i + n).min(s.len())])
            .ok()
            .and_then(|x| x.chars().next())
        {
            Some(r) if n > 1 => {
                if r == '\u{2028}' || r == '\u{2029}' {
                    out.extend_from_slice(if r == '\u{2028}' {
                        b"\\u2028"
                    } else {
                        b"\\u2029"
                    });
                } else {
                    out.extend_from_slice(&s[i..i + n]);
                }
                i += n;
            }
            _ => {
                out.extend_from_slice(b"\\ufffd");
                i += 1;
            }
        }
    }
    out.push(b'"');
}

struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl JsonParser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\r' | b'\n') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn literal(&mut self, lit: &[u8], out: &mut Vec<u8>) -> Option<()> {
        if !self.b[self.i..].starts_with(lit) {
            return None;
        }
        self.i += lit.len();
        out.extend_from_slice(lit);
        Some(())
    }

    /// -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
    fn number(&mut self) -> Option<&[u8]> {
        let start = self.i;
        let b = self.b;
        let digits = |i: &mut usize| {
            let s = *i;
            while *i < b.len() && b[*i].is_ascii_digit() {
                *i += 1;
            }
            *i > s
        };
        let mut i = self.i;
        if b.get(i) == Some(&b'-') {
            i += 1;
        }
        match b.get(i) {
            Some(b'0') => i += 1,
            Some(b'1'..=b'9') => {
                digits(&mut i);
            }
            _ => return None,
        }
        if b.get(i) == Some(&b'.') {
            i += 1;
            if !digits(&mut i) {
                return None;
            }
        }
        if matches!(b.get(i), Some(b'e' | b'E')) {
            i += 1;
            if matches!(b.get(i), Some(b'+' | b'-')) {
                i += 1;
            }
            if !digits(&mut i) {
                return None;
            }
        }
        self.i = i;
        Some(&b[start..i])
    }

    fn hex4(&self, at: usize) -> Option<u32> {
        let h = self.b.get(at..at + 4)?;
        let mut v = 0u32;
        for &c in h {
            v = v << 4 | u32::from(unhex(c)?);
        }
        Some(v)
    }

    /// A string token, decoded as Go does (invalid UTF-8 and lone
    /// surrogates become U+FFFD).
    fn string(&mut self) -> Option<Vec<u8>> {
        self.i += 1; // the quote
        let mut out = vec![];
        let push = |out: &mut Vec<u8>, c: char| {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        };
        loop {
            let c = self.peek()?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Some(out);
                }
                0..=0x1f => return None,
                b'\\' => {
                    let e = *self.b.get(self.i + 1)?;
                    self.i += 2;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let r = self.hex4(self.i)?;
                            self.i += 4;
                            if (0xd800..0xe000).contains(&r) {
                                // a valid pair is consumed whole
                                let low = (self.b.get(self.i..self.i + 2) == Some(b"\\u"))
                                    .then(|| self.hex4(self.i + 2))
                                    .flatten()
                                    .filter(|l| {
                                        (0xd800..0xdc00).contains(&r)
                                            && (0xdc00..0xe000).contains(l)
                                    });
                                match low {
                                    Some(l) => {
                                        self.i += 6;
                                        let cp = 0x10000 + ((r - 0xd800) << 10) + (l - 0xdc00);
                                        push(&mut out, char::from_u32(cp).unwrap_or('\u{fffd}'));
                                    }
                                    None => push(&mut out, '\u{fffd}'),
                                }
                            } else {
                                push(&mut out, char::from_u32(r).unwrap_or('\u{fffd}'));
                            }
                        }
                        _ => return None,
                    }
                }
                0x20..=0x7f => {
                    out.push(c);
                    self.i += 1;
                }
                _ => {
                    let n = utf8_len(c);
                    let end = (self.i + n).min(self.b.len());
                    match std::str::from_utf8(&self.b[self.i..end]) {
                        Ok(s) if n > 1 && s.chars().count() == 1 => {
                            out.extend_from_slice(s.as_bytes());
                            self.i += n;
                        }
                        _ => {
                            push(&mut out, '\u{fffd}');
                            self.i += 1;
                        }
                    }
                }
            }
        }
    }
}

// --- mime/multipart + net/textproto -------------------------------------------

struct Part<'a> {
    header: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    content: &'a [u8],
}

/// mime/multipart.Reader over a body in memory, NextRawPart only.
struct Multipart<'a> {
    b: &'a [u8],
    pos: usize,
    nl: &'static [u8],
    dash_boundary: Vec<u8>,
    parts_read: usize,
}

/// bufio buffer of the Go reader: a line read with ReadSlice must fit.
const PEEK_BUFFER: usize = 4096;
const MAX_MIME_HEADERS: usize = 10000;

impl<'a> Multipart<'a> {
    fn new(b: &'a [u8], boundary: &[u8]) -> Self {
        let mut db = b"--".to_vec();
        db.extend_from_slice(boundary);
        Multipart {
            b,
            pos: 0,
            nl: b"\r\n",
            dash_boundary: db,
            parts_read: 0,
        }
    }

    fn nl_dash_boundary(&self) -> Vec<u8> {
        let mut v = self.nl.to_vec();
        v.extend_from_slice(&self.dash_boundary);
        v
    }

    /// bufio.Reader.ReadSlice('\n'): (line, at EOF without '\n'), None
    /// when the line does not fit the buffer.
    fn read_slice(&mut self) -> Option<(&'a [u8], bool)> {
        let rest = &self.b[self.pos..];
        match memchr::memchr(b'\n', &rest[..rest.len().min(PEEK_BUFFER)]) {
            Some(i) => {
                self.pos += i + 1;
                Some((&rest[..=i], false))
            }
            None if rest.len() < PEEK_BUFFER => {
                self.pos = self.b.len();
                Some((rest, true))
            }
            None => None,
        }
    }

    fn is_final_boundary(&self, line: &[u8]) -> bool {
        let mut dbd = self.dash_boundary.clone();
        dbd.extend_from_slice(b"--");
        let Some(rest) = line.strip_prefix(dbd.as_slice()) else {
            return false;
        };
        let rest = skip_lwsp(rest);
        rest.is_empty() || rest == self.nl
    }

    fn is_boundary_delimiter_line(&mut self, line: &[u8]) -> bool {
        let Some(rest) = line.strip_prefix(self.dash_boundary.as_slice()) else {
            return false;
        };
        let rest = skip_lwsp(rest);
        if self.parts_read == 0 && rest == b"\n" {
            self.nl = b"\n";
        }
        rest == self.nl
    }

    /// Ok(None) at the end; None on an error.
    fn next_part(&mut self) -> Option<Option<Part<'a>>> {
        if self.dash_boundary == b"--" {
            return None;
        }
        let mut expect_new_part = false;
        loop {
            let (line, eof) = self.read_slice()?;
            if eof && self.is_final_boundary(line) {
                return Some(None);
            }
            if eof {
                return None;
            }
            if self.is_boundary_delimiter_line(line) {
                self.parts_read += 1;
                // Go: an EOF in the headers is a plain io.EOF, which the
                // caller takes for the end of the parts
                let Some(header) = self.read_mime_header().ok()? else {
                    return Some(None);
                };
                let content = self.content()?;
                return Some(Some(Part { header, content }));
            }
            if self.is_final_boundary(line) {
                return Some(None);
            }
            if expect_new_part {
                return None;
            }
            if self.parts_read == 0 {
                continue;
            }
            if line == self.nl {
                expect_new_part = true;
                continue;
            }
            return None;
        }
    }

    /// The part's body: up to the boundary (partReader + scanUntilBoundary
    /// with the whole body read).
    fn content(&mut self) -> Option<&'a [u8]> {
        let buf = &self.b[self.pos..];
        let after = |b: &[u8], plen: usize| -> i8 {
            // matchAfterPrefix with the read error set (all data is here)
            match b.get(plen) {
                None => 1,
                Some(b' ' | b'\t' | b'\r' | b'\n') => 1,
                Some(b'-') => match b.get(plen + 1) {
                    None => -1,
                    Some(b'-') => 1,
                    _ => -1,
                },
                _ => -1,
            }
        };
        if buf.starts_with(&self.dash_boundary) && after(buf, self.dash_boundary.len()) == 1 {
            return Some(&buf[..0]); // an empty part right at the boundary
        }
        let ndb = self.nl_dash_boundary();
        let mut from = 0;
        if buf.starts_with(&self.dash_boundary) {
            from = self.dash_boundary.len(); // "-1": part of the body
        }
        while let Some(i) = memchr::memmem::find(&buf[from..], &ndb) {
            let at = from + i;
            if after(&buf[at..], ndb.len()) == 1 {
                self.pos += at;
                return Some(&buf[..at]);
            }
            from = at + ndb.len();
        }
        None // no boundary: unexpected EOF
    }

    /// textproto readMIMEHeader on the bytes at pos: Ok(None) at EOF
    /// before the blank line, Err on a malformed header.
    #[allow(clippy::type_complexity)]
    fn read_mime_header(&mut self) -> Result<Option<HashMap<Vec<u8>, Vec<Vec<u8>>>>, ()> {
        let mut m: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
        if matches!(self.b.get(self.pos), Some(b' ' | b'\t')) {
            return Err(());
        }
        let mut n = 0;
        loop {
            let Some(kv) = self.read_continued_line()? else {
                return Ok(None);
            };
            if kv.is_empty() {
                return Ok(Some(m));
            }
            let c = kv.iter().position(|&c| c == b':').ok_or(())?;
            let (k, v) = (&kv[..c], &kv[c + 1..]);
            let key = canonical_mime_header_key(k).ok_or(())?;
            if !v.iter().all(|&c| valid_header_value_byte(c)) {
                return Err(());
            }
            n += 1;
            if n > MAX_MIME_HEADERS {
                return Err(());
            }
            let value = v
                .iter()
                .position(|&c| c != b' ' && c != b'\t')
                .map_or(&v[v.len()..], |i| &v[i..]);
            m.entry(key).or_default().push(value.to_vec());
        }
    }

    /// bufio.ReadLine: the line without "\n" or "\r\n"; None at EOF.
    fn read_line(&mut self) -> Option<&'a [u8]> {
        let rest = &self.b[self.pos..];
        if rest.is_empty() {
            return None;
        }
        match memchr::memchr(b'\n', rest) {
            Some(i) => {
                self.pos += i + 1;
                let l = &rest[..i];
                Some(l.strip_suffix(b"\r").unwrap_or(l))
            }
            None => {
                self.pos = self.b.len();
                Some(rest)
            }
        }
    }

    /// readContinuedLineSlice: a header line and its continuation lines;
    /// Ok(None) at EOF, Err for a line without a colon.
    fn read_continued_line(&mut self) -> Result<Option<Vec<u8>>, ()> {
        let Some(line) = self.read_line() else {
            return Ok(None);
        };
        if line.is_empty() {
            return Ok(Some(vec![]));
        }
        if !line.contains(&b':') {
            return Err(());
        }
        let mut buf = trim(line).to_vec();
        loop {
            let mut sp = 0;
            while matches!(self.b.get(self.pos), Some(b' ' | b'\t')) {
                self.pos += 1;
                sp += 1;
            }
            if sp == 0 {
                break;
            }
            buf.push(b' ');
            match self.read_line() {
                Some(l) => buf.extend_from_slice(trim(l)),
                None => break,
            }
        }
        Ok(Some(buf))
    }
}

fn skip_lwsp(b: &[u8]) -> &[u8] {
    let i = b
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(b.len());
    &b[i..]
}

fn trim(s: &[u8]) -> &[u8] {
    let s = skip_lwsp(s);
    let end = s
        .iter()
        .rposition(|&c| c != b' ' && c != b'\t')
        .map_or(0, |i| i + 1);
    &s[..end]
}

fn valid_header_field_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn valid_header_value_byte(c: u8) -> bool {
    c >= 0x80 || (0x20..0x7f).contains(&c) || c == b'\t'
}

fn canonical_mime_header_key(a: &[u8]) -> Option<Vec<u8>> {
    if a.is_empty() {
        return None;
    }
    let mut no_canon = false;
    for &c in a {
        if valid_header_field_byte(c) {
            continue;
        }
        if c == b' ' {
            no_canon = true;
            continue;
        }
        return None;
    }
    if no_canon {
        return Some(a.to_vec());
    }
    let mut upper = true;
    Some(
        a.iter()
            .map(|&c| {
                let c = if upper {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                };
                upper = c == b'-';
                c
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a() -> Anonymizer {
        Anonymizer::new(&[0x5a; 32], "test-1").unwrap()
    }

    #[test]
    fn hmac_matches_rfc4231() {
        // RFC 4231 test case 2
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn mask_value_as_the_go_tests() {
        let a = a();
        let t = |s: &str| String::from_utf8(a.token(s.as_bytes())).unwrap();
        for (input, want) in [
            ("plain text 42", "plain text 42".to_string()),
            (
                "mail alice@example.test now",
                format!("mail {} now", t("alice@example.test")),
            ),
            ("call 0912345678", format!("call {}", t("0912345678"))),
            ("+84912345678", t("+84912345678")),
            ("id 001099012345.", format!("id {}.", t("001099012345"))),
            ("order 2026101400123", "order 2026101400123".to_string()),
            (
                "card 4111 1111 1111 1111 ok",
                format!("card {} ok", t("4111 1111 1111 1111")),
            ),
            (
                "card 4111111111111111",
                format!("card {}", t("4111111111111111")),
            ),
            ("ts 1760000000000", "ts 1760000000000".to_string()),
            (
                "0912345678 0987654321",
                format!("{} {}", t("0912345678"), t("0987654321")),
            ),
            ("x09123456789", "x09123456789".to_string()),
            (
                "' OR 1=1 -- 0912345678",
                format!("' OR 1=1 -- {}", t("0912345678")),
            ),
            (
                "Bearer eyJhbGciOi.eyJzdWIi.sig",
                format!("Bearer {}", t("eyJhbGciOi.eyJzdWIi.sig")),
            ),
        ] {
            assert_eq!(
                String::from_utf8(a.mask_value(input.as_bytes())).unwrap(),
                want,
                "{input}"
            );
        }
        for (v, c) in [
            ("123", ":d3"),
            ("abc", ":a3"),
            ("a1", ":x2"),
            ("a-1", ":s3"),
            ("", ":s0"),
        ] {
            assert!(t(v).ends_with(c), "{v}");
        }
    }

    /// #75: the policy's fields and patterns, in every place a name or a
    /// value goes; the same input without them keeps the values.
    #[test]
    fn policy_privacy_fields_and_patterns() {
        let mut a = a();
        let t = |a: &Anonymizer, s: &str| String::from_utf8(a.token(s.as_bytes())).unwrap();
        let req = Request {
            raw_uri: b"/v1/orders?Ma_Khach_Hang=C0012345&ref=KH12345678",
            args: b"Ma_Khach_Hang=C0012345&ref=KH12345678",
            headers: vec![
                (&b"X-Branch-Code"[..], &b"HN-042"[..]),
                (b"Content-Type", b"application/json"),
            ],
            body: br#"{"order":{"ma_khach_hang":"C0012345","note":"KH12345678 ok"}}"#,
            client: b"192.0.2.1",
            ..Default::default()
        };
        let plain = a.anonymize(&req);
        assert!(
            String::from_utf8_lossy(&plain.raw_uri).contains("C0012345")
                && String::from_utf8_lossy(&plain.body).contains("KH12345678")
                && String::from_utf8_lossy(&plain.headers).contains("HN-042")
        );
        let re = crate::privacy::compile_pattern("KH[0-9]{8}").unwrap();
        a.set_privacy(&["ma_khach_hang".into(), "x-branch-code".into()], &[re]);
        let r = a.anonymize(&req);
        let (c, k) = (t(&a, "C0012345"), t(&a, "KH12345678"));
        // tokens are query-escaped in the query
        let (qc, qk) = (c.replace(':', "%3A"), k.replace(':', "%3A"));
        assert_eq!(
            String::from_utf8(r.raw_uri).unwrap(),
            format!("/v1/orders?Ma_Khach_Hang={qc}&ref={qk}")
        );
        assert_eq!(
            String::from_utf8(r.args).unwrap(),
            format!("Ma_Khach_Hang={qc}&ref={qk}")
        );
        assert_eq!(
            String::from_utf8(r.body).unwrap(),
            format!(r#"{{"order":{{"ma_khach_hang":"{c}","note":"{k} ok"}}}}"#)
        );
        assert!(
            String::from_utf8_lossy(&r.headers).contains(&t(&a, "HN-042")),
            "{}",
            String::from_utf8_lossy(&r.headers)
        );
        // a form field and a multipart field with the name
        assert_eq!(
            a.body(
                b"application/x-www-form-urlencoded",
                b"ma_khach_hang=C0012345&x=1"
            ),
            format!("ma_khach_hang={qc}&x=1").into_bytes()
        );
        let mp = b"--b\r\nContent-Disposition: form-data; name=\"MA_KHACH_HANG\"\r\n\r\nC0012345\r\n--b--\r\n";
        let out = a.body(b"multipart/form-data; boundary=b", mp);
        assert!(
            !String::from_utf8_lossy(&out).contains("C0012345"),
            "{}",
            String::from_utf8_lossy(&out)
        );
    }

    #[test]
    fn json_depth_and_bad_json_pass_as_raw_text() {
        let a = a();
        let deep = "[".repeat(200) + &"]".repeat(200);
        assert_eq!(
            a.body(b"application/json", deep.as_bytes()),
            deep.as_bytes()
        );
        let ok = "[".repeat(65) + &"]".repeat(65);
        assert_eq!(a.json(ok.as_bytes()).unwrap(), ok.as_bytes());
        let over = "[".repeat(65) + "1" + &"]".repeat(65);
        assert!(a.json(over.as_bytes()).is_none());
        let broken = a.body(b"application/json", br#"{"email": "carol@example.test""#);
        assert!(!String::from_utf8_lossy(&broken).contains("carol@"));
        assert_eq!(
            a.json(br#" {"a" : [1, true, null, "x"], "b":{}} "#)
                .unwrap(),
            br#"{"a":[1,true,null,"x"],"b":{}}"#
        );
        for bad in [
            &b"01"[..],
            b"[1,]",
            b"{\"a\"}",
            b"\"\x01\"",
            b"1 2",
            b"",
            b"tru",
        ] {
            assert!(a.json(bad).is_none(), "{bad:?}");
        }
    }
}
