//! Bounded encoding and exact scope checks for policy exception artifacts.
//! Compiler and engine share this codec; section 10 and the mandatory policy
//! compatibility flag activate only configured exceptions.
#![forbid(unsafe_code)]

use crate::bundle::{Error, MAX_POLICIES};

pub const MAX_ENTRIES: usize = 4096;
pub const MAX_PER_POLICY: usize = 128;
const MAX_METHOD: usize = 32;
const MAX_HOST: usize = 253;
const MAX_PATH: usize = 2048;
const MAX_FIELD: usize = 160;
const MAGIC: &[u8; 4] = b"SEX1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exception {
    pub policy_index: u32,
    pub rule_id: u32,
    pub expires_unix_ms: u64,
    pub method: String,
    pub host: String,
    pub path: String,
    /// ARGS:<exact name> or REQUEST_HEADERS:<header name>.
    pub field: String,
}

fn bad() -> Error {
    Error::BadLayout("invalid policy exception section")
}

impl Exception {
    fn valid(&self, n_policies: u32) -> bool {
        let field = self.field.split_once(':').is_some_and(|(var, name)| {
            matches!(var, "ARGS" | "REQUEST_HEADERS")
                && !name.is_empty()
                && name.len() <= 128
                && !name.contains('*')
                && if var == "REQUEST_HEADERS" {
                    name.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'+-.^_`|~".contains(&b))
                } else {
                    name.chars()
                        .all(|ch| !ch.is_control() && !ch.is_whitespace())
                }
        });
        self.policy_index < n_policies
            && self.rule_id != 0
            && self.expires_unix_ms > 0
            && self.expires_unix_ms <= i64::MAX as u64
            && !self.method.is_empty()
            && self.method.len() <= MAX_METHOD
            && self
                .method
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b == b'-')
            && !self.host.is_empty()
            && self.host.len() <= MAX_HOST
            && self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
            && self.path.starts_with('/')
            && self.path.len() <= MAX_PATH
            && !self.path.contains(['?', '#', '\\', '*'])
            && self.path.bytes().all(|b| b >= 0x21 && b != 0x7f)
            && self.field.len() <= MAX_FIELD
            && field
    }

    /// Zero/unknown time never enables a bypass. Equality at expiry is expired.
    /// Caller supplies the canonical request path and the single Host value;
    /// duplicate/missing Host must not enable an exception.
    pub fn matches_scope(
        &self,
        policy: u32,
        method: &[u8],
        host: &[u8],
        path: &[u8],
        now_ms: u64,
    ) -> bool {
        now_ms > 0
            && now_ms < self.expires_unix_ms
            && self.policy_index == policy
            && self.method.as_bytes() == method
            && self.host.as_bytes().eq_ignore_ascii_case(host)
            && self.path.as_bytes() == path
    }

    /// Argument names remain case-sensitive; HTTP header names do not.
    /// No prefix, wildcard or implicit base64 alias matching.
    pub fn matches_field(&self, var: &str, name: &[u8]) -> bool {
        self.field.split_once(':').is_some_and(|(v, key)| {
            v == var
                && if v == "REQUEST_HEADERS" {
                    key.as_bytes().eq_ignore_ascii_case(name)
                } else {
                    key.as_bytes() == name
                }
        })
    }
}

fn validate(entries: &[Exception], n_policies: u32) -> Result<(), Error> {
    if n_policies > MAX_POLICIES || entries.len() > MAX_ENTRIES {
        return Err(bad());
    }
    let mut counts = vec![0usize; n_policies as usize];
    for entry in entries {
        if !entry.valid(n_policies) {
            return Err(bad());
        }
        counts[entry.policy_index as usize] += 1;
        if counts[entry.policy_index as usize] > MAX_PER_POLICY {
            return Err(bad());
        }
    }
    Ok(())
}

/// Empty exceptions produce no section and require no compatibility flag.
pub fn encode(entries: &[Exception], n_policies: u32) -> Result<Vec<u8>, Error> {
    validate(entries, n_policies)?;
    if entries.is_empty() {
        return Ok(vec![]);
    }
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.policy_index.to_le_bytes());
        out.extend_from_slice(&e.rule_id.to_le_bytes());
        out.extend_from_slice(&e.expires_unix_ms.to_le_bytes());
        for value in [&e.method, &e.host, &e.path, &e.field] {
            let len = u16::try_from(value.len()).map_err(|_| bad())?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(value.as_bytes());
        }
    }
    Ok(out)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or_else(bad)?;
        let result = self.bytes.get(self.at..end).ok_or_else(bad)?;
        self.at = end;
        Ok(result)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    fn string(&mut self, max: usize) -> Result<String, Error> {
        let b = self.take(2)?;
        let n = u16::from_le_bytes([b[0], b[1]]) as usize;
        if n > max {
            return Err(bad());
        }
        std::str::from_utf8(self.take(n)?)
            .map(str::to_owned)
            .map_err(|_| bad())
    }
}

/// The set of policies with entries must equal the set carrying the required
/// compatibility bit. Old engines must reject that bit, not ignore this section.
pub fn parse(bytes: &[u8], n_policies: u32, flagged: &[u32]) -> Result<Vec<Exception>, Error> {
    if n_policies > MAX_POLICIES || flagged.len() > n_policies as usize {
        return Err(bad());
    }
    let mut expected = vec![false; n_policies as usize];
    for &p in flagged {
        let slot = expected.get_mut(p as usize).ok_or_else(bad)?;
        if *slot {
            return Err(bad());
        }
        *slot = true;
    }
    if bytes.is_empty() {
        return if flagged.is_empty() {
            Ok(vec![])
        } else {
            Err(bad())
        };
    }
    let mut c = Cursor { bytes, at: 0 };
    if c.take(4)? != MAGIC {
        return Err(bad());
    }
    let n = c.u32()? as usize;
    if n == 0 || n > MAX_ENTRIES {
        return Err(bad());
    }
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        entries.push(Exception {
            policy_index: c.u32()?,
            rule_id: c.u32()?,
            expires_unix_ms: c.u64()?,
            method: c.string(MAX_METHOD)?,
            host: c.string(MAX_HOST)?,
            path: c.string(MAX_PATH)?,
            field: c.string(MAX_FIELD)?,
        });
    }
    if c.at != bytes.len() {
        return Err(bad());
    }
    validate(&entries, n_policies)?;
    let mut actual = vec![false; n_policies as usize];
    for e in &entries {
        actual[e.policy_index as usize] = true;
    }
    if actual != expected {
        return Err(bad());
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> Exception {
        Exception {
            policy_index: 0,
            rule_id: 942100,
            expires_unix_ms: 1000,
            method: "POST".into(),
            host: "api.example.test".into(),
            path: "/v1/login".into(),
            field: "ARGS:Name".into(),
        }
    }
    #[test]
    fn round_trip_and_every_truncation() {
        let e = example();
        let b = encode(std::slice::from_ref(&e), 1).unwrap();
        assert_eq!(parse(&b, 1, &[0]).unwrap(), vec![e]);
        for n in 0..b.len() {
            assert!(parse(&b[..n], 1, &[0]).is_err(), "prefix {n}");
        }
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(parse(&trailing, 1, &[0]).is_err());
        assert!(parse(&b, 1, &[]).is_err());
        assert!(parse(&b, 1, &[0, 0]).is_err());
        assert!(parse(&[], 1, &[0]).is_err());
        assert!(parse(&b, 0, &[]).is_err());
        assert!(parse(&b, u32::MAX, &[]).is_err());
        assert_eq!(encode(&[], 1).unwrap(), vec![]);
        assert!(parse(&[], 1, &[]).unwrap().is_empty());
    }
    #[test]
    fn hostile_sizes_and_invalid_scopes() {
        let mut e = example();
        assert!(encode(&vec![e.clone(); MAX_PER_POLICY + 1], 1).is_err());
        assert!(encode(&vec![e.clone(); MAX_ENTRIES + 1], 1).is_err());
        for field in [
            "*",
            "ARGS:*",
            "ARGS:",
            "REQUEST_BODY",
            "ARGS:a b",
            "UNKNOWN:Name",
        ] {
            e.field = field.into();
            assert!(encode(&[e.clone()], 1).is_err());
        }
        e = example();
        e.path = "/v1/*".into();
        assert!(encode(&[e.clone()], 1).is_err());
        e = example();
        e.expires_unix_ms = 0;
        assert!(encode(&[e], 1).is_err());
        let mut b = encode(&[example()], 1).unwrap();
        b[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&b, 1, &[0]).is_err());
    }
    #[test]
    fn scope_is_exact_and_expires_without_a_reload() {
        let e = example();
        assert!(e.matches_scope(0, b"POST", b"API.EXAMPLE.TEST", b"/v1/login", 999));
        for now in [0, 1000, u64::MAX] {
            assert!(!e.matches_scope(0, b"POST", b"api.example.test", b"/v1/login", now));
        }
        assert!(!e.matches_scope(1, b"POST", b"api.example.test", b"/v1/login", 999));
        assert!(!e.matches_scope(0, b"GET", b"api.example.test", b"/v1/login", 999));
        assert!(!e.matches_scope(0, b"POST", b"other.example.test", b"/v1/login", 999));
        assert!(!e.matches_scope(0, b"POST", b"api.example.test", b"/v1/Login", 999));
        assert!(!e.matches_scope(0, b"POST", b"api.example.test", b"/v1/login/extra", 999));
        assert!(e.matches_field("ARGS", b"Name"));
        assert!(!e.matches_field("ARGS", b"name"));
        assert!(!e.matches_field("ARGS", b"Name|base64"));
        let mut unicode = e.clone();
        unicode.field = "ARGS:tên".into();
        assert!(encode(&[unicode.clone()], 1).is_ok());
        assert!(unicode.matches_field("ARGS", "tên".as_bytes()));
        unicode.field = "ARGS:a\u{2003}b".into();
        assert!(encode(&[unicode], 1).is_err());
        let mut h = e;
        h.field = "REQUEST_HEADERS:X-Example-Filter".into();
        assert!(h.matches_field("REQUEST_HEADERS", b"x-example-filter"));
        assert!(!h.matches_field("ARGS", b"X-Example-Filter"));
    }
}
