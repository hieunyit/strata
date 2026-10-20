//! Rule evaluation v0 (W05-R-01): stages `request_headers` and
//! `request_body`.
//!
//! Targets: method, uri_raw, uri, path, args (query string and, for an
//! `application/x-www-form-urlencoded`, `multipart/form-data` or JSON body,
//! its fields: `json.a.0` for JSON), args_get (query), args_post (body
//! fields), args_names, files and files_names (uploads of a multipart
//! body), xml and xml_attributes (an XML body's text and attribute values),
//! body_processor (URLENCODED, MULTIPART, JSON, XML or empty, from the
//! Content-Type, also at stage request_headers), request_body (the raw body as
//! inspected), request_headers[_names], request_cookies[_names],
//! remote_addr, protocol, request_line, query_string (raw), and
//! matched_vars: the values (transformed) for which the previous condition
//! of an `all` rule held. At stage request_headers the body is empty.
//! JSON and XML bodies come later. Operators: the Hyperscan ones (rx, pm, contains,
//! begins_with, ends_with, streq) and the numeric ones (eq ... le, on a
//! value or on the count of values), and detect_sqli / detect_xss (the
//! libinjection port, on each transformed value). A rule using an operator or a
//! transformation this engine does not implement yet is skipped.
//!
//! Each distinct (value, transformation chain) is scanned once with the
//! bundle's Hyperscan database; the matches of every pattern-condition are
//! collected from that one scan. Values up to `BLOCK_SCAN_MAX` bytes go to
//! the block-mode copy of the database when the bundle has one (#27): a
//! block scan skips resetting a stream and flushing its end of data, which
//! cost more than the scan itself on short values. An rx pattern Hyperscan does not take
//! (CRS has a few too large for it) is left out of the database by the
//! compiler and runs with the `regex` crate instead, also in linear time
//! ([`Regexes`]).
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::collections::HashMap;

use strata_hs::MappedDb;

use crate::detectors::Violation;
use crate::detectors::injection::{cmdi, detect_sqli, detect_xss, ssti};
use crate::operators::{self, CompiledOperators};
use crate::rules::{
    BLOCK_SCAN_MAX, CondView, HS_OPERATORS, Hyperscan, RuleView, Tables, TargetView, VARS,
    ValueView, code,
};

/// The Hyperscan databases of a request: the condition index and the
/// stream (or block) database of HYPERSCAN, and the block copy of
/// HYPERSCAN_BLOCK when the bundle has it.
type HsDbs<'b> = (Hyperscan<'b>, MappedDb<'b>, Option<MappedDb<'b>>);

/// Set in the scratch ID of a HYPERSCAN_BLOCK database: it differs from the
/// ID of the stream database of the same engine, whose scratch it shares.
pub const BLOCK_DB_ID: u64 = 1 << 62;
use crate::transform;
use crate::{json, multipart, xml};

pub struct FallbackRegex {
    pub ci: u32,
    pattern: Vec<u8>,
    /// compiled on first use (W09-R-01): most of these are the secondary
    /// conditions of rules whose gate rarely holds, and each compiled
    /// regex costs memory in every worker
    compiled: std::sync::OnceLock<Option<(regex::bytes::Regex, regex_automata::hybrid::dfa::DFA)>>,
}

impl FallbackRegex {
    /// The regex and its lazy DFA; None if the pattern does not compile
    /// (the compiler checked it: a bundle signed for another build).
    pub fn compiled(&self) -> Option<(&regex::bytes::Regex, &regex_automata::hybrid::dfa::DFA)> {
        self.compiled_timed().0
    }

    /// `compiled`, and the time spent compiling when this call did it.
    #[allow(clippy::type_complexity)]
    pub fn compiled_timed(
        &self,
    ) -> (
        Option<(&regex::bytes::Regex, &regex_automata::hybrid::dfa::DFA)>,
        Option<std::time::Duration>,
    ) {
        let start = self.compiled.get().is_none().then(std::time::Instant::now);
        let c = self
            .compiled
            .get_or_init(|| {
                Some((
                    fallback_regex(&self.pattern).ok()?,
                    fallback_dfa(&self.pattern).ok()?,
                ))
            })
            .as_ref()
            .map(|(re, dfa)| (re, dfa));
        (c, start.map(|s| s.elapsed()))
    }
}

/// The rx patterns of a bundle that are not in its Hyperscan database, run
/// with the `regex` crate and lazy DFA; each is compiled on first use.
#[derive(Default)]
pub struct Regexes(Vec<FallbackRegex>);

/// Compiles an rx pattern for the lazy DFA with Hyperscan's meaning
/// (the database is built without HS_FLAG_UTF8): on bytes, classes and
/// case folding are ASCII, and `\x{bc}` is the byte 0xbc.
pub fn fallback_dfa(pattern: &[u8]) -> Result<regex_automata::hybrid::dfa::DFA, String> {
    let s = std::str::from_utf8(pattern).map_err(|_| "pattern is not UTF-8".to_string())?;
    let syntax = regex_automata::util::syntax::Config::new()
        .unicode(false)
        .utf8(false);
    regex_automata::hybrid::dfa::DFA::builder()
        .syntax(syntax)
        .build(&byte_escapes(s))
        .map_err(|e| e.to_string())
}

pub fn fallback_regex(pattern: &[u8]) -> Result<regex::bytes::Regex, String> {
    let s = std::str::from_utf8(pattern).map_err(|_| "pattern is not UTF-8".to_string())?;
    regex::bytes::RegexBuilder::new(&byte_escapes(s))
        .unicode(false)
        .size_limit(64 << 20)
        .dfa_size_limit(16 << 20)
        .build()
        .map_err(|e| e.to_string())
}

struct DfaCacheSlot {
    engine_id: u64,
    dfa_ptr: *const (),
    cache: regex_automata::hybrid::dfa::Cache,
}

thread_local! {
    static DFA_CACHE: std::cell::RefCell<Option<DfaCacheSlot>> = const { std::cell::RefCell::new(None) };
}

pub fn dfa_is_match_with_budget(
    engine_id: u64,
    dfa: &regex_automata::hybrid::dfa::DFA,
    re: &regex::bytes::Regex,
    haystack: &[u8],
    budget: &mut Option<&mut crate::budget::TxBudget>,
) -> Result<bool, crate::budget::BudgetExceeded> {
    if budget.is_none() || haystack.len() <= 8192 {
        return Ok(re.is_match(haystack));
    }
    let outcome = DFA_CACHE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let ptr = dfa as *const regex_automata::hybrid::dfa::DFA as *const ();
        if slot
            .as_ref()
            .is_none_or(|s| s.engine_id != engine_id || s.dfa_ptr != ptr)
        {
            *slot = Some(DfaCacheSlot {
                engine_id,
                dfa_ptr: ptr,
                cache: dfa.create_cache(),
            });
        }
        let cache = &mut slot.as_mut().unwrap().cache;
        let input = regex_automata::Input::new(haystack);
        let mut state = match dfa.start_state_forward(cache, &input) {
            Ok(s) => s,
            Err(_) => return None, // gave up: fallback to Regex::is_match
        };
        if state.is_match() {
            return Some(Ok(true));
        }

        let mut bytes_since_check = 0;
        for &b in haystack {
            bytes_since_check += 1;
            if bytes_since_check >= 4096 {
                bytes_since_check = 0;
                if let Some(bgt) = budget.as_mut() {
                    match bgt.check() {
                        Ok(()) => {}
                        Err(e) => return Some(Err(e)),
                    }
                }
            }
            state = match dfa.next_state(cache, state, b) {
                Ok(s) => s,
                Err(_) => return None, // gave up: fallback to Regex::is_match
            };
            if state.is_match() {
                return Some(Ok(true));
            }
        }
        state = match dfa.next_eoi_state(cache, state) {
            Ok(s) => s,
            Err(_) => return None, // gave up
        };
        Some(Ok(state.is_match()))
    });

    match outcome {
        Some(res) => res,
        None => Ok(re.is_match(haystack)),
    }
}

/// `\x{HH}` -> `\xHH` for values up to 0xff; other escapes as written.
pub fn byte_escapes(p: &str) -> String {
    let b = p.as_bytes();
    let mut out = String::with_capacity(p.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            let n = p[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&p[i..i + n]);
            i += n;
            continue;
        }
        if b[i + 1] == b'x'
            && b.get(i + 2) == Some(&b'{')
            && let Some(len) = b[i + 3..].iter().position(|&c| c == b'}')
            && let Ok(v @ 0..=0xff) = u32::from_str_radix(&p[i + 3..i + 3 + len], 16)
        {
            out.push_str(&format!("\\x{v:02x}"));
            i += 4 + len;
            continue;
        }
        // any other escape: the backslash and the character it escapes
        let n = p[i + 1..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&p[i..i + 1 + n]);
        i += 1 + n;
    }
    out
}

impl Regexes {
    /// The rx conditions of `tables` that no Hyperscan pattern stands for.
    pub fn build(tables: &Tables<'_>) -> Result<Regexes, String> {
        let rx = code(crate::rules::OPERATORS, "rx").unwrap_or(u8::MAX);
        let mut in_db = std::collections::HashSet::new();
        if let Some(hs) = tables.hyperscan() {
            for id in 0..hs.n_patterns() as u32 {
                in_db.extend(hs.condition(id));
            }
        }
        let mut out = vec![];
        for i in 0..tables.n_rules() {
            let Some(r) = tables.rule(i) else { continue };
            for ci in r.cond_first..r.cond_first + r.cond_count {
                let Some(c) = tables.cond(ci) else { continue };
                if let (true, ValueView::Str(p), false) = (c.op == rx, c.value, in_db.contains(&ci))
                {
                    // checked when compiled; a pattern that is not UTF-8
                    // never compiles: refuse the bundle now, as before
                    std::str::from_utf8(p)
                        .map_err(|_| format!("rule {}: pattern is not UTF-8", r.id))?;
                    out.push(FallbackRegex {
                        ci,
                        pattern: p.to_vec(),
                        compiled: std::sync::OnceLock::new(),
                    });
                }
            }
        }
        out.sort_by_key(|fb| fb.ci);
        Ok(Regexes(out))
    }

    pub fn get(&self, ci: u32) -> Option<&FallbackRegex> {
        self.0
            .binary_search_by_key(&ci, |fb| fb.ci)
            .ok()
            .map(|i| &self.0[i])
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Compiles every pattern now (instead of on first use); returns how
    /// many compiled.
    pub fn compile_all(&self) -> usize {
        self.0.iter().filter(|fb| fb.compiled().is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many are compiled already (for tests and reports).
    pub fn compiled_count(&self) -> usize {
        self.0
            .iter()
            .filter(|fb| fb.compiled.get().is_some())
            .count()
    }
}

/// Bounded work on hostile input.
const MAX_ARGS: usize = 1024;
const MAX_COOKIES: usize = 256;

/// Targets this evaluator reads; a rule on another target never matches.
pub const SUPPORTED_VARS: &[&str] = &[
    "method",
    "uri_raw",
    "uri",
    "path",
    "protocol",
    "remote_addr",
    "args",
    "args_get",
    "args_post",
    "args_names",
    "request_body",
    "request_headers",
    "request_headers_names",
    "request_cookies",
    "request_cookies_names",
    "files",
    "files_names",
    "matched_vars",
    "request_line",
    "query_string",
    "xml",
    "xml_attributes",
    "body_processor",
    "tls_ja4",
    "bot_claim",
    "bot_verified",
    "basename",
    "geo_country",
    "geo_asn",
    "multipart_part_headers",
];

/// Operators and transformations this evaluator runs; a rule using
/// another one is skipped (never matches). Tools use this list to tell a
/// rule the engine cannot run yet from a rule that fails its tests.
pub fn supported() -> (Vec<&'static str>, Vec<&'static str>) {
    let ops = crate::rules::OPERATORS
        .iter()
        .enumerate()
        .filter(|(i, name)| {
            HS_OPERATORS.contains(&(*i as u8))
                || matches!(
                    **name,
                    "eq" | "ne"
                        | "gt"
                        | "ge"
                        | "lt"
                        | "le"
                        | "detect_sqli"
                        | "detect_xss"
                        | "detect_ssti"
                        | "detect_cmdi"
                        | "validate_byte_range"
                        | "validate_url_encoding"
                        | "validate_utf8_encoding"
                        | "ip_match"
                )
        })
        .map(|(_, n)| *n)
        .collect();
    let transforms = crate::rules::TRANSFORMS
        .iter()
        .enumerate()
        .filter(|(i, _)| transform::is_implemented(*i as u8))
        .map(|(_, n)| *n)
        .collect();
    (ops, transforms)
}

/// What the connector passed for the request line and headers.
pub struct Request<'a> {
    pub method: &'a [u8],
    pub raw_uri: &'a [u8],
    pub uri: &'a [u8],
    pub args: &'a [u8],
    pub proto: &'a [u8],
    pub client_addr: &'a [u8],
    /// JA4 of the TLS connection (RV-N-02), empty without one
    pub ja4: &'a [u8],
    /// published crawler ranges of the bundle (W18-R-02)
    pub good_bots: &'a crate::goodbots::GoodBots,
    /// networks of the countries and ASNs rules name (W19-R-01)
    pub geo: &'a crate::geo::Geo,
    /// the policy-scoped rules of the policy, as (rule ID, mode) by
    /// increasing ID (W19-G2-01)
    pub scoped: &'a [(u32, crate::scope::Mode)],
    /// the policy's CRS paranoia levels (W17-S-01)
    pub paranoia: crate::paranoia::Levels,
    pub headers: &'a [(&'a [u8], &'a [u8])],
    /// The request body as inspected (empty at stage request_headers).
    pub body: &'a [u8],
    /// Arguments (query, then body fields) inspected: the policy's
    /// `max_args`; 0 or more than MAX_ARGS is MAX_ARGS (#28)
    pub max_args: usize,
    /// W13-R-02: for a sampled transaction, where the time of each rule
    /// visited (by index) and of the prefilter's scans (None) goes
    pub costs: Option<&'a crate::rulecost::Samples>,
}

/// The body processor for a Content-Type, named as ModSecurity's
/// REQBODY_PROCESSOR: URLENCODED, MULTIPART, JSON, XML, or empty (the body
/// is only `request_body`).
pub fn body_processor(ct: &[u8]) -> &'static [u8] {
    if xml::media_type(ct).eq_ignore_ascii_case(b"application/x-www-form-urlencoded") {
        b"URLENCODED"
    } else if json::is_json(ct) {
        b"JSON"
    } else if xml::is_xml(ct) {
        b"XML"
    } else if multipart::boundary(ct).is_some() {
        b"MULTIPART"
    } else {
        b""
    }
}

/// The request's Content-Type (empty without one).
pub(crate) fn content_type<'a>(headers: &[(&'a [u8], &'a [u8])]) -> &'a [u8] {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(b"content-type"))
        .map_or(&b""[..], |(_, v)| v)
}

/// Whether the request body is encoded so the engine cannot read it (#97):
/// a `Content-Encoding` header with any token other than `identity`. The
/// header may list several (`gzip, br`); any non-identity token counts.
fn content_encoding_opaque(headers: &[(&[u8], &[u8])]) -> bool {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(b"content-encoding"))
        .flat_map(|(_, v)| v.split(|&c| c == b','))
        .map(|t| {
            let t = t.strip_prefix(b" ").unwrap_or(t);
            t.strip_suffix(b" ").unwrap_or(t)
        })
        .any(|t| !t.is_empty() && !t.eq_ignore_ascii_case(b"identity"))
}

/// `application/x-www-form-urlencoded` decoding: %XX and '+'.
fn form_decode_with_budget<'a>(
    s: &'a [u8],
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Cow<'a, [u8]>, crate::budget::BudgetExceeded> {
    if memchr::memchr2(b'%', b'+', s).is_none() {
        if s.len() >= 8192
            && let Some(bgt) = budget.as_deref_mut()
        {
            bgt.check()?;
        }
        return Ok(Cow::Borrowed(s));
    }
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(s.len().min(65536));
    let mut i = 0;
    let mut next_check = 8192;
    while i < s.len() {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        match s[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < s.len() => match (hex(s[i + 1]), hex(s[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    Ok(Cow::Owned(out))
}

#[cfg(test)]
fn form_decode(s: &[u8]) -> Cow<'_, [u8]> {
    form_decode_with_budget(s, None).unwrap()
}

type Pair<'a> = (Cow<'a, [u8]>, Cow<'a, [u8]>);

/// The fields of `q`, at most `limit`, and whether some were left out.
fn parse_query_limit<'a>(
    q: &'a [u8],
    limit: usize,
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<(Vec<Pair<'a>>, bool), crate::budget::BudgetExceeded> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut next_check = 8192;
    while start < q.len() {
        if start >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = start + 8192;
        }
        let end = match memchr::memchr(b'&', &q[start..]) {
            Some(pos) => start + pos,
            None => q.len(),
        };
        let p = &q[start..end];
        start = end + 1;
        if p.is_empty() {
            continue;
        }
        if out.len() >= limit {
            return Ok((out, true));
        }
        let pair = match memchr::memchr(b'=', p) {
            Some(eq) => (
                form_decode_with_budget(&p[..eq], budget.as_deref_mut())?,
                form_decode_with_budget(&p[eq + 1..], budget.as_deref_mut())?,
            ),
            None => (
                form_decode_with_budget(p, budget.as_deref_mut())?,
                Cow::Borrowed(&p[..0]),
            ),
        };
        out.push(pair);
    }
    Ok((out, false))
}

#[cfg(test)]
fn parse_query(q: &[u8]) -> Vec<Pair<'_>> {
    parse_query_limit(q, MAX_ARGS, None).unwrap().0
}

fn pair<'p>((n, v): &'p Pair<'_>) -> (&'p [u8], &'p [u8]) {
    (n, v)
}

fn trim(v: &[u8]) -> &[u8] {
    let start = v
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|&c| c != b' ' && c != b'\t')
        .map_or(start, |e| e + 1);
    &v[start..end]
}

fn parse_cookies<'a>(headers: &[(&'a [u8], &'a [u8])]) -> Vec<Pair<'a>> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(b"cookie"))
        .flat_map(|(_, v)| v.split(|&c| c == b';'))
        .map(trim)
        .filter(|p| !p.is_empty())
        .take(MAX_COOKIES)
        .map(|p| match memchr::memchr(b'=', p) {
            Some(eq) => (Cow::Borrowed(&p[..eq]), Cow::Borrowed(&p[eq + 1..])),
            None => (Cow::Borrowed(p), Cow::Borrowed(&p[..0])),
        })
        .collect()
}

/// Request data prepared once per evaluation.
struct Data<'a> {
    req: &'a Request<'a>,
    full_uri: Cow<'a, [u8]>,
    /// how the body is parsed (ModSecurity's REQBODY_PROCESSOR)
    processor: &'static [u8],
    /// method, raw URI and protocol, as on the wire
    request_line: Vec<u8>,
    /// query fields, then body fields: args_get is args[..n_get]
    args: Vec<Pair<'a>>,
    n_get: usize,
    cookies: Vec<Pair<'a>>,
    /// uploaded files of a multipart body: (field name, file name)
    files: Vec<(&'a [u8], &'a [u8])>,
    /// header lines of the parts of a multipart body: (part name, line)
    part_headers: Vec<(&'a [u8], &'a [u8])>,
    /// an XML body
    xml: Option<xml::Xml>,
    /// decoded copies of the args that look base64-encoded (b64.rs), the
    /// query's first: args_get reads b64_args[..b64_get]
    b64_args: Vec<(Vec<u8>, Vec<u8>)>,
    b64_get: usize,
    /// decoded copies of the cookies that look base64-encoded
    b64_cookies: Vec<(Vec<u8>, Vec<u8>)>,
}

type ScanKey = (usize, usize, u128, u8);

#[inline(always)]
fn make_scan_key(v: &[u8], chain: &[u8]) -> ScanKey {
    let mut packed = 0u128;
    for &c in chain {
        packed = (packed << 8) | (c as u128);
    }
    (v.as_ptr() as usize, v.len(), packed, chain.len() as u8)
}

#[derive(Default)]
struct ScanKeyHasher(u64);

impl std::hash::Hasher for ScanKeyHasher {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(5) ^ (b as u64);
        }
    }
    #[inline(always)]
    fn write_usize(&mut self, i: usize) {
        self.0 = self.0.wrapping_mul(0x517cc1b727220a95) ^ (i as u64);
    }
    #[inline(always)]
    fn write_u128(&mut self, i: u128) {
        let lo = i as u64;
        let hi = (i >> 64) as u64;
        self.0 = self.0.wrapping_mul(0x517cc1b727220a95) ^ lo;
        self.0 = self.0.wrapping_mul(0x517cc1b727220a95) ^ hi;
    }
    #[inline(always)]
    fn write_u8(&mut self, i: u8) {
        self.0 = self.0.wrapping_mul(0x517cc1b727220a95) ^ (i as u64);
    }
}

type FastBuildHasher = std::hash::BuildHasherDefault<ScanKeyHasher>;

/// Hyperscan prefilter (W09-R-01). A condition is a *gate* when it holds
/// exactly when Hyperscan reports it on one of its values: an HS pattern
/// operator without a `regex`-crate fallback, not negated, on targets that
/// are neither counts nor `matched_vars`. Gates with the same targets, chain
/// and `multi_match` read the same values: they form a scan group, scanned
/// once per request, which gives every gate of the group that holds. A rule
/// whose conditions must all hold (`all`) cannot match when one of its gates
/// is missing; a rule with `any` whose conditions are all gates cannot match
/// when none is present. Such rules are skipped without visiting their
/// values; the result is the one of evaluating them.
#[derive(Debug, Default)]
pub struct Prefilter {
    /// per condition: its scan group, or NO_GROUP
    cond_group: Vec<u32>,
    /// per group: one of its conditions (they share targets and chain)
    group_rep: Vec<u32>,
    /// per rule: how it is gated
    rule_gate: Vec<Gate>,
    /// per condition: the rule it belongs to
    cond_rule: Vec<u32>,
    /// per stage code: the rules evaluated on every request (not gated),
    /// and the scan groups of the gates of its other rules
    stages: Vec<(Vec<u32>, Vec<u32>)>,
    /// #28: the transformation chains of the groups as a trie, node 0 the
    /// empty chain; a node's parent comes before it
    nodes: Vec<(u16, u8)>,
    /// chain -> its node
    chain_node: HashMap<Vec<u8>, u16>,
    /// per group: its target set, and the nodes it reads (its chain, and
    /// every shorter prefix with multi_match)
    group_tset: Vec<u32>,
    group_reads: Vec<Vec<u16>>,
    /// per target set: a condition with those targets, and the nodes its
    /// groups read
    tset_rep: Vec<u32>,
    tset_reads: Vec<Vec<u16>>,
    /// distinct targets (var, key, excludes) as a target table index, and
    /// per target set the ones it reads: values are listed once per target
    targets: Vec<u32>,
    tset_targets: Vec<Vec<u32>>,
    /// false when the trie does not fit node ids (u16): candidates then
    /// scans group by group, as before #28
    trie: bool,
}

const NO_GROUP: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
enum Gate {
    /// evaluated as before
    None,
    /// an `all` rule: skipped when this gate does not hold
    One(u32),
    /// an `any` rule of gates only: skipped when none holds
    AnyOf,
}

impl Prefilter {
    /// Groups the gates of `tables`; linear in the rule tables, once per load.
    pub fn build(tables: &Tables<'_>, regexes: &Regexes) -> Prefilter {
        let mut pf = Prefilter::default();
        // without a Hyperscan database no condition is a gate: every rule
        // is evaluated on every request
        let has_hs = tables.hyperscan().is_some();
        type TargetKey = (u8, Option<Vec<u8>>, Vec<Vec<u8>>);
        let mut groups: HashMap<(Vec<u8>, bool, Vec<TargetKey>), u32> = HashMap::new();
        let mut gate_of = |ci: u32| -> u32 {
            let Some(c) = tables.cond(ci) else {
                return NO_GROUP;
            };
            let gate = has_hs
                && HS_OPERATORS.contains(&c.op)
                && regexes.get(ci).is_none()
                && !c.negate
                && c.target_count > 0
                && c.transforms.iter().all(|&t| transform::is_implemented(t));
            if !gate {
                return NO_GROUP;
            }
            let mut targets = Vec::with_capacity(c.target_count as usize);
            for ti in c.target_first..c.target_first + c.target_count {
                let Some(t) = tables.target(ti) else {
                    return NO_GROUP;
                };
                if t.count || t.var == const { var("matched_vars") } {
                    return NO_GROUP;
                }
                let excludes = (t.exclude_first..t.exclude_first + t.exclude_count)
                    .filter_map(|i| tables.list(i))
                    .map(<[u8]>::to_vec)
                    .collect();
                targets.push((t.var, t.key.map(<[u8]>::to_vec), excludes));
            }
            let key = (c.transforms.to_vec(), c.multi_match, targets);
            let next = groups.len() as u32;
            let g = *groups.entry(key).or_insert(next);
            if g == next {
                pf.group_rep.push(ci);
            }
            g
        };
        let n_conds = (0..tables.n_rules())
            .filter_map(|i| tables.rule(i))
            .map(|r| r.cond_first + r.cond_count)
            .max()
            .unwrap_or(0);
        pf.cond_group = (0..n_conds).map(&mut gate_of).collect();
        pf.rule_gate = (0..tables.n_rules())
            .map(|i| {
                let Some(r) = tables.rule(i) else {
                    return Gate::None;
                };
                let conds = r.cond_first..r.cond_first + r.cond_count;
                let is_gate = |ci: u32| {
                    pf.cond_group
                        .get(ci as usize)
                        .is_some_and(|&g| g != NO_GROUP)
                };
                if r.cond_count == 0 {
                    Gate::None
                } else if r.any {
                    if conds.clone().all(is_gate) {
                        Gate::AnyOf
                    } else {
                        Gate::None
                    }
                } else {
                    conds
                        .clone()
                        .find(|&ci| is_gate(ci))
                        .map_or(Gate::None, Gate::One)
                }
            })
            .collect();
        pf.cond_rule = vec![u32::MAX; n_conds as usize];
        pf.stages = vec![(vec![], vec![]); crate::rules::STAGES.len()];
        for i in 0..tables.n_rules() {
            let Some(r) = tables.rule(i) else { continue };
            for ci in r.cond_first..r.cond_first + r.cond_count {
                pf.cond_rule[ci as usize] = i as u32;
            }
            let Some((ungated, groups)) = pf.stages.get_mut(r.stage as usize) else {
                continue;
            };
            match pf.rule_gate[i] {
                Gate::None => ungated.push(i as u32),
                Gate::One(ci) => groups.push(pf.cond_group[ci as usize]),
                Gate::AnyOf => groups.extend(
                    (r.cond_first..r.cond_first + r.cond_count)
                        .map(|ci| pf.cond_group[ci as usize]),
                ),
            }
        }
        for (_, groups) in &mut pf.stages {
            groups.sort_unstable();
            groups.dedup();
        }
        pf.build_trie(tables);
        pf.trie =
            pf.nodes.len() < u16::MAX as usize && pf.group_tset.iter().all(|&t| t != u32::MAX);
        pf
    }

    /// The chain trie and the target sets of the groups (#28).
    fn build_trie(&mut self, tables: &Tables<'_>) {
        self.nodes = vec![(u16::MAX, 0)];
        self.chain_node = HashMap::from([(vec![], 0)]);
        type TargetKey = (u8, Option<Vec<u8>>, Vec<Vec<u8>>);
        let mut tsets: HashMap<Vec<TargetKey>, u32> = HashMap::new();
        let mut targets: HashMap<TargetKey, u32> = HashMap::new();
        for &ci in &self.group_rep {
            let Some(c) = tables.cond(ci) else {
                self.group_tset.push(u32::MAX);
                self.group_reads.push(vec![]);
                continue;
            };
            let mut node = 0u16;
            let mut path = vec![0u16];
            if self.nodes.len() + c.transforms.len() >= u16::MAX as usize {
                self.group_tset.push(u32::MAX);
                self.group_reads.push(vec![]);
                continue;
            }
            for k in 1..=c.transforms.len() {
                let chain = c.transforms[..k].to_vec();
                node = match self.chain_node.get(&chain) {
                    Some(&n) => n,
                    None => {
                        let n = self.nodes.len() as u16;
                        self.nodes.push((node, c.transforms[k - 1]));
                        self.chain_node.insert(chain, n);
                        n
                    }
                };
                path.push(node);
            }
            let reads = if c.multi_match { path } else { vec![node] };
            let mut key: Vec<TargetKey> = vec![];
            let mut ids = vec![];
            for ti in c.target_first..c.target_first + c.target_count {
                let Some(t) = tables.target(ti) else { continue };
                let excludes = (t.exclude_first..t.exclude_first + t.exclude_count)
                    .filter_map(|i| tables.list(i))
                    .map(<[u8]>::to_vec)
                    .collect();
                let k: TargetKey = (t.var, t.key.map(<[u8]>::to_vec), excludes);
                let next = self.targets.len() as u32;
                let id = *targets.entry(k.clone()).or_insert(next);
                if id == next {
                    self.targets.push(ti);
                }
                ids.push(id);
                key.push(k);
            }
            let next = self.tset_rep.len() as u32;
            let ts = *tsets.entry(key).or_insert(next);
            if ts == next {
                self.tset_rep.push(ci);
                self.tset_reads.push(vec![]);
                self.tset_targets.push(ids);
            }
            let tr = &mut self.tset_reads[ts as usize];
            tr.extend_from_slice(&reads);
            tr.sort_unstable();
            tr.dedup();
            self.group_tset.push(ts);
            self.group_reads.push(reads);
        }
    }

    /// Why conditions are not gates, by operator, for the benchmark report.
    pub fn diagnose(tables: &Tables<'_>, regexes: &Regexes) -> Vec<(String, usize)> {
        let mut out: HashMap<String, usize> = HashMap::new();
        let n_conds = (0..tables.n_rules())
            .filter_map(|i| tables.rule(i))
            .map(|r| r.cond_first + r.cond_count)
            .max()
            .unwrap_or(0);
        for ci in 0..n_conds {
            let Some(c) = tables.cond(ci) else { continue };
            let op = crate::rules::OPERATORS
                .get(c.op as usize)
                .copied()
                .unwrap_or("?");
            let why = if !HS_OPERATORS.contains(&c.op) {
                "not an HS operator"
            } else if regexes.get(ci).is_some() {
                "regex fallback"
            } else if c.negate {
                "negated"
            } else if (c.target_first..c.target_first + c.target_count)
                .filter_map(|t| tables.target(t))
                .any(|t| t.count || t.var == const { var("matched_vars") })
            {
                "count or matched_vars"
            } else {
                "gate"
            };
            *out.entry(format!("{op}: {why}")).or_default() += 1;
        }
        let mut v: Vec<_> = out.into_iter().collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
        v
    }

    /// Conditions needed without a selective input gate. A method-only
    /// gate is common traffic too: GET must not compile its secondary
    /// regexes on the first request after a worker starts.
    pub fn startup_conditions<'t>(
        &'t self,
        tables: &'t Tables<'_>,
    ) -> impl Iterator<Item = u32> + 't {
        self.rule_gate
            .iter()
            .enumerate()
            .filter(|(_, gate)| match gate {
                Gate::None => true,
                Gate::One(ci) => tables.cond(*ci).is_some_and(|c| {
                    (c.target_first..c.target_first + c.target_count).all(|ti| {
                        tables
                            .target(ti)
                            .is_some_and(|t| t.var == const { var("method") })
                    })
                }),
                Gate::AnyOf => false,
            })
            .filter_map(|(ri, _)| tables.rule(ri))
            .flat_map(|r| r.cond_first..r.cond_first + r.cond_count)
    }

    /// Rules that may be skipped, and scan groups, for tests and reports.
    pub fn stats(&self) -> (usize, usize) {
        (
            self.rule_gate
                .iter()
                .filter(|g| !matches!(g, Gate::None))
                .count(),
            self.group_rep.len(),
        )
    }
}

/// The gates of scan group `g` that hold on this request (sorted).
fn group_hits<'c>(ctx: &'c mut Ctx<'_, '_, '_>, d: &Data<'_>, pf: &Prefilter, g: u32) -> &'c [u32] {
    let gi = g as usize;
    if ctx.groups[gi].is_none() {
        let mut hits = vec![];
        if let Some(c) = ctx.tables.cond(pf.group_rep[gi]) {
            let chains = if c.multi_match {
                0..=c.transforms.len()
            } else {
                c.transforms.len()..=c.transforms.len()
            };
            'targets: for ti in c.target_first..c.target_first + c.target_count {
                let Some(t) = ctx.tables.target(ti) else {
                    continue;
                };
                let tables = ctx.tables;
                let excluded = |name: &[u8]| {
                    (t.exclude_first..t.exclude_first + t.exclude_count)
                        .filter_map(|i| tables.list(i))
                        .any(|e| e.eq_ignore_ascii_case(name))
                };
                for v in &values(d, &t, &excluded) {
                    for k in chains.clone() {
                        if ctx.budget_exceeded {
                            break 'targets;
                        }
                        hits.extend_from_slice(matched(ctx, v.val, &c.transforms[..k]));
                    }
                }
            }
        }
        hits.sort_unstable();
        hits.dedup();
        ctx.groups[gi] = Some(hits);
    }
    ctx.groups[gi].as_deref().unwrap_or(&[])
}

/// #28: the prefilter's scans of this request, value by value. Each value
/// that a scan group reads is transformed once per node of the chain trie
/// its groups need (a node from its parent's bytes, not the whole chain
/// again), and scanned once per distinct bytes: a transformation that
/// leaves the bytes as they are gives the parent's result without a scan.
/// The results are kept in flat arrays, so the groups, and the rules
/// evaluated afterwards (`matched`), read them without hashing or copies.
#[derive(Default)]
struct Pass<'t> {
    pf: Option<&'t Prefilter>,
    /// value (address, length) -> its index
    index: HashMap<(usize, usize), u32, FastBuildHasher>,
    /// per value x node: index into `ranges`, or NOT_SCANNED
    slot: Vec<u32>,
    /// conditions matched, as ranges of `hits`
    ranges: Vec<(u32, u32)>,
    hits: Vec<u32>,
}

const NOT_SCANNED: u32 = u32::MAX;

impl Pass<'_> {
    /// The conditions the prefilter found on `v` with `chain`, when it
    /// scanned that pair.
    fn get(&self, v: &[u8], chain: &[u8]) -> Option<&[u32]> {
        let pf = self.pf?;
        let &node = pf.chain_node.get(chain)?;
        let &vi = self.index.get(&(v.as_ptr() as usize, v.len()))?;
        let r = *self
            .slot
            .get(vi as usize * pf.nodes.len() + node as usize)?;
        if r == NOT_SCANNED {
            return None;
        }
        let (a, b) = self.ranges[r as usize];
        Some(&self.hits[a as usize..b as usize])
    }
}

/// The bytes of a trie node for one value: the value itself, the bytes of
/// another node (unchanged by the transformation), owned bytes, or none (a
/// transformation not implemented: nothing below it matches).
#[derive(Clone, Copy)]
enum NodeBytes {
    Value,
    Buf(u32),
    Missing,
}

/// Scans the values of the target sets of `groups` (see `Pass`) and fills
/// `ctx.groups` for them.
fn scan_values<'t>(ctx: &mut Ctx<'t, '_, '_>, d: &Data<'_>, pf: &'t Prefilter, groups: &[u32]) {
    let n_nodes = pf.nodes.len();
    ctx.pass.pf = Some(pf);
    // the values of each target set, by index
    let mut tsets: Vec<u32> = groups.iter().map(|&g| pf.group_tset[g as usize]).collect();
    tsets.sort_unstable();
    tsets.dedup();
    let mut vals: Vec<&[u8]> = vec![];
    // Repeated JSON values can share transformations as well as scans.
    // Keep every address in Pass for later field-specific evaluation. Other
    // workloads keep the address-only path: hashing unique values adds work.
    let mut by_bytes: Option<HashMap<&[u8], u32>> = (d.processor == b"JSON"
        && !d.req.body.is_empty())
    .then(|| HashMap::with_hasher(ctx.operators.content_hasher.clone()));
    // the values of each target the sets read, as value indexes
    let mut target_vals: Vec<Option<Vec<u32>>> = vec![None; pf.targets.len()];
    let mut tset_vals: Vec<(u32, Vec<u32>)> = Vec::with_capacity(tsets.len());
    let mut need: Vec<bool> = vec![];
    for &ts in &tsets {
        let mut idxs = vec![];
        for &tid in &pf.tset_targets[ts as usize] {
            if target_vals[tid as usize].is_none() {
                let mut list = vec![];
                if let Some(t) = ctx.tables.target(pf.targets[tid as usize]) {
                    let tables = ctx.tables;
                    let excluded = |name: &[u8]| {
                        (t.exclude_first..t.exclude_first + t.exclude_count)
                            .filter_map(|i| tables.list(i))
                            .any(|e| e.eq_ignore_ascii_case(name))
                    };
                    for v in &values(d, &t, &excluded) {
                        let next = vals.len() as u32;
                        let vi = *ctx
                            .pass
                            .index
                            .entry((v.val.as_ptr() as usize, v.val.len()))
                            .or_insert_with(|| {
                                by_bytes
                                    .as_mut()
                                    .map_or(next, |cache| *cache.entry(v.val).or_insert(next))
                            });
                        if vi == next {
                            vals.push(v.val);
                            need.resize(need.len() + n_nodes, false);
                        }
                        list.push(vi);
                    }
                }
                target_vals[tid as usize] = Some(list);
            }
            let list = target_vals[tid as usize].as_deref().unwrap_or(&[]);
            for &vi in list {
                let base = vi as usize * n_nodes;
                for &n in &pf.tset_reads[ts as usize] {
                    need[base + n as usize] = true;
                }
            }
            idxs.extend_from_slice(list);
        }
        tset_vals.push((ts, idxs));
    }
    drop(by_bytes);
    ctx.pass.slot = vec![NOT_SCANNED; vals.len() * n_nodes];

    // value by value, node by node (a parent before its children)
    let mut bytes = vec![NodeBytes::Missing; n_nodes];
    let mut bufs: Vec<Vec<u8>> = vec![];
    let mut wanted = vec![false; n_nodes];
    let mut reads = vec![false; n_nodes];
    // per node: the node whose result it shares (same bytes)
    let mut same = vec![0u16; n_nodes];
    // (bytes, transformation) -> the node that applied it: a node whose
    // parent has the bytes of another node takes that node's child's bytes
    // instead of transforming again ("url_decode, lowercase" on a value
    // without '%' is "lowercase")
    let mut memo: Vec<(u16, u8, u16)> = Vec::with_capacity(n_nodes);
    'vals: for (vi, &v) in vals.iter().enumerate() {
        if let Some(bgt) = ctx.budget.as_mut()
            && bgt.check_cheap().is_err()
        {
            ctx.budget_exceeded = true;
            break 'vals;
        }
        let base = vi * n_nodes;
        // the nodes to scan, and their ancestors to transform
        wanted.copy_from_slice(&need[base..base + n_nodes]);
        reads.copy_from_slice(&need[base..base + n_nodes]);
        for n in (1..n_nodes).rev() {
            if wanted[n] {
                wanted[pf.nodes[n].0 as usize] = true;
            }
        }
        bufs.clear();
        memo.clear();
        for n in 0..n_nodes {
            if !wanted[n] {
                continue;
            }
            let (parent, code) = pf.nodes[n];
            let b = if n == 0 {
                same[0] = 0;
                NodeBytes::Value
            } else if let Some(&(_, _, m)) = memo
                .iter()
                .find(|&&(sp, c, _)| sp == same[parent as usize] && c == code)
            {
                same[n] = same[m as usize];
                bytes[m as usize]
            } else {
                memo.push((same[parent as usize], code, n as u16));
                let p = parent as usize;
                let src: &[u8] = match bytes[p] {
                    NodeBytes::Value => v,
                    NodeBytes::Buf(i) => &bufs[i as usize],
                    NodeBytes::Missing => {
                        bytes[n] = NodeBytes::Missing;
                        same[n] = n as u16;
                        continue;
                    }
                };
                match transform::apply_with_budget(code, src, ctx.budget.as_deref_mut()) {
                    Err(crate::budget::BudgetExceeded) => {
                        ctx.budget_exceeded = true;
                        break 'vals;
                    }
                    Ok(None) => {
                        same[n] = n as u16;
                        NodeBytes::Missing
                    }
                    Ok(Some(out)) => {
                        if *out == *src {
                            same[n] = same[p];
                            bytes[p]
                        } else {
                            let o = out.into_owned();
                            same[n] = n as u16;
                            bufs.push(o);
                            NodeBytes::Buf(bufs.len() as u32 - 1)
                        }
                    }
                }
            };
            bytes[n] = b;
            if !reads[n] {
                continue;
            }
            // same bytes as a node already scanned: its result
            let s = same[n] as usize;
            if s != n && ctx.pass.slot[base + s] != NOT_SCANNED {
                ctx.pass.slot[base + n] = ctx.pass.slot[base + s];
                continue;
            }
            let found = match b {
                NodeBytes::Missing => vec![],
                NodeBytes::Value => scan_bytes(ctx, v),
                NodeBytes::Buf(i) => {
                    let o = std::mem::take(&mut bufs[i as usize]);
                    let h = scan_bytes(ctx, &o);
                    bufs[i as usize] = o;
                    h
                }
            };
            if ctx.budget_exceeded {
                break 'vals;
            }
            let a = ctx.pass.hits.len() as u32;
            ctx.pass.hits.extend_from_slice(&found);
            ctx.pass.ranges.push((a, ctx.pass.hits.len() as u32));
            let r = ctx.pass.ranges.len() as u32 - 1;
            ctx.pass.slot[base + n] = r;
            if s != n {
                ctx.pass.slot[base + s] = r;
            }
        }
    }
    if ctx.budget_exceeded {
        return;
    }

    // the gates of each group: what its values gave on its nodes
    for &g in groups {
        let gi = g as usize;
        let ts = pf.group_tset[gi];
        let Some((_, idxs)) = tset_vals.iter().find(|(t, _)| *t == ts) else {
            continue;
        };
        let mut hits = vec![];
        // many values give the same conditions (a pattern on a word every
        // field name holds): append a list once, not once per value
        let mut last: &[u32] = &[];
        for &vi in idxs {
            let base = vi as usize * n_nodes;
            for &n in &pf.group_reads[gi] {
                let r = ctx.pass.slot[base + n as usize];
                if r != NOT_SCANNED {
                    let (a, b) = ctx.pass.ranges[r as usize];
                    let h = &ctx.pass.hits[a as usize..b as usize];
                    if !h.is_empty() && h != last {
                        hits.extend_from_slice(h);
                        last = h;
                    }
                }
            }
        }
        if hits.len() > 1 {
            hits.sort_unstable();
            hits.dedup();
        }
        ctx.groups[gi] = Some(hits);
    }
}

/// Conditions matched by `b`, shared between equal bytes of the request.
fn scan_bytes(ctx: &mut Ctx<'_, '_, '_>, b: &[u8]) -> Vec<u32> {
    if let Some(h) = ctx.scans_by_bytes.get(b) {
        return h.clone();
    }
    let h = scan(
        &ctx.hs,
        &mut ctx.budget,
        &mut ctx.budget_exceeded,
        &Some(Cow::Borrowed(b)),
    );
    if !ctx.budget_exceeded {
        ctx.scans_by_bytes.insert(b.into(), h.clone());
    }
    h
}

/// The rules of `stage` that may match this request, in rule order: those
/// not gated, and those whose gate (one of them for `any`) holds. Every
/// other rule of the stage cannot match (see `Prefilter`).
fn candidates<'t>(
    ctx: &mut Ctx<'t, '_, '_>,
    d: &Data<'_>,
    pf: &'t Prefilter,
    stage: u8,
) -> Vec<u32> {
    let Some((ungated, groups)) = pf.stages.get(stage as usize) else {
        return vec![];
    };
    let mut out = ungated.clone();
    if pf.trie {
        scan_values(ctx, d, pf, groups);
        if ctx.budget_exceeded {
            return out;
        }
    }
    for &g in groups {
        for &ci in group_hits(ctx, d, pf, g) {
            if pf.cond_group.get(ci as usize) != Some(&g) {
                continue; // a pattern of another group, scanned on the same bytes
            }
            let Some(&ri) = pf.cond_rule.get(ci as usize) else {
                continue;
            };
            match pf.rule_gate.get(ri as usize) {
                Some(Gate::One(gate)) if *gate == ci => out.push(ri),
                Some(Gate::AnyOf) => out.push(ri),
                _ => {}
            }
        }
        if ctx.budget_exceeded {
            break;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// False when the prefilter proves rule `i` cannot match.
fn may_match(
    ctx: &mut Ctx<'_, '_, '_>,
    d: &Data<'_>,
    pf: &Prefilter,
    i: usize,
    r: &RuleView<'_>,
) -> bool {
    let holds = |ctx: &mut Ctx<'_, '_, '_>, ci: u32| {
        let g = pf.cond_group[ci as usize];
        group_hits(ctx, d, pf, g).binary_search(&ci).is_ok()
    };
    match pf.rule_gate.get(i) {
        Some(Gate::One(ci)) => holds(ctx, *ci),
        Some(Gate::AnyOf) => (r.cond_first..r.cond_first + r.cond_count).any(|ci| holds(ctx, ci)),
        _ => true,
    }
}

// Raw request bytes are hostile keys. Keep the keyed standard hasher here;
// FastBuildHasher is reserved for internally generated pointer/index keys.
type ContentScans = HashMap<Box<[u8]>, Vec<u32>>;

struct Ctx<'t, 'b, 'a> {
    engine_id: u64,
    tables: &'t Tables<'b>,
    regexes: &'t Regexes,
    operators: &'t CompiledOperators,
    hs: Option<HsDbs<'b>>,
    /// (value address, length, chain, chain_len) -> conditions matched by the scan
    scans: HashMap<ScanKey, Vec<u32>, FastBuildHasher>,
    /// transformed values (owned) -> conditions matched by the scan
    scans_by_bytes: ContentScans,
    active_exceptions: Vec<&'t crate::exceptions::Exception>,
    /// removals of the exclusion rules matched so far (W17-S-01)
    removals: Vec<&'t crate::rule_exclusions::Removal>,
    /// per scan group of the prefilter: the gates that hold, once computed
    groups: Vec<Option<Vec<u32>>>,
    /// #28: what the prefilter scanned, value by value
    pass: Pass<'t>,
    budget: Option<&'a mut crate::budget::TxBudget>,
    budget_exceeded: bool,
}

/// Code of a target variable; constant-folded for literal names (the hot
/// loops ask for `matched_vars` on every condition).
#[inline(always)]
const fn var(name: &str) -> u8 {
    let mut i = 0;
    while i < VARS.len() {
        if const_eq(VARS[i].as_bytes(), name.as_bytes()) {
            return i as u8;
        }
        i += 1;
    }
    u8::MAX
}

const fn const_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[derive(Clone, Copy)]
pub struct TargetVal<'d> {
    pub name: Option<&'d [u8]>,
    pub val: &'d [u8],
}

pub enum TargetVals<'d> {
    Empty,
    One(TargetVal<'d>),
    Many(Vec<TargetVal<'d>>),
}

impl<'d> TargetVals<'d> {
    #[inline(always)]
    pub fn len(&self) -> usize {
        match self {
            TargetVals::Empty => 0,
            TargetVals::One(_) => 1,
            TargetVals::Many(v) => v.len(),
        }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub enum TargetValsIter<'a, 'd> {
    Empty,
    One(Option<TargetVal<'d>>),
    Many(std::slice::Iter<'a, TargetVal<'d>>),
}

impl<'a, 'd> Iterator for TargetValsIter<'a, 'd> {
    type Item = TargetVal<'d>;
    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            TargetValsIter::Empty => None,
            TargetValsIter::One(opt) => opt.take(),
            TargetValsIter::Many(iter) => iter.next().copied(),
        }
    }
}

impl<'a, 'd> IntoIterator for &'a TargetVals<'d> {
    type Item = TargetVal<'d>;
    type IntoIter = TargetValsIter<'a, 'd>;
    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        match self {
            TargetVals::Empty => TargetValsIter::Empty,
            TargetVals::One(val) => TargetValsIter::One(Some(*val)),
            TargetVals::Many(vec) => TargetValsIter::Many(vec.iter()),
        }
    }
}

/// Values of one target (key and exclude filters applied).
fn values<'d>(
    d: &'d Data<'d>,
    t: &TargetView<'_>,
    excluded: &dyn Fn(&[u8]) -> bool,
) -> TargetVals<'d> {
    let r = d.req;
    // a decoded value is keyed and excluded under the name it came with
    let keyed = |name: &[u8]| {
        let name = crate::b64::base_name(name);
        t.key.is_none_or(|k| k.eq_ignore_ascii_case(name)) && !excluded(name)
    };
    let v = t.var;
    if v == const { var("method") } {
        TargetVals::One(TargetVal {
            name: None,
            val: r.method,
        })
    } else if v == const { var("uri_raw") } {
        TargetVals::One(TargetVal {
            name: None,
            val: r.raw_uri,
        })
    } else if v == const { var("uri") } {
        TargetVals::One(TargetVal {
            name: None,
            val: &d.full_uri,
        })
    } else if v == const { var("path") } {
        TargetVals::One(TargetVal {
            name: None,
            val: r.uri,
        })
    } else if v == const { var("basename") } {
        // REQUEST_BASENAME: the file name part of the path
        let p = r.uri;
        TargetVals::One(TargetVal {
            name: None,
            val: &p[p.iter().rposition(|&c| c == b'/').map_or(0, |i| i + 1)..],
        })
    } else if v == const { var("protocol") } {
        TargetVals::One(TargetVal {
            name: None,
            val: r.proto,
        })
    } else if v == const { var("request_line") } {
        TargetVals::One(TargetVal {
            name: None,
            val: &d.request_line,
        })
    } else if v == const { var("query_string") } {
        if r.args.is_empty() {
            TargetVals::Empty
        } else {
            TargetVals::One(TargetVal {
                name: None,
                val: r.args,
            })
        }
    } else if v == const { var("remote_addr") } {
        TargetVals::One(TargetVal {
            name: None,
            val: r.client_addr,
        })
    } else if v == const { var("bot_claim") } || v == const { var("bot_verified") } {
        // the first User-Agent header, as the event's context takes it
        let ua = r
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(b"user-agent"))
            .map(|(_, v)| *v)
            .unwrap_or_default();
        match crate::goodbots::verify(r.good_bots, ua, r.client_addr) {
            Some((name, verified)) => TargetVals::One(TargetVal {
                name: None,
                val: if v == const { var("bot_claim") } {
                    name.as_bytes()
                } else {
                    verified
                },
            }),
            None => TargetVals::Empty,
        }
    } else if v == const { var("geo_country") } || v == const { var("geo_asn") } {
        let kind = if v == const { var("geo_country") } {
            crate::geo::Kind::Country
        } else {
            crate::geo::Kind::Asn
        };
        match r.geo.lookup(kind, r.client_addr) {
            Some(val) => TargetVals::One(TargetVal { name: None, val }),
            None => TargetVals::Empty,
        }
    } else if v == const { var("tls_ja4") } {
        if r.ja4.is_empty() {
            TargetVals::Empty
        } else {
            TargetVals::One(TargetVal {
                name: None,
                val: r.ja4,
            })
        }
    } else if v == const { var("args") }
        || v == const { var("args_get") }
        || v == const { var("args_post") }
    {
        let (fields, decoded) = if v == const { var("args_get") } {
            (&d.args[..d.n_get], &d.b64_args[..d.b64_get])
        } else if v == const { var("args_post") } {
            (&d.args[d.n_get..], &d.b64_args[d.b64_get..])
        } else {
            (&d.args[..], &d.b64_args[..])
        };
        TargetVals::Many(
            fields
                .iter()
                .map(|(n, val)| (&**n, &**val))
                .chain(decoded.iter().map(|(n, val)| (&n[..], &val[..])))
                .filter(|(n, _)| keyed(n))
                .map(|(n, val)| TargetVal { name: Some(n), val })
                .collect(),
        )
    } else if v == const { var("request_body") } {
        if r.body.is_empty() {
            TargetVals::Empty
        } else {
            TargetVals::One(TargetVal {
                name: None,
                val: r.body,
            })
        }
    } else if v == const { var("args_names") } {
        TargetVals::Many(
            d.args
                .iter()
                .filter(|(n, _)| keyed(n))
                .map(|(n, _)| TargetVal { name: None, val: n })
                .collect(),
        )
    } else if v == const { var("request_headers") } {
        TargetVals::Many(
            r.headers
                .iter()
                .filter(|(n, _)| keyed(n))
                .map(|(n, val)| TargetVal {
                    name: Some(*n),
                    val,
                })
                .collect(),
        )
    } else if v == const { var("request_headers_names") } {
        TargetVals::Many(
            r.headers
                .iter()
                .filter(|(n, _)| keyed(n))
                .map(|(n, _)| TargetVal { name: None, val: n })
                .collect(),
        )
    } else if v == const { var("request_cookies") } {
        TargetVals::Many(
            d.cookies
                .iter()
                .map(|(n, val)| (&**n, &**val))
                .chain(d.b64_cookies.iter().map(|(n, val)| (&n[..], &val[..])))
                .filter(|(n, _)| keyed(n))
                .map(|(n, val)| TargetVal { name: Some(n), val })
                .collect(),
        )
    } else if v == const { var("request_cookies_names") } {
        TargetVals::Many(
            d.cookies
                .iter()
                .filter(|(n, _)| keyed(n))
                .map(|(n, _)| TargetVal { name: None, val: n })
                .collect(),
        )
    } else if v == const { var("body_processor") } {
        TargetVals::One(TargetVal {
            name: None,
            val: d.processor,
        })
    } else if v == const { var("xml") } {
        TargetVals::Many(
            d.xml
                .iter()
                .map(|x| TargetVal {
                    name: None,
                    val: &x.text[..],
                })
                .collect(),
        )
    } else if v == const { var("xml_attributes") } {
        TargetVals::Many(
            d.xml
                .iter()
                .flat_map(|x| x.attrs.iter())
                .map(|a| TargetVal {
                    name: None,
                    val: &a[..],
                })
                .collect(),
        )
    } else if v == const { var("files") } {
        TargetVals::Many(
            d.files
                .iter()
                .filter(|(n, _)| keyed(n))
                .map(|(n, f)| TargetVal {
                    name: Some(*n),
                    val: f,
                })
                .collect(),
        )
    } else if v == const { var("multipart_part_headers") } {
        TargetVals::Many(
            d.part_headers
                .iter()
                .filter(|(n, _)| keyed(n))
                .map(|(n, h)| TargetVal {
                    name: Some(*n),
                    val: h,
                })
                .collect(),
        )
    } else if v == const { var("files_names") } {
        TargetVals::Many(
            d.files
                .iter()
                .filter(|(n, _)| keyed(n))
                .map(|(n, _)| TargetVal { name: None, val: n })
                .collect(),
        )
    } else {
        TargetVals::Empty
    }
}

#[derive(Clone, Debug, Default)]
pub struct MatchDetail {
    pub field: String,
    pub snippet: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum Candidate {
    Value {
        var: u8,
        name: Option<Vec<u8>>,
        window: Vec<u8>,
    },
    Count {
        var: u8,
        count: usize,
    },
}

impl Candidate {
    pub fn is_boilerplate(&self) -> bool {
        match self {
            Candidate::Value { var, .. } | Candidate::Count { var, .. } => {
                let name = crate::rules::var_to_field_name(*var);
                name == "REQUEST_METHOD" || name == "REQUEST_PROTOCOL"
            }
        }
    }

    pub fn to_match_detail(&self) -> MatchDetail {
        match self {
            Candidate::Value { var, name, window } => {
                let base = crate::rules::var_to_field_name(*var);
                let field = match name {
                    Some(n) => format!("{}:{}", base, String::from_utf8_lossy(n)),
                    None => base.to_string(),
                };
                MatchDetail {
                    field,
                    snippet: window.clone(),
                }
            }
            Candidate::Count { var, count } => {
                let field = crate::rules::var_to_field_name(*var).to_string();
                MatchDetail {
                    field,
                    snippet: count.to_string().into_bytes(),
                }
            }
        }
    }
}

enum Outcome {
    Match(bool, Option<Candidate>),
    Unsupported,
}

fn compare(op: &str, x: i64, y: i64) -> bool {
    match op {
        "eq" => x == y,
        "ne" => x != y,
        "gt" => x > y,
        "ge" => x >= y,
        "lt" => x < y,
        _ => x <= y,
    }
}

/// Values for which a condition held, after its transformations: the
/// `matched_vars` of the next condition (ModSecurity's MATCHED_VARS).
type Matched = Vec<Vec<u8>>;

/// Evaluates condition `ci`. `prev` holds the values the previous
/// condition of the rule matched; with `collect`, every value this one
/// matches is kept there (else evaluation stops at the first).
fn condition(
    ctx: &mut Ctx<'_, '_, '_>,
    d: &Data<'_>,
    ci: u32,
    rule_id: u32,
    c: &CondView<'_>,
    prev: &Matched,
    mut collect: Option<&mut Matched>,
) -> Outcome {
    if ctx.budget_exceeded {
        return Outcome::Match(false, None);
    }
    let op = crate::rules::OPERATORS
        .get(c.op as usize)
        .copied()
        .unwrap_or("");
    let numeric = matches!(op, "eq" | "ne" | "gt" | "ge" | "lt" | "le");
    let pattern = HS_OPERATORS.contains(&c.op);
    let detect = matches!(
        op,
        "detect_sqli" | "detect_xss" | "detect_ssti" | "detect_cmdi"
    );
    let operator_v2 = matches!(
        op,
        "validate_byte_range" | "validate_url_encoding" | "validate_utf8_encoding" | "ip_match"
    );
    if !(numeric || pattern || detect || operator_v2)
        || !c.transforms.iter().all(|&t| transform::is_implemented(t))
    {
        return Outcome::Unsupported;
    }
    let regexes = ctx.regexes;
    let fallback = regexes.get(ci);
    if pattern && fallback.is_none() && ctx.hs.is_none() {
        return Outcome::Unsupported;
    }
    let y = match (numeric, c.value) {
        (false, _) => 0,
        (true, ValueView::Int(y)) => y,
        (true, _) => return Outcome::Unsupported,
    };

    // As in ModSecurity: the operator, negated or not, is applied to each
    // value, and the condition holds when it holds for one of them; a
    // target without values never matches, negated or not.
    let neg = c.negate;
    let mut any = false;
    let mut match_candidate: Option<Candidate> = None;

    for ti in c.target_first..c.target_first + c.target_count {
        if ctx.budget_exceeded {
            break;
        }
        let Some(t) = ctx.tables.target(ti) else {
            return Outcome::Unsupported;
        };
        let excluded = |name: &[u8]| {
            (t.exclude_first..t.exclude_first + t.exclude_count)
                .filter_map(|i| ctx.tables.list(i))
                .any(|e| e.eq_ignore_ascii_case(name))
        };
        // values of matched_vars are owned by the previous condition: their
        // addresses are not stable keys for the scan cache
        let from_prev = t.var == const { var("matched_vars") };
        let mut vals = if from_prev {
            TargetVals::Many(
                prev.iter()
                    .map(|v| TargetVal {
                        name: None,
                        val: &v[..],
                    })
                    .collect(),
            )
        } else {
            values(d, &t, &excluded)
        };
        let namespace =
            if t.var == var("args") || t.var == var("args_get") || t.var == var("args_post") {
                "ARGS"
            } else if t.var == var("request_headers") {
                "REQUEST_HEADERS"
            } else {
                ""
            };
        // W17-S-01: values an exclusion rule took away from this rule
        if !from_prev
            && ctx
                .removals
                .iter()
                .any(|x| x.var == t.var && x.covers(rule_id))
        {
            let removed = |v: &TargetVal<'_>| {
                ctx.removals
                    .iter()
                    .any(|x| x.removes_value(rule_id, t.var, v.name))
            };
            match vals {
                TargetVals::One(ref v) if removed(v) => vals = TargetVals::Empty,
                TargetVals::Many(ref mut values) => values.retain(|v| !removed(v)),
                _ => {}
            }
        }
        if !namespace.is_empty()
            && ctx.active_exceptions.iter().any(|e| e.rule_id == rule_id)
            && let TargetVals::Many(ref mut values) = vals
        {
            values.retain(|value| {
                if ctx.budget_exceeded {
                    return true;
                }
                if ctx
                    .budget
                    .as_mut()
                    .is_some_and(|budget| budget.check_cheap().is_err())
                {
                    ctx.budget_exceeded = true;
                    return true;
                }
                let Some(name) = value.name else { return true };
                // Only decoder-owned names are aliases. A real parameter named
                // "Name|base64" is a different field from decoded "Name".
                let name = if namespace == "ARGS"
                    && d.b64_args
                        .iter()
                        .any(|(key, _)| key.as_ptr() == name.as_ptr() && key.len() == name.len())
                {
                    crate::b64::base_name(name)
                } else {
                    name
                };
                !ctx.active_exceptions
                    .iter()
                    .any(|e| e.rule_id == rule_id && e.matches_field(namespace, name))
            });
        }
        if ctx.budget_exceeded {
            return Outcome::Match(false, None);
        }
        if numeric && t.count {
            // a count always has a value
            if compare(op, vals.len() as i64, y) != neg {
                if !any {
                    match_candidate = Some(Candidate::Count {
                        var: t.var,
                        count: vals.len(),
                    });
                }
                any = true;
            }
            continue;
        }
        // with multi_match, every prefix of the chain: none, the first, ...
        let chains = if c.multi_match {
            0..=c.transforms.len()
        } else {
            c.transforms.len()..=c.transforms.len()
        };
        'values: for v in &vals {
            if ctx.budget_exceeded {
                break;
            }
            for k in chains.clone() {
                let chain = &c.transforms[..k];
                let is_pattern_scan = pattern && fallback.is_none() && !from_prev;
                let mut tv: Option<Cow<'_, [u8]>> = None;
                if !is_pattern_scan {
                    tv = match transform::apply_chain_with_budget(
                        chain,
                        v.val,
                        ctx.budget.as_deref_mut(),
                    ) {
                        Ok(res) => res,
                        Err(crate::budget::BudgetExceeded) => {
                            ctx.budget_exceeded = true;
                            break 'values;
                        }
                    };
                }
                let hit = if numeric {
                    // on the transformed value; one that is not a number
                    // counts as 0, as atoi does
                    tv.as_deref().is_some_and(|tv_ref| {
                        let x = std::str::from_utf8(trim(tv_ref))
                            .ok()
                            .and_then(|s| s.parse::<i64>().ok())
                            .unwrap_or(0);
                        compare(op, x, y)
                    })
                } else if detect {
                    tv.as_deref().is_some_and(|tv_ref| match op {
                        "detect_sqli" => detect_sqli(tv_ref).is_some(),
                        "detect_xss" => detect_xss(tv_ref),
                        "detect_ssti" => ssti::detect(tv_ref),
                        "detect_cmdi" => cmdi::detect(tv_ref),
                        _ => false,
                    })
                } else if operator_v2 {
                    tv.as_deref().is_some_and(|tv_ref| match op {
                        "validate_byte_range" => ctx.operators.check_byte_range(ci, tv_ref),
                        "validate_url_encoding" => operators::validate_url_encoding(tv_ref),
                        "validate_utf8_encoding" => operators::validate_utf8_encoding(tv_ref),
                        "ip_match" => ctx.operators.check_ip_match(ci, tv_ref),
                        _ => false,
                    })
                } else if let Some(fb) = fallback {
                    // compiled on first use: once per worker and bundle,
                    // so not this request's inspection time
                    let (compiled, spent) = fb.compiled_timed();
                    if let (Some(d), Some(b)) = (spent, ctx.budget.as_deref_mut()) {
                        b.credit(d);
                    }
                    tv.as_deref().is_some_and(|val| {
                        let Some((re, dfa)) = compiled else {
                            return false;
                        };
                        match dfa_is_match_with_budget(ctx.engine_id, dfa, re, val, &mut ctx.budget)
                        {
                            Ok(h) => h,
                            Err(_) => {
                                ctx.budget_exceeded = true;
                                false
                            }
                        }
                    })
                } else if from_prev {
                    scan(&ctx.hs, &mut ctx.budget, &mut ctx.budget_exceeded, &tv).contains(&ci)
                } else {
                    matched(ctx, v.val, chain).contains(&ci)
                };
                if ctx.budget_exceeded {
                    break 'values;
                }
                if hit != neg {
                    if is_pattern_scan && tv.is_none() {
                        tv = match transform::apply_chain_with_budget(
                            chain,
                            v.val,
                            ctx.budget.as_deref_mut(),
                        ) {
                            Ok(res) => res,
                            Err(crate::budget::BudgetExceeded) => {
                                ctx.budget_exceeded = true;
                                break 'values;
                            }
                        };
                    }
                    if !any {
                        let window = match tv.as_deref() {
                            Some(b) => {
                                let len = b.len().min(crate::event::MASK_WINDOW);
                                b[..len].to_vec()
                            }
                            None => Vec::new(),
                        };
                        // a decoded value keeps its suffix under a keyed
                        // target too: ARGS:q|base64, not ARGS:q
                        let key_name = match (t.key, v.name) {
                            (Some(k), Some(n)) if n.ends_with(crate::b64::SUFFIX) => {
                                Some(crate::b64::name(k))
                            }
                            (Some(k), _) => Some(k.to_vec()),
                            (None, n) => n.map(|n| n.to_vec()),
                        };
                        match_candidate = Some(Candidate::Value {
                            var: t.var,
                            name: key_name,
                            window,
                        });
                    }
                    any = true;
                    match collect.as_deref_mut() {
                        Some(m) => {
                            if let Some(tv) = tv {
                                m.push(tv.into_owned());
                            }
                            continue 'values;
                        }
                        None => break 'values,
                    }
                }
            }
        }
        if any && collect.is_none() {
            break;
        }
    }
    Outcome::Match(any, match_candidate)
}

/// Conditions matched by `v` after `chain`, scanning at most once per
/// (value, chain), and at most once per transformed bytes: chains that
/// leave a value as it is (most of them, on most values) or that give the
/// same bytes share one scan, whose result only depends on the bytes
/// (W09-R-01).
fn matched<'c>(ctx: &'c mut Ctx<'_, '_, '_>, v: &[u8], chain: &[u8]) -> &'c [u32] {
    // what the prefilter scanned (#28); the borrow checker wants the
    // lookup twice rather than a returned borrow across the fallback
    if ctx.pass.get(v, chain).is_some() {
        return ctx.pass.get(v, chain).unwrap_or(&[]);
    }
    let key = make_scan_key(v, chain);
    if !ctx.scans.contains_key(&key) {
        let tv = match transform::apply_chain_with_budget(chain, v, ctx.budget.as_deref_mut()) {
            Ok(res) => res,
            Err(crate::budget::BudgetExceeded) => {
                ctx.budget_exceeded = true;
                None
            }
        };
        let hits = match tv {
            None => vec![],
            Some(Cow::Borrowed(b)) => {
                let k0 = make_scan_key(b, &[]);
                match ctx.scans.get(&k0) {
                    Some(h) => h.clone(),
                    None => {
                        let h = scan(
                            &ctx.hs,
                            &mut ctx.budget,
                            &mut ctx.budget_exceeded,
                            &Some(Cow::Borrowed(b)),
                        );
                        ctx.scans.insert(k0, h.clone());
                        h
                    }
                }
            }
            Some(Cow::Owned(o)) => match ctx.scans_by_bytes.get(&o[..]) {
                Some(h) => h.clone(),
                None => {
                    let tv = Some(Cow::Owned(o));
                    let h = scan(&ctx.hs, &mut ctx.budget, &mut ctx.budget_exceeded, &tv);
                    if let Some(Cow::Owned(o)) = tv {
                        ctx.scans_by_bytes.insert(o.into_boxed_slice(), h.clone());
                    }
                    h
                }
            },
        };
        ctx.scans.insert(key, hits);
    }
    ctx.scans.get(&key).map_or(&[], Vec::as_slice)
}

/// Conditions matched by a transformed value, without the cache.
fn scan(
    hs: &Option<HsDbs<'_>>,
    budget: &mut Option<&mut crate::budget::TxBudget>,
    budget_exceeded: &mut bool,
    tv: &Option<Cow<'_, [u8]>>,
) -> Vec<u32> {
    let mut hits = vec![];
    if let (Some((map, db, block)), Some(tv)) = (hs, tv) {
        let short_block = block.as_ref().filter(|_| tv.len() <= BLOCK_SCAN_MAX);
        if let (true, Some(b)) = (map.is_stream, short_block) {
            // same patterns and ids as the stream database (checked at load)
            let _ = b.scan(tv, &mut |id| {
                if let Some(c) = map.condition(id) {
                    hits.push(c);
                }
                true
            });
        } else if map.is_stream {
            let mut on_match = |id: u32| -> bool {
                if let Some(c) = map.condition(id) {
                    hits.push(c);
                }
                true
            };
            let check_budget = || -> bool {
                if let Some(bgt) = budget.as_mut() {
                    bgt.check().is_ok()
                } else {
                    true
                }
            };
            match db.scan_stream_chunks(tv, 2048, check_budget, &mut on_match) {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    if budget.as_mut().is_some_and(|bgt| bgt.check().is_err()) {
                        *budget_exceeded = true;
                    }
                }
            }
        } else {
            let _ = db.scan(tv, &mut |id| {
                if let Some(c) = map.condition(id) {
                    hits.push(c);
                }
                true
            });
        }
    }
    if hits.len() > 1 {
        hits.sort_unstable();
        hits.dedup();
    }
    hits
}

fn rule_matches(
    ctx: &mut Ctx<'_, '_, '_>,
    d: &Data<'_>,
    r: &RuleView<'_>,
) -> Option<(bool, Option<MatchDetail>)> {
    let mut results = Vec::with_capacity(r.cond_count as usize);
    let mut prev = Matched::new();
    let mut best_candidate: Option<Candidate> = None;

    let end = r.cond_first + r.cond_count;
    for ci in r.cond_first..end {
        if ctx.budget_exceeded {
            return Some((false, None));
        }
        let c = ctx.tables.cond(ci)?;
        // keep what this condition matches when the next one reads it
        let next_reads = !r.any
            && ci + 1 < end
            && ctx.tables.cond(ci + 1).is_some_and(|n| {
                (n.target_first..n.target_first + n.target_count).any(|t| {
                    ctx.tables
                        .target(t)
                        .is_some_and(|t| t.var == const { var("matched_vars") })
                })
            });
        let mut kept = Matched::new();
        let collect = if next_reads { Some(&mut kept) } else { None };
        match condition(ctx, d, ci, r.id, &c, &prev, collect) {
            Outcome::Unsupported => return None,
            Outcome::Match(m, cand) => {
                if ctx.budget_exceeded {
                    return Some((false, None));
                }
                if let (true, Some(mut cand)) = (m, cand) {
                    // matched_vars holds values the previous condition matched:
                    // they keep that condition's name, so a password matched
                    // through a chain stays recognized as one
                    if let (
                        Candidate::Value { var: v, name, .. },
                        Some(Candidate::Value {
                            name: prev_name, ..
                        }),
                    ) = (&mut cand, &best_candidate)
                        && *v == const { var("matched_vars") }
                        && name.is_none()
                    {
                        name.clone_from(prev_name);
                    }
                    let should_replace = best_candidate.is_none()
                        || best_candidate.as_ref().is_some_and(|b| b.is_boilerplate())
                        || !cand.is_boilerplate();
                    if should_replace {
                        best_candidate = Some(cand);
                    }
                }
                results.push(m);
                // a rule whose conditions must all hold fails at the first
                // that does not: the rest cannot change that (W09-R-01)
                if !r.any && !m {
                    return Some((false, None));
                }
            }
        }
        prev = kept;
    }
    let matched = if r.any {
        results.iter().any(|&m| m)
    } else {
        !results.is_empty() && results.iter().all(|&m| m)
    };
    let detail = if matched {
        best_candidate.map(|c| c.to_match_detail())
    } else {
        None
    };
    Some((matched, detail))
}

/// Evaluates every rule of `stage` against the request.
pub fn evaluate(
    tables: &Tables<'_>,
    db: Option<MappedDb<'_>>,
    regexes: &Regexes,
    operators: &CompiledOperators,
    req: &Request<'_>,
    stage: u8,
    report: &mut impl FnMut(Violation),
) {
    let engine_id = db.as_ref().map(|d| d.id()).unwrap_or(0);
    let _ = evaluate_with_budget(
        engine_id,
        tables,
        db,
        regexes,
        operators,
        None,
        req,
        stage,
        false,
        true,
        &[],
        None,
        None,
        None,
        report,
    );
}

/// Records a rule's evaluation time when dropped (W13-R-02), so that
/// every way out of the rule's turn (continue, return) counts.
struct RuleTimer<'a> {
    t0: std::time::Instant,
    index: u32,
    costs: Option<&'a crate::rulecost::Samples>,
}

impl Drop for RuleTimer<'_> {
    fn drop(&mut self) {
        if let Some(c) = self.costs {
            c.borrow_mut()
                .push((Some(self.index), self.t0.elapsed().as_nanos() as u64));
        }
    }
}

/// Evaluates every rule of `stage` against the request with CPU budget tracking.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_with_budget(
    engine_id: u64,
    tables: &Tables<'_>,
    db: Option<MappedDb<'_>>,
    regexes: &Regexes,
    operators: &CompiledOperators,
    prefilter: Option<&Prefilter>,
    req: &Request<'_>,
    stage: u8,
    degraded: bool,
    signatures: bool,
    disabled: &[u32],
    exception_policy: Option<(u32, &[crate::exceptions::Exception])>,
    exclusions: Option<crate::rule_exclusions::Pass<'_>>,
    mut budget: Option<&mut crate::budget::TxBudget>,
    report: &mut impl FnMut(Violation),
) -> Result<(), crate::budget::BudgetExceeded> {
    if tables.n_rules() == 0 {
        return Ok(());
    }
    if let Some(bgt) = budget.as_mut() {
        bgt.check()?;
    }
    let full_uri = if req.args.is_empty() {
        Cow::Borrowed(req.uri)
    } else {
        Cow::Owned([req.uri, b"?", req.args].concat())
    };
    let max_args = match req.max_args {
        0 => MAX_ARGS,
        n => n.min(MAX_ARGS),
    };
    let (mut args, mut args_left_out) =
        parse_query_limit(req.args, max_args, budget.as_deref_mut())?;
    let n_get = args.len();
    let mut files = vec![];
    let mut part_headers = vec![];
    let mut xml_body = None;
    // the body parser stopped before the end (#97): rule 100022
    let mut body_unparsed = false;
    // the body is encoded, so the engine cannot read it (#97): rule 100023
    let body_encoded = !req.body.is_empty() && content_encoding_opaque(req.headers);
    let room = max_args.saturating_sub(n_get);
    let ct = content_type(req.headers);
    let processor = body_processor(ct);
    if !req.body.is_empty() {
        match processor {
            b"URLENCODED" => {
                let (body_args, left_out) =
                    parse_query_limit(req.body, room, budget.as_deref_mut())?;
                args_left_out |= left_out;
                args.extend(body_args);
            }
            b"JSON" => {
                // one more than room: whether some were left out
                let (mut j, whole) =
                    json::args_checked_with_budget(req.body, room + 1, budget.as_deref_mut())?;
                body_unparsed = !whole;
                if j.len() > room {
                    j.truncate(room);
                    args_left_out = true;
                }
                args.extend(j.into_iter().map(|(k, v)| (Cow::Owned(k), Cow::Owned(v))));
            }
            b"XML" => {
                let (x, whole) = xml::parse_checked_with_budget(req.body, budget.as_deref_mut())?;
                body_unparsed = !whole;
                xml_body = Some(x);
            }
            b"MULTIPART" => {
                let (parts, read) = multipart::parts_checked_with_budget(
                    req.body,
                    multipart::boundary(ct).unwrap_or(b""),
                    budget.as_deref_mut(),
                )?;
                match read {
                    multipart::Read::Whole => {}
                    multipart::Read::Damaged => body_unparsed = true,
                    multipart::Read::TooManyParts => args_left_out = true,
                }
                for p in parts {
                    part_headers.extend(p.headers.iter().map(|h| (p.name, *h)));
                    match p.filename {
                        Some(f) => files.push((p.name, f)),
                        None if args.len() < max_args => {
                            args.push((Cow::Borrowed(p.name), Cow::Borrowed(p.content)))
                        }
                        None => args_left_out = true,
                    }
                }
            }
            _ => {}
        }
    }
    if args_left_out {
        // not every argument is inspected: rule 100021, which the
        // transaction makes block or recorded per the policy's oversize
        report(Violation {
            rule: crate::detectors::protocol::ARGS_OVER_LIMIT,
            score: 0,
            block_alone: false,
            signature: false,
            report_only: false,
            layer: "protocol",
            field: "ARGS".to_string(),
            snippet: Vec::new(),
        });
    }
    if body_unparsed {
        // what follows the damage is not inspected: rule 100022, which the
        // transaction makes block or recorded per the policy's oversize
        report(Violation {
            rule: crate::detectors::protocol::BODY_UNPARSED,
            score: 0,
            block_alone: false,
            signature: false,
            report_only: false,
            layer: "protocol",
            field: "REQUEST_BODY".to_string(),
            snippet: Vec::new(),
        });
    }
    if body_encoded {
        // an encoded body the engine cannot read: rule 100023, which the
        // transaction makes block or recorded per the policy's oversize
        report(Violation {
            rule: crate::detectors::protocol::BODY_ENCODED,
            score: 0,
            block_alone: false,
            signature: false,
            report_only: false,
            layer: "protocol",
            field: "REQUEST_HEADERS:Content-Encoding".to_string(),
            snippet: Vec::new(),
        });
    }
    let cookies = parse_cookies(req.headers);
    // values that look base64-encoded are inspected decoded too (b64.rs)
    if let Some(bgt) = budget.as_mut() {
        bgt.check()?;
    }
    let mut left = crate::b64::Left::default();
    let mut b64_args = crate::b64::decode_all(args[..n_get].iter().map(pair), &mut left);
    let b64_get = b64_args.len();
    b64_args.extend(crate::b64::decode_all(
        args[n_get..].iter().map(pair),
        &mut left,
    ));
    let b64_cookies = crate::b64::decode_all(cookies.iter().map(pair), &mut left);
    let d = Data {
        req,
        full_uri,
        processor,
        request_line: [req.method, b" ", req.raw_uri, b" ", req.proto].concat(),
        args,
        n_get,
        cookies,
        files,
        part_headers,
        xml: xml_body,
        b64_args,
        b64_get,
        b64_cookies,
    };
    let hs = tables.hyperscan().zip(db).map(|(map, db)| {
        // validated with the engine (Engine::map), like the stream image
        let block = tables
            .hyperscan_block()
            .map(|b| MappedDb::assume_valid_with_id(b.image, db.id() | BLOCK_DB_ID));
        (map, db, block)
    });
    let active_exceptions = exception_policy.map_or_else(Vec::new, |(index, entries)| {
        if entries.is_empty() {
            return vec![];
        }
        let mut hosts = req
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(b"Host"));
        let Some((_, host)) = hosts.next() else {
            return vec![];
        };
        if hosts.next().is_some() {
            return vec![];
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        entries
            .iter()
            .filter(|e| e.matches_scope(index, req.method, host, req.uri, now))
            .collect()
    });
    let mut ctx = Ctx {
        engine_id,
        tables,
        regexes,
        operators,
        hs,
        scans: HashMap::with_hasher(FastBuildHasher::default()),
        scans_by_bytes: ContentScans::with_hasher(operators.content_hasher.clone()),
        active_exceptions,
        removals: vec![],
        groups: vec![None; prefilter.map_or(0, |p| p.group_rep.len())],
        pass: Pass::default(),
        budget,
        budget_exceeded: false,
    };
    // W17-S-01: the exclusion rules of this stage run before the others;
    // what the matched ones remove holds for the rest of the transaction
    if let Some(x) = exclusions {
        for &(id, index) in x.rules {
            let Some(r) = tables.rule(index as usize) else {
                continue;
            };
            if r.stage != stage || x.active.contains(&id) {
                continue;
            }
            if let Some(bgt) = ctx.budget.as_mut() {
                bgt.check_cheap()?;
            }
            if let Some((true, _)) = rule_matches(&mut ctx, &d, &r) {
                x.active.push(id);
            }
            if ctx.budget_exceeded {
                return Err(crate::budget::BudgetExceeded);
            }
        }
        ctx.removals = x
            .active
            .iter()
            .flat_map(|&id| x.table.removals(id))
            .collect();
    }
    // with the prefilter, only the rules that may match are visited
    let order: Vec<u32> = match prefilter {
        Some(pf) if !degraded => {
            let t0 = req.costs.map(|_| std::time::Instant::now());
            let c = candidates(&mut ctx, &d, pf, stage);
            if let (Some(t0), Some(costs)) = (t0, req.costs) {
                costs
                    .borrow_mut()
                    .push((None, t0.elapsed().as_nanos() as u64));
            }
            if ctx.budget_exceeded {
                return Err(crate::budget::BudgetExceeded);
            }
            c
        }
        _ => (0..tables.n_rules() as u32).collect(),
    };
    let gated = prefilter.is_some() && !degraded;
    for i in order {
        let i = i as usize;
        let Some(r) = tables.rule(i) else { continue };
        let role = req.paranoia.role(r.paranoia);
        // W19-G2-01: a scoped rule runs for its policies only, in its mode
        let scope = if r.scoped {
            match req.scoped.binary_search_by_key(&r.id, |&(id, _)| id) {
                Ok(k) => Some(req.scoped[k].1),
                Err(_) => continue,
            }
        } else {
            None
        };
        if r.stage != stage
            || r.exclusion
            || role == crate::paranoia::Role::Skip
            || (r.signature && !signatures)
            || (!disabled.is_empty() && disabled.binary_search(&r.id).is_ok())
            || ctx.removals.iter().any(|x| x.removes_rule(r.id))
        {
            continue;
        }
        if degraded {
            let layer_name = crate::rules::LAYERS
                .get(r.layer as usize)
                .copied()
                .unwrap_or("");
            let is_protocol = layer_name == "protocol";
            let all_ip_match = r.cond_count > 0
                && (r.cond_first..r.cond_first + r.cond_count).all(|ci| {
                    tables.cond(ci).is_some_and(|c| {
                        let op = crate::rules::OPERATORS
                            .get(c.op as usize)
                            .copied()
                            .unwrap_or("");
                        op == "ip_match"
                    })
                });
            if !is_protocol && !all_ip_match {
                continue;
            }
        }
        if let Some(bgt) = ctx.budget.as_mut() {
            bgt.check_cheap()?;
        }
        if ctx.budget_exceeded {
            return Err(crate::budget::BudgetExceeded);
        }
        // W13-R-02: the rule's time, from here to the end of its turn
        let t0 = req.costs.map(|_| std::time::Instant::now());
        let _timed = t0.map(|t0| RuleTimer {
            t0,
            index: i as u32,
            costs: req.costs,
        });
        if !gated
            && let Some(pf) = prefilter
            && !may_match(&mut ctx, &d, pf, i, &r)
        {
            if ctx.budget_exceeded {
                return Err(crate::budget::BudgetExceeded);
            }
            continue;
        }
        if let Some((true, detail)) = rule_matches(&mut ctx, &d, &r) {
            let (field, snippet) = detail.map(|d| (d.field, d.snippet)).unwrap_or_default();
            let layer_name = crate::rules::LAYERS
                .get(r.layer as usize)
                .copied()
                .unwrap_or("managed");
            report(Violation {
                rule: r.id,
                score: r.score,
                block_alone: r.block_alone,
                signature: r.signature,
                report_only: role == crate::paranoia::Role::Shadow
                    || scope == Some(crate::scope::Mode::Log),
                layer: layer_name,
                field,
                snippet,
            });
        }
        if ctx.budget_exceeded {
            return Err(crate::budget::BudgetExceeded);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn raw_content_hash_resists_repeated_xor_pairs() {
        use std::hash::BuildHasher;
        // Equal-length inputs whose differing bytes are 64 apart collide under
        // rotate-left(5) XOR. A hostile body can supply all 1024 distinct values.
        let operators = crate::operators::CompiledOperators::default();
        let cache = super::ContentScans::with_hasher(operators.content_hasher.clone());
        let mut hashes = std::collections::HashSet::new();
        for mask in 0..1024u16 {
            let mut value = vec![b'a'; 128];
            for bit in 0..10 {
                if mask & (1 << bit) != 0 {
                    value[bit] ^= 1;
                    value[bit + 64] ^= 1;
                }
            }
            hashes.insert(cache.hasher().hash_one(value.as_slice()));
        }
        assert!(
            hashes.len() >= 1000,
            "only {} hash values for 1024 hostile keys",
            hashes.len()
        );
    }

    use super::*;

    #[test]
    fn query_and_cookies() {
        let q = parse_query(b"a=1&b=x+y%3C&&flag&a=2");
        let names: Vec<&[u8]> = q.iter().map(|(n, _)| &**n).collect();
        assert_eq!(names, [&b"a"[..], b"b", b"flag", b"a"]);
        assert_eq!(&*q[1].1, b"x y<");
        assert_eq!(&*q[2].1, b"");
        let h: Vec<(&[u8], &[u8])> = vec![(b"Cookie", b"sid=abc; theme=dark"), (b"cookie", b"x")];
        let c = parse_cookies(&h);
        assert_eq!(c.len(), 3);
        assert_eq!((&*c[1].0, &*c[1].1), (&b"theme"[..], &b"dark"[..]));
    }

    #[test]
    fn supported_lists_match_the_evaluator() {
        let (ops, transforms) = supported();
        for op in [
            "rx",
            "pm",
            "eq",
            "detect_sqli",
            "detect_xss",
            "detect_ssti",
            "detect_cmdi",
            "validate_byte_range",
            "validate_url_encoding",
            "validate_utf8_encoding",
            "ip_match",
        ] {
            assert!(ops.contains(&op), "{op}");
        }
        assert_eq!(
            transforms.len(),
            crate::rules::TRANSFORMS.len(),
            "every IR transformation runs"
        );
        for v in SUPPORTED_VARS {
            assert!(crate::rules::VARS.contains(v), "{v} is not an IR variable");
        }
    }

    #[test]
    fn content_encoding_opaque_detects_non_identity() {
        let h = |v: &'static [u8]| content_encoding_opaque(&[(&b"Content-Encoding"[..], v)]);
        assert!(h(b"gzip"));
        assert!(h(b"br"));
        assert!(h(b"gzip, br"));
        assert!(h(b"identity, gzip")); // any non-identity token counts
        assert!(!h(b"identity"));
        assert!(!h(b""));
        assert!(!content_encoding_opaque(&[(
            &b"Content-Type"[..],
            b"application/json"
        )]));
    }

    #[test]
    fn body_processor_by_content_type() {
        for (ct, want) in [
            (
                &b"application/x-www-form-urlencoded; charset=utf-8"[..],
                &b"URLENCODED"[..],
            ),
            (b"application/json", b"JSON"),
            (b"application/problem+json", b"JSON"),
            (b"text/xml", b"XML"),
            (b"multipart/form-data; boundary=x", b"MULTIPART"),
            (b"multipart/form-data", b""),
            (b"text/plain", b""),
            (b"", b""),
        ] {
            assert_eq!(body_processor(ct), want, "{}", String::from_utf8_lossy(ct));
        }
    }

    #[test]
    fn length_transform() {
        assert_eq!(&*transform::apply(transform::LENGTH, b"").unwrap(), b"0");
        assert_eq!(
            &*transform::apply(transform::LENGTH, "é".as_bytes()).unwrap(),
            b"2",
            "bytes"
        );
    }

    #[test]
    fn byte_escapes_rewrites_only_byte_values() {
        assert_eq!(byte_escapes(r"\x{bc}[^\x{BE}]"), r"\xbc[^\xbe]");
        assert_eq!(byte_escapes(r"\\x{bc}"), r"\\x{bc}", "an escaped backslash");
        assert_eq!(byte_escapes(r"\x{100}a\d{2}é"), r"\x{100}a\d{2}é");
        assert_eq!(byte_escapes("\\"), "\\");
    }

    #[test]
    fn form_decode_edge_cases() {
        assert_eq!(&*form_decode(b"%41%4"), b"A%4");
        assert_eq!(&*form_decode(b"%zz+%"), b"%zz %");
    }
}
