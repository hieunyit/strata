//! Rule evaluation v0 (W05-R-01): stages `request_headers` and
//! `request_body`.
//!
//! Targets: method, uri_raw, uri, path, args (query string and, for an
//! `application/x-www-form-urlencoded`, `multipart/form-data` or JSON body,
//! its fields: `json.a.0` for JSON), args_get (query), args_post (body
//! fields), args_names, files and files_names (uploads of a multipart
//! body), xml and xml_attributes (an XML body's text and attribute values),
//! request_body (the raw body as
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
//! collected from that one scan. An rx pattern Hyperscan does not take
//! (CRS has a few too large for it) is left out of the database by the
//! compiler and runs with the `regex` crate instead, also in linear time
//! ([`Regexes`]).
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::collections::HashMap;

use strata_hs::MappedDb;

use crate::detectors::Violation;
use crate::detectors::injection::{detect_sqli, detect_xss};
use crate::rules::{
    CondView, HS_OPERATORS, Hyperscan, RuleView, Tables, TargetView, VARS, ValueView, code,
};
use crate::transform;
use crate::{json, multipart, xml};

/// The rx patterns of a bundle that are not in its Hyperscan database,
/// compiled with the `regex` crate when the bundle is mapped.
#[derive(Default)]
pub struct Regexes(Vec<(u32, regex::bytes::Regex)>);

/// Compiles an rx pattern for the `regex` crate with Hyperscan's meaning
/// (the database is built without HS_FLAG_UTF8): on bytes, classes and
/// case folding are ASCII, and `\x{bc}` is the byte 0xbc (for the `regex`
/// crate it is a code point, so it is written `\xbc`).
pub fn fallback_regex(pattern: &[u8]) -> Result<regex::bytes::Regex, String> {
    let s = std::str::from_utf8(pattern).map_err(|_| "pattern is not UTF-8".to_string())?;
    regex::bytes::RegexBuilder::new(&byte_escapes(s))
        .unicode(false)
        .size_limit(64 << 20)
        .dfa_size_limit(16 << 20)
        .build()
        .map_err(|e| e.to_string())
}

/// `\x{HH}` -> `\xHH` for values up to 0xff; other escapes as written.
fn byte_escapes(p: &str) -> String {
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
                    let re = fallback_regex(p).map_err(|e| format!("rule {}: {e}", r.id))?;
                    out.push((ci, re));
                }
            }
        }
        out.sort_by_key(|(ci, _)| *ci);
        Ok(Regexes(out))
    }

    fn get(&self, ci: u32) -> Option<&regex::bytes::Regex> {
        self.0
            .binary_search_by_key(&ci, |(c, _)| *c)
            .ok()
            .map(|i| &self.0[i].1)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
                    "eq" | "ne" | "gt" | "ge" | "lt" | "le" | "detect_sqli" | "detect_xss"
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
    pub headers: &'a [(&'a [u8], &'a [u8])],
    /// The request body as inspected (empty at stage request_headers).
    pub body: &'a [u8],
}

/// Whether the body is `application/x-www-form-urlencoded`.
fn form_body(headers: &[(&[u8], &[u8])]) -> bool {
    const FORM: &[u8] = b"application/x-www-form-urlencoded";
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case(b"content-type")
            && trim(v).len() >= FORM.len()
            && trim(v)[..FORM.len()].eq_ignore_ascii_case(FORM)
    })
}

/// The request's Content-Type (empty without one).
fn content_type<'a>(headers: &[(&'a [u8], &'a [u8])]) -> &'a [u8] {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(b"content-type"))
        .map_or(&b""[..], |(_, v)| v)
}

/// `application/x-www-form-urlencoded` decoding: %XX and '+'.
fn form_decode(s: &[u8]) -> Cow<'_, [u8]> {
    if !s.iter().any(|&c| c == b'%' || c == b'+') {
        return Cow::Borrowed(s);
    }
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
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
    Cow::Owned(out)
}

type Pair<'a> = (Cow<'a, [u8]>, Cow<'a, [u8]>);

fn parse_query(q: &[u8]) -> Vec<Pair<'_>> {
    q.split(|&c| c == b'&')
        .filter(|p| !p.is_empty())
        .take(MAX_ARGS)
        .map(|p| match p.iter().position(|&c| c == b'=') {
            Some(eq) => (form_decode(&p[..eq]), form_decode(&p[eq + 1..])),
            None => (form_decode(p), Cow::Borrowed(&p[..0])),
        })
        .collect()
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
        .map(|p| match p.iter().position(|&c| c == b'=') {
            Some(eq) => (Cow::Borrowed(&p[..eq]), Cow::Borrowed(&p[eq + 1..])),
            None => (Cow::Borrowed(p), Cow::Borrowed(&p[..0])),
        })
        .collect()
}

/// Request data prepared once per evaluation.
struct Data<'a> {
    req: &'a Request<'a>,
    full_uri: Cow<'a, [u8]>,
    /// method, raw URI and protocol, as on the wire
    request_line: Vec<u8>,
    /// query fields, then body fields: args_get is args[..n_get]
    args: Vec<Pair<'a>>,
    n_get: usize,
    cookies: Vec<Pair<'a>>,
    /// uploaded files of a multipart body: (field name, file name)
    files: Vec<(&'a [u8], &'a [u8])>,
    /// an XML body
    xml: Option<xml::Xml>,
}

struct Ctx<'t, 'b> {
    tables: &'t Tables<'b>,
    regexes: &'t Regexes,
    hs: Option<(Hyperscan<'b>, MappedDb<'b>)>,
    /// (value address, length, chain) -> conditions matched by the scan
    scans: HashMap<(usize, usize, Vec<u8>), Vec<u32>>,
}

fn var(name: &str) -> u8 {
    code(VARS, name).unwrap_or(u8::MAX)
}

/// Values of one target (key and exclude filters applied).
fn values<'d>(
    d: &'d Data<'d>,
    t: &TargetView<'_>,
    excluded: &dyn Fn(&[u8]) -> bool,
) -> Vec<&'d [u8]> {
    let r = d.req;
    let keyed = |name: &[u8]| t.key.is_none_or(|k| k.eq_ignore_ascii_case(name)) && !excluded(name);
    let v = t.var;
    if v == var("method") {
        vec![r.method]
    } else if v == var("uri_raw") {
        vec![r.raw_uri]
    } else if v == var("uri") {
        vec![&d.full_uri]
    } else if v == var("path") {
        vec![r.uri]
    } else if v == var("protocol") {
        vec![r.proto]
    } else if v == var("request_line") {
        vec![&d.request_line]
    } else if v == var("query_string") {
        if r.args.is_empty() {
            vec![]
        } else {
            vec![r.args]
        }
    } else if v == var("remote_addr") {
        vec![r.client_addr]
    } else if v == var("args") || v == var("args_get") || v == var("args_post") {
        let fields = if v == var("args_get") {
            &d.args[..d.n_get]
        } else if v == var("args_post") {
            &d.args[d.n_get..]
        } else {
            &d.args[..]
        };
        fields
            .iter()
            .filter(|(n, _)| keyed(n))
            .map(|(_, v)| &**v)
            .collect()
    } else if v == var("request_body") {
        if r.body.is_empty() {
            vec![]
        } else {
            vec![r.body]
        }
    } else if v == var("args_names") {
        d.args
            .iter()
            .filter(|(n, _)| keyed(n))
            .map(|(n, _)| &**n)
            .collect()
    } else if v == var("request_headers") {
        r.headers
            .iter()
            .filter(|(n, _)| keyed(n))
            .map(|(_, v)| *v)
            .collect()
    } else if v == var("request_headers_names") {
        r.headers
            .iter()
            .filter(|(n, _)| keyed(n))
            .map(|(n, _)| *n)
            .collect()
    } else if v == var("request_cookies") {
        d.cookies
            .iter()
            .filter(|(n, _)| keyed(n))
            .map(|(_, v)| &**v)
            .collect()
    } else if v == var("request_cookies_names") {
        d.cookies
            .iter()
            .filter(|(n, _)| keyed(n))
            .map(|(n, _)| &**n)
            .collect()
    } else if v == var("xml") {
        d.xml.iter().map(|x| &x.text[..]).collect()
    } else if v == var("xml_attributes") {
        d.xml
            .iter()
            .flat_map(|x| x.attrs.iter().map(|a| &a[..]))
            .collect()
    } else if v == var("files") {
        d.files
            .iter()
            .filter(|(n, _)| keyed(n))
            .map(|(_, f)| *f)
            .collect()
    } else if v == var("files_names") {
        d.files
            .iter()
            .filter(|(n, _)| keyed(n))
            .map(|(n, _)| *n)
            .collect()
    } else {
        vec![] // response variables: later
    }
}

enum Outcome {
    Match(bool),
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
    ctx: &mut Ctx<'_, '_>,
    d: &Data<'_>,
    ci: u32,
    c: &CondView<'_>,
    prev: &Matched,
    mut collect: Option<&mut Matched>,
) -> Outcome {
    let op = crate::rules::OPERATORS
        .get(c.op as usize)
        .copied()
        .unwrap_or("");
    let numeric = matches!(op, "eq" | "ne" | "gt" | "ge" | "lt" | "le");
    let pattern = HS_OPERATORS.contains(&c.op);
    let detect = matches!(op, "detect_sqli" | "detect_xss");
    if !(numeric || pattern || detect)
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
    for ti in c.target_first..c.target_first + c.target_count {
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
        let from_prev = t.var == var("matched_vars");
        let vals: Vec<&[u8]> = if from_prev {
            prev.iter().map(|v| &v[..]).collect()
        } else {
            values(d, &t, &excluded)
        };
        if numeric && t.count {
            // a count always has a value
            if compare(op, vals.len() as i64, y) != neg {
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
        'values: for v in vals {
            for k in chains.clone() {
                let chain = &c.transforms[..k];
                let tv = || transform::apply_chain(chain, v);
                let hit = if numeric {
                    // a value that is not a number counts as 0, as atoi does
                    let x = std::str::from_utf8(trim(v))
                        .ok()
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or(0);
                    compare(op, x, y)
                } else if detect {
                    tv().is_some_and(|tv| {
                        if op == "detect_sqli" {
                            detect_sqli(&tv).is_some()
                        } else {
                            detect_xss(&tv)
                        }
                    })
                } else if let Some(re) = fallback {
                    tv().is_some_and(|tv| re.is_match(&tv))
                } else if from_prev {
                    scan(ctx, &tv()).contains(&ci)
                } else {
                    matched(ctx, v, chain).contains(&ci)
                };
                if hit != neg {
                    any = true;
                    match collect.as_deref_mut() {
                        Some(m) => {
                            if let Some(tv) = tv() {
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
    Outcome::Match(any)
}

/// Conditions matched by `v` after `chain`, scanning at most once per
/// (value, chain).
fn matched<'c>(ctx: &'c mut Ctx<'_, '_>, v: &[u8], chain: &[u8]) -> &'c [u32] {
    let key = (v.as_ptr() as usize, v.len(), chain.to_vec());
    if !ctx.scans.contains_key(&key) {
        let hits = match transform::apply_chain(chain, v) {
            Some(tv) => scan(ctx, &Some(tv)),
            None => vec![],
        };
        ctx.scans.insert(key.clone(), hits);
    }
    &ctx.scans[&key]
}

/// Conditions matched by a transformed value, without the cache.
fn scan(ctx: &Ctx<'_, '_>, tv: &Option<Cow<'_, [u8]>>) -> Vec<u32> {
    let mut hits = vec![];
    if let (Some((map, db)), Some(tv)) = (&ctx.hs, tv) {
        let _ = db.scan(tv, &mut |id| {
            if let Some(c) = map.condition(id) {
                hits.push(c);
            }
            true
        });
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

fn rule_matches(ctx: &mut Ctx<'_, '_>, d: &Data<'_>, r: &RuleView<'_>) -> Option<bool> {
    let mut results = Vec::with_capacity(r.cond_count as usize);
    let mut prev = Matched::new();
    let end = r.cond_first + r.cond_count;
    for ci in r.cond_first..end {
        let c = ctx.tables.cond(ci)?;
        // keep what this condition matches when the next one reads it
        let next_reads = !r.any
            && ci + 1 < end
            && ctx.tables.cond(ci + 1).is_some_and(|n| {
                (n.target_first..n.target_first + n.target_count).any(|t| {
                    ctx.tables
                        .target(t)
                        .is_some_and(|t| t.var == var("matched_vars"))
                })
            });
        let mut kept = Matched::new();
        let collect = if next_reads { Some(&mut kept) } else { None };
        match condition(ctx, d, ci, &c, &prev, collect) {
            Outcome::Unsupported => return None,
            Outcome::Match(m) => results.push(m),
        }
        prev = kept;
    }
    Some(if r.any {
        results.iter().any(|&m| m)
    } else {
        !results.is_empty() && results.iter().all(|&m| m)
    })
}

/// Evaluates every rule of `stage` against the request.
pub fn evaluate(
    tables: &Tables<'_>,
    db: Option<MappedDb<'_>>,
    regexes: &Regexes,
    req: &Request<'_>,
    stage: u8,
    report: &mut impl FnMut(Violation),
) {
    if tables.n_rules() == 0 {
        return;
    }
    let full_uri = if req.args.is_empty() {
        Cow::Borrowed(req.uri)
    } else {
        Cow::Owned([req.uri, b"?", req.args].concat())
    };
    let mut args = parse_query(req.args);
    let n_get = args.len();
    let mut files = vec![];
    let mut xml_body = None;
    let room = MAX_ARGS.saturating_sub(n_get);
    let ct = content_type(req.headers);
    if req.body.is_empty() {
    } else if form_body(req.headers) {
        args.extend(parse_query(req.body).into_iter().take(room));
    } else if json::is_json(ct) {
        args.extend(
            json::args(req.body, room)
                .into_iter()
                .map(|(k, v)| (Cow::Owned(k), Cow::Owned(v))),
        );
    } else if xml::is_xml(ct) {
        xml_body = Some(xml::parse(req.body));
    } else if let Some(b) = multipart::boundary(ct) {
        for p in multipart::parts(req.body, b) {
            match p.filename {
                Some(f) => files.push((p.name, f)),
                None if args.len() < MAX_ARGS => {
                    args.push((Cow::Borrowed(p.name), Cow::Borrowed(p.content)))
                }
                None => {}
            }
        }
    }
    let d = Data {
        req,
        full_uri,
        request_line: [req.method, b" ", req.raw_uri, b" ", req.proto].concat(),
        args,
        n_get,
        cookies: parse_cookies(req.headers),
        files,
        xml: xml_body,
    };
    let hs = tables.hyperscan().zip(db);
    let mut ctx = Ctx {
        tables,
        regexes,
        hs,
        scans: HashMap::new(),
    };
    for i in 0..tables.n_rules() {
        let Some(r) = tables.rule(i) else { continue };
        if r.stage != stage {
            continue;
        }
        if rule_matches(&mut ctx, &d, &r) == Some(true) {
            report(Violation {
                rule: r.id,
                score: r.score,
                block_alone: false,
            });
        }
    }
}

#[cfg(test)]
mod tests {
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
        for op in ["rx", "pm", "eq", "detect_sqli", "detect_xss"] {
            assert!(ops.contains(&op), "{op}");
        }
        assert!(!ops.contains(&"ip_match"));
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
