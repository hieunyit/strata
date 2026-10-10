//! Rule evaluation v0 (W05-R-01): stage `request_headers`.
//!
//! Targets: method, uri_raw, uri, path, args / args_get / args_names (query
//! string, form-decoded), request_headers[_names], request_cookies[_names],
//! remote_addr, protocol. Operators: the Hyperscan ones (rx, pm, contains,
//! begins_with, ends_with, streq) and the numeric ones (eq ... le, on a
//! value or on the count of values), and detect_sqli / detect_xss (the
//! libinjection port, on each transformed value). A rule using an operator or a
//! transformation this engine does not implement yet is skipped.
//!
//! Each distinct (value, transformation chain) is scanned once with the
//! bundle's Hyperscan database; the matches of every pattern-condition are
//! collected from that one scan.
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

/// Bounded work on hostile input.
const MAX_ARGS: usize = 1024;
const MAX_COOKIES: usize = 256;

/// What the connector passed for the request line and headers.
pub struct Request<'a> {
    pub method: &'a [u8],
    pub raw_uri: &'a [u8],
    pub uri: &'a [u8],
    pub args: &'a [u8],
    pub proto: &'a [u8],
    pub client_addr: &'a [u8],
    pub headers: &'a [(&'a [u8], &'a [u8])],
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
    args: Vec<Pair<'a>>,
    cookies: Vec<Pair<'a>>,
}

struct Ctx<'t, 'b> {
    tables: &'t Tables<'b>,
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
    } else if v == var("remote_addr") {
        vec![r.client_addr]
    } else if v == var("args") || v == var("args_get") {
        d.args
            .iter()
            .filter(|(n, _)| keyed(n))
            .map(|(_, v)| &**v)
            .collect()
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
    } else {
        vec![] // body and response variables: later stages
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

fn condition(ctx: &mut Ctx<'_, '_>, d: &Data<'_>, ci: u32, c: &CondView<'_>) -> Outcome {
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
    if pattern && ctx.hs.is_none() {
        return Outcome::Unsupported;
    }

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
        let vals = values(d, &t, &excluded);

        if numeric {
            let ValueView::Int(y) = c.value else {
                return Outcome::Unsupported;
            };
            if t.count {
                any |= compare(op, vals.len() as i64, y);
            } else {
                any |= vals.iter().any(|v| {
                    std::str::from_utf8(trim(v))
                        .ok()
                        .and_then(|s| s.parse::<i64>().ok())
                        .is_some_and(|x| compare(op, x, y))
                });
            }
        } else if detect {
            any |= vals.iter().any(|v| {
                transform::apply_chain(c.transforms, v).is_some_and(|tv| {
                    if op == "detect_sqli" {
                        detect_sqli(&tv).is_some()
                    } else {
                        detect_xss(&tv)
                    }
                })
            });
        } else {
            for v in vals {
                if matched(ctx, v, c.transforms).contains(&ci) {
                    any = true;
                    break;
                }
            }
        }
        if any {
            break;
        }
    }
    Outcome::Match(any != c.negate)
}

/// Conditions matched by `v` after `chain`, scanning at most once per
/// (value, chain).
fn matched<'c>(ctx: &'c mut Ctx<'_, '_>, v: &[u8], chain: &[u8]) -> &'c [u32] {
    let key = (v.as_ptr() as usize, v.len(), chain.to_vec());
    if !ctx.scans.contains_key(&key) {
        let mut hits = vec![];
        if let (Some((map, db)), Some(tv)) = (&ctx.hs, transform::apply_chain(chain, v)) {
            let _ = db.scan(&tv, &mut |id| {
                if let Some(c) = map.condition(id) {
                    hits.push(c);
                }
                true
            });
        }
        hits.sort_unstable();
        hits.dedup();
        ctx.scans.insert(key.clone(), hits);
    }
    &ctx.scans[&key]
}

fn rule_matches(ctx: &mut Ctx<'_, '_>, d: &Data<'_>, r: &RuleView<'_>) -> Option<bool> {
    let mut results = Vec::with_capacity(r.cond_count as usize);
    for ci in r.cond_first..r.cond_first + r.cond_count {
        let c = ctx.tables.cond(ci)?;
        match condition(ctx, d, ci, &c) {
            Outcome::Unsupported => return None,
            Outcome::Match(m) => results.push(m),
        }
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
    let d = Data {
        req,
        full_uri,
        args: parse_query(req.args),
        cookies: parse_cookies(req.headers),
    };
    let hs = tables.hyperscan().zip(db);
    let mut ctx = Ctx {
        tables,
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
    fn form_decode_edge_cases() {
        assert_eq!(&*form_decode(b"%41%4"), b"A%4");
        assert_eq!(&*form_decode(b"%zz+%"), b"%zz %");
    }
}
