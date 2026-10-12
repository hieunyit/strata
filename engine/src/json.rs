//! JSON request bodies, as arguments (CRS sets ModSecurity's JSON body
//! processor for application/json): every scalar is one argument named by
//! its path, `json.a.b` for objects and `json.a.0` for array items;
//! strings are unescaped, other scalars kept as written. Iterative with an
//! explicit stack, bounded depth and count. A document that does not parse
//! yields the arguments read before the damage.
#![forbid(unsafe_code)]

/// Deeper documents stop the parse.
pub const MAX_DEPTH: usize = 64;

/// Whether a Content-Type is JSON: application/json, */*+json.
pub fn is_json(content_type: &[u8]) -> bool {
    let media = crate::xml::media_type(content_type);
    media.eq_ignore_ascii_case(b"application/json")
        || (media.len() > 5 && media[media.len() - 5..].eq_ignore_ascii_case(b"+json"))
}

enum Frame {
    /// path length to restore, next key expected
    Object(usize),
    /// path length to restore, next index
    Array(usize, usize),
}

fn memchr2_8k(
    c1: u8,
    c2: u8,
    slice: &[u8],
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Option<usize>, crate::budget::BudgetExceeded> {
    let mut curr = 0;
    while curr < slice.len() {
        if curr > 0
            && let Some(bgt) = budget.as_mut()
        {
            bgt.check()?;
        }
        let end = (curr + 8192).min(slice.len());
        if let Some(i) = memchr::memchr2(c1, c2, &slice[curr..end]) {
            return Ok(Some(curr + i));
        }
        curr = end;
    }
    Ok(None)
}

fn position_8k<F>(
    slice: &[u8],
    mut pred: F,
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Option<usize>, crate::budget::BudgetExceeded>
where
    F: FnMut(u8) -> bool,
{
    let mut curr = 0;
    while curr < slice.len() {
        if curr > 0
            && let Some(bgt) = budget.as_mut()
        {
            bgt.check()?;
        }
        let end = (curr + 8192).min(slice.len());
        if let Some(i) = slice[curr..end].iter().position(|&c| pred(c)) {
            return Ok(Some(curr + i));
        }
        curr = end;
    }
    Ok(None)
}

/// (name, value) of every scalar, at most `max`, with cooperative budget tracking.
#[allow(clippy::type_complexity)]
pub fn args_with_budget(
    b: &[u8],
    max: usize,
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, crate::budget::BudgetExceeded> {
    let mut out = vec![];
    let mut path = b"json".to_vec();
    let mut stack: Vec<Frame> = vec![];
    let mut i = skip_ws(b, 0);
    // a value is expected at i; after it, the container goes on
    'value: while i < b.len() && out.len() < max {
        match b[i] {
            b'{' => {
                if stack.len() >= MAX_DEPTH {
                    break;
                }
                i = skip_ws(b, i + 1);
                if b.get(i) == Some(&b'}') {
                    i += 1; // empty: no member, nothing to close
                } else {
                    stack.push(Frame::Object(path.len()));
                    match key(b, i, &mut path, budget.as_deref_mut())? {
                        Some(n) => {
                            i = n;
                            continue 'value;
                        }
                        None => break,
                    }
                }
            }
            b'[' => {
                if stack.len() >= MAX_DEPTH {
                    break;
                }
                i = skip_ws(b, i + 1);
                if b.get(i) == Some(&b']') {
                    i += 1;
                } else {
                    stack.push(Frame::Array(path.len(), 0));
                    path.extend_from_slice(b".0");
                    continue 'value;
                }
            }
            b'"' => {
                let Some((v, n)) = string(b, i, budget.as_deref_mut())? else {
                    break;
                };
                out.push((path.clone(), v));
                i = n;
            }
            _ => {
                let end = position_8k(
                    &b[i..],
                    |c| matches!(c, b',' | b'}' | b']') || c.is_ascii_whitespace(),
                    budget.as_deref_mut(),
                )?
                .map_or(b.len(), |e| i + e);
                if end == i {
                    break;
                }
                out.push((path.clone(), b[i..end].to_vec()));
                i = end;
            }
        }
        // after a value (or an empty container): close containers, or the
        // next member
        loop {
            i = skip_ws(b, i);
            let Some(top) = stack.last_mut() else {
                break 'value; // the document is one value
            };
            match (top, b.get(i)) {
                (Frame::Object(base), Some(b',')) => {
                    path.truncate(*base);
                    match key(b, skip_ws(b, i + 1), &mut path, budget.as_deref_mut())? {
                        Some(n) => {
                            i = n;
                            continue 'value;
                        }
                        None => break 'value,
                    }
                }
                (Frame::Array(base, idx), Some(b',')) => {
                    *idx += 1;
                    path.truncate(*base);
                    path.push(b'.');
                    path.extend_from_slice(idx.to_string().as_bytes());
                    i = skip_ws(b, i + 1);
                    continue 'value;
                }
                (Frame::Object(base), Some(b'}')) | (Frame::Array(base, _), Some(b']')) => {
                    path.truncate(*base);
                    stack.pop();
                    i += 1;
                }
                _ => break 'value,
            }
        }
    }
    Ok(out)
}

/// (name, value) of every scalar, at most `max`.
pub fn args(b: &[u8], max: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    args_with_budget(b, max, None).unwrap()
}

/// `"key" :` at i: appends `.key` to path; returns where the value starts.
fn key(
    b: &[u8],
    i: usize,
    path: &mut Vec<u8>,
    budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Option<usize>, crate::budget::BudgetExceeded> {
    if b.get(i) != Some(&b'"') {
        return Ok(None);
    }
    let Some((k, n)) = string(b, i, budget)? else {
        return Ok(None);
    };
    let n = skip_ws(b, n);
    if b.get(n) != Some(&b':') {
        return Ok(None);
    }
    path.push(b'.');
    path.extend_from_slice(&k);
    Ok(Some(skip_ws(b, n + 1)))
}

/// The string at `b[i] == '"'`, unescaped, and the index after it.
fn string(
    b: &[u8],
    i: usize,
    mut budget: Option<&mut crate::budget::TxBudget>,
) -> Result<Option<(Vec<u8>, usize)>, crate::budget::BudgetExceeded> {
    let mut out = vec![];
    let mut j = i + 1;
    loop {
        let Some(rel) = memchr2_8k(b'"', b'\\', &b[j..], budget.as_deref_mut())? else {
            return Ok(None);
        };
        out.extend_from_slice(&b[j..j + rel]);
        j += rel;
        if b[j] == b'"' {
            return Ok(Some((out, j + 1)));
        }
        let Some(&e) = b.get(j + 1) else {
            return Ok(None);
        };
        j += 2;
        match e {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'u' => {
                let Some(mut cp) = hex4(b, j) else {
                    return Ok(None);
                };
                j += 4;
                // a surrogate pair
                if (0xd800..0xdc00).contains(&cp)
                    && b.get(j..j + 2) == Some(b"\\u")
                    && let Some(lo @ 0xdc00..0xe000) = hex4(b, j + 2)
                {
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                    j += 6;
                }
                let c = char::from_u32(cp).unwrap_or('\u{fffd}');
                let mut buf = [0; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            other => out.push(other), // \" \\ \/ and anything else
        }
    }
}

fn hex4(b: &[u8], j: usize) -> Option<u32> {
    u32::from_str_radix(std::str::from_utf8(b.get(j..j + 4)?).ok()?, 16).ok()
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        let end = (i + 8192).min(b.len());
        match b[i..end].iter().position(|&c| !c.is_ascii_whitespace()) {
            Some(pos) => return i + pos,
            None => i = end,
        }
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(b: &[u8]) -> Vec<(String, String)> {
        args(b, 1000)
            .into_iter()
            .map(|(k, v)| {
                (
                    String::from_utf8(k).unwrap(),
                    String::from_utf8_lossy(&v).into_owned(),
                )
            })
            .collect()
    }

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn content_types() {
        assert!(is_json(b"application/json; charset=utf-8"));
        assert!(is_json(b"application/vnd.api+json"));
        assert!(!is_json(b"text/json-ish"));
    }

    #[test]
    fn scalars_by_path() {
        let doc = br#" { "url" : "javascript&#10:alert(7)", "n": -1.5e3, "o": {"a": [true, null, "x\"\u0041\ud83d\ude00"], "e": {}}, "z": [] } "#;
        assert_eq!(
            named(doc),
            pairs(&[
                ("json.url", "javascript&#10:alert(7)"),
                ("json.n", "-1.5e3"),
                ("json.o.a.0", "true"),
                ("json.o.a.1", "null"),
                ("json.o.a.2", "x\"A😀"),
            ])
        );
        assert_eq!(
            named(b"[1, [2, 3]]"),
            pairs(&[("json.0", "1"), ("json.1.0", "2"), ("json.1.1", "3")])
        );
        assert_eq!(named(br#""top""#), pairs(&[("json", "top")]));
        assert_eq!(
            named(br#"{"a": {}, "b": [], "c": [[], {}, "x"], "d": 1}"#),
            pairs(&[("json.c.2", "x"), ("json.d", "1")]),
            "empty containers"
        );
    }

    #[test]
    fn damaged_documents_end_the_parse() {
        assert_eq!(named(br#"{"a": "1", "b" 2}"#), pairs(&[("json.a", "1")]));
        assert_eq!(named(br#"{"a": "unterminated"#), pairs(&[]));
        assert_eq!(named(b"{,}"), pairs(&[]));
        assert_eq!(named(b""), pairs(&[]));
        let deep = [
            b"[".repeat(MAX_DEPTH + 1),
            b"1".to_vec(),
            b"]".repeat(MAX_DEPTH + 1),
        ]
        .concat();
        assert_eq!(named(&deep), pairs(&[]), "too deep");
        let ok = [
            b"[".repeat(MAX_DEPTH),
            b"1".to_vec(),
            b"]".repeat(MAX_DEPTH),
        ]
        .concat();
        assert_eq!(named(&ok).len(), 1);
    }

    #[test]
    fn at_most_max() {
        let doc = format!("[{}1]", "1,".repeat(50));
        assert_eq!(args(doc.as_bytes(), 10).len(), 10);
    }
}
