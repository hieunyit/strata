//! Transformations, batch 1 (W05-R-01): urlDecodeUni, htmlEntityDecode,
//! lowercase, removeNulls, compressWhitespace, normalizePath; batch 2
//! (W06-S-01) in batch2.rs.
//!
//! Semantics follow Coraza v3.8.1 (and, through it, ModSecurity and Go's
//! standard library) byte for byte, so that differential runs against
//! Coraza agree; they are checked against Coraza's test vectors in
//! `engine/tests/transform_vectors.rs`. Every function is a single loop with
//! no recursion and returns `Cow::Borrowed` when nothing changes.
#![forbid(unsafe_code)]

mod batch2;
mod tables;

use std::borrow::Cow;

use crate::budget::{BudgetExceeded, TxBudget};

pub use batch2::{
    base64_decode, base64_decode_with_budget, cmd_line, cmd_line_with_budget, css_decode,
    css_decode_with_budget, js_decode, js_decode_with_budget, normalize_path_win,
    normalize_path_win_with_budget, remove_comments_char, remove_comments_char_with_budget,
    remove_whitespace, remove_whitespace_with_budget, replace_comments,
    replace_comments_with_budget, url_decode, url_decode_with_budget, utf8_to_unicode,
    utf8_to_unicode_with_budget,
};

use tables::{BEST_FIT, ENTITY, ENTITY2, LONGEST_ENTITY_WITHOUT_SEMICOLON, REPLACEMENT};

/// Codes as in `rules::TRANSFORMS`.
pub const URL_DECODE_UNI: u8 = 0;
pub const HTML_ENTITY_DECODE: u8 = 1;
pub const JS_DECODE: u8 = 2;
pub const CSS_DECODE: u8 = 3;
pub const LOWERCASE: u8 = 4;
pub const REMOVE_NULLS: u8 = 5;
pub const REMOVE_WHITESPACE: u8 = 6;
pub const COMPRESS_WHITESPACE: u8 = 7;
pub const CMD_LINE: u8 = 8;
pub const NORMALIZE_PATH: u8 = 9;
pub const UTF8_TO_UNICODE: u8 = 10;
pub const BASE64_DECODE: u8 = 11;
// Added for CRS (W06-S-01), at the end so that existing codes keep their
// meaning in bundles already built.
pub const URL_DECODE: u8 = 12;
pub const NORMALIZE_PATH_WIN: u8 = 13;
pub const REPLACE_COMMENTS: u8 = 14;
pub const REMOVE_COMMENTS_CHAR: u8 = 15;
/// The byte length of the value, in decimal (for numeric operators).
pub const LENGTH: u8 = 16;

/// Applies one transformation with cooperative CPU budget tracking;
/// `Ok(None)` when this engine does not implement it yet (condition skipped).
pub fn apply_with_budget<'a>(
    code: u8,
    input: &'a [u8],
    budget: Option<&mut TxBudget>,
) -> Result<Option<Cow<'a, [u8]>>, BudgetExceeded> {
    Ok(Some(match code {
        URL_DECODE_UNI => url_decode_uni_with_budget(input, budget)?,
        HTML_ENTITY_DECODE => html_entity_decode_with_budget(input, budget)?,
        LOWERCASE => lowercase_with_budget(input, budget)?,
        REMOVE_NULLS => remove_nulls_with_budget(input, budget)?,
        COMPRESS_WHITESPACE => compress_whitespace_with_budget(input, budget)?,
        NORMALIZE_PATH => normalize_path_with_budget(input, budget)?,
        JS_DECODE => js_decode_with_budget(input, budget)?,
        CSS_DECODE => css_decode_with_budget(input, budget)?,
        REMOVE_WHITESPACE => remove_whitespace_with_budget(input, budget)?,
        CMD_LINE => cmd_line_with_budget(input, budget)?,
        UTF8_TO_UNICODE => utf8_to_unicode_with_budget(input, budget)?,
        BASE64_DECODE => base64_decode_with_budget(input, budget)?,
        URL_DECODE => url_decode_with_budget(input, budget)?,
        NORMALIZE_PATH_WIN => normalize_path_win_with_budget(input, budget)?,
        REPLACE_COMMENTS => replace_comments_with_budget(input, budget)?,
        REMOVE_COMMENTS_CHAR => remove_comments_char_with_budget(input, budget)?,
        LENGTH => Cow::Owned(input.len().to_string().into_bytes()),
        _ => return Ok(None),
    }))
}

/// Applies one transformation without budget tracking.
pub fn apply(code: u8, input: &[u8]) -> Option<Cow<'_, [u8]>> {
    apply_with_budget(code, input, None).ok().flatten()
}

/// Applies a chain left to right with cooperative CPU budget tracking;
/// `Ok(None)` if one of them is not implemented.
pub fn apply_chain_with_budget<'a>(
    codes: &[u8],
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Option<Cow<'a, [u8]>>, BudgetExceeded> {
    if codes.is_empty() {
        return Ok(Some(Cow::Borrowed(input)));
    }
    if codes.len() == 1 {
        return apply_with_budget(codes[0], input, budget);
    }
    let mut cur = Cow::Borrowed(input);
    for &c in codes {
        cur = match cur {
            Cow::Borrowed(b) => match apply_with_budget(c, b, budget.as_deref_mut())? {
                Some(res) => res,
                None => return Ok(None),
            },
            Cow::Owned(o) => match apply_with_budget(c, &o, budget.as_deref_mut())? {
                Some(res) => Cow::Owned(res.into_owned()),
                None => return Ok(None),
            },
        };
    }
    Ok(Some(cur))
}

/// Applies a chain left to right; `None` if one of them is not implemented.
pub fn apply_chain<'a>(codes: &[u8], input: &'a [u8]) -> Option<Cow<'a, [u8]>> {
    apply_chain_with_budget(codes, input, None).ok().flatten()
}

pub fn is_implemented(code: u8) -> bool {
    code <= LENGTH
}

pub(crate) fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// `%XX`, `%uXXXX` (IIS, with ModSecurity's best-fit table) and `+`.
/// Invalid or truncated escapes are copied as they are.
pub fn url_decode_uni_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let Some(first) = input.iter().position(|&c| c == b'%' || c == b'+') else {
        return Ok(Cow::Borrowed(input));
    };
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..first]);
    let n = input.len();
    let mut i = first;
    let mut next_check = 8192;
    while i < n {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        let ch = input[i];
        if ch == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        if ch != b'%' {
            out.push(ch);
            i += 1;
            continue;
        }
        if i + 1 < n && (input[i + 1] == b'u' || input[i + 1] == b'U') {
            if i + 5 < n
                && let (Some(h2), Some(h3), Some(h4), Some(h5)) = (
                    hex(input[i + 2]),
                    hex(input[i + 3]),
                    hex(input[i + 4]),
                    hex(input[i + 5]),
                )
            {
                let code =
                    u32::from(h2) << 12 | u32::from(h3) << 8 | u32::from(h4) << 4 | u32::from(h5);
                let b = match BEST_FIT.binary_search_by_key(&code, |&(cp, _)| cp) {
                    Ok(k) => BEST_FIT[k].1,
                    Err(_) => {
                        // lower byte; fullwidth ASCII (ff01-ff5e) needs 0x20 added
                        let mut low = h4 << 4 | h5;
                        if low > 0x00 && low < 0x5f && h2 == 15 && h3 == 15 {
                            low += 0x20;
                        }
                        low
                    }
                };
                out.push(b);
                i += 6;
                continue;
            }
            out.extend_from_slice(&input[i..i + 2]);
            i += 2;
            continue;
        }
        if i + 2 < n
            && let (Some(h1), Some(h2)) = (hex(input[i + 1]), hex(input[i + 2]))
        {
            out.push(h1 << 4 | h2);
            i += 3;
            continue;
        }
        out.push(b'%');
        i += 1;
    }
    if out == input {
        Ok(Cow::Borrowed(input))
    } else {
        Ok(Cow::Owned(out))
    }
}

pub fn url_decode_uni(input: &[u8]) -> Cow<'_, [u8]> {
    url_decode_uni_with_budget(input, None).unwrap()
}

fn push_char(out: &mut Vec<u8>, cp: u32) {
    let c = char::from_u32(cp).unwrap_or('\u{FFFD}');
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

fn entity(name: &[u8]) -> Option<u32> {
    ENTITY
        .binary_search_by(|(n, _)| n.as_bytes().cmp(name))
        .ok()
        .map(|k| ENTITY[k].1)
}

fn entity2(name: &[u8]) -> Option<(u32, u32)> {
    ENTITY2
        .binary_search_by(|(n, _, _)| n.as_bytes().cmp(name))
        .ok()
        .map(|k| (ENTITY2[k].1, ENTITY2[k].2))
}

/// One character reference at `s[0] == '&'` (Go's unescapeEntity, text
/// content): (first code point, optional second, bytes consumed); consumed
/// 1 with '&' means "not a reference".
fn html_entity(s: &[u8]) -> (u32, u32, usize) {
    let not = (u32::from(b'&'), 0, 1);
    if s.len() <= 1 {
        return not;
    }
    let mut i = 1;
    if s[1] == b'#' {
        if s.len() <= 2 {
            return not;
        }
        i = 2;
        let is_hex = s[2] == b'x' || s[2] == b'X';
        if is_hex {
            i += 1;
        }
        let start = i;
        let mut x: u32 = 0;
        while i < s.len() {
            let d = if is_hex {
                hex(s[i])
            } else {
                s[i].is_ascii_digit().then(|| s[i] - b'0')
            };
            let Some(d) = d else { break };
            if x <= 0x10FFFF {
                x = x * if is_hex { 16 } else { 10 } + u32::from(d);
            }
            i += 1;
        }
        if i == start {
            return not;
        }
        if i < s.len() && s[i] == b';' {
            i += 1;
        }
        let x = if (0x80..=0x9F).contains(&x) {
            REPLACEMENT[(x - 0x80) as usize]
        } else if x == 0 || (0xD800..=0xDFFF).contains(&x) || x > 0x10FFFF {
            0xFFFD
        } else {
            x
        };
        return (x, 0, i);
    }

    // longest run of [A-Za-z0-9], plus a ';' if it ends there
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c.is_ascii_alphanumeric() {
            continue;
        }
        if c != b';' {
            i -= 1;
        }
        break;
    }
    let name = &s[1..i];
    if name.is_empty() {
        return not;
    }
    if let Some(x) = entity(name) {
        return (x, 0, i);
    }
    if let Some((a, b)) = entity2(name) {
        return (a, b, i);
    }
    let max_len = (name.len() - 1).min(LONGEST_ENTITY_WITHOUT_SEMICOLON);
    for j in (2..=max_len).rev() {
        if let Some(x) = entity(&name[..j]) {
            return (x, 0, j + 1);
        }
    }
    not
}

/// HTML character references, as Go's `html.UnescapeString` (Coraza).
pub fn html_entity_decode_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let Some(first) = input.iter().position(|&c| c == b'&') else {
        return Ok(Cow::Borrowed(input));
    };
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..first]);
    let mut src = first;
    let mut next_check = 8192;
    while src < input.len() {
        if src >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = src + 8192;
        }
        if input[src] != b'&' {
            out.push(input[src]);
            src += 1;
            continue;
        }
        let (r1, r2, used) = html_entity(&input[src..]);
        if used == 1 && r1 == u32::from(b'&') {
            out.push(b'&');
            src += 1;
            continue;
        }
        push_char(&mut out, r1);
        if r2 != 0 {
            push_char(&mut out, r2);
        }
        src += used;
    }
    if out == input {
        Ok(Cow::Borrowed(input))
    } else {
        Ok(Cow::Owned(out))
    }
}

pub fn html_entity_decode(input: &[u8]) -> Cow<'_, [u8]> {
    html_entity_decode_with_budget(input, None).unwrap()
}

/// Decodes one UTF-8 sequence like Go's `utf8.DecodeRune`: invalid input
/// gives (U+FFFD, 1).
pub(crate) fn decode_rune(b: &[u8]) -> (u32, usize) {
    let len = match b[0] {
        0x00..=0x7F => return (u32::from(b[0]), 1),
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return (0xFFFD, 1),
    };
    match b.get(..len).map(std::str::from_utf8) {
        Some(Ok(s)) => (s.chars().next().map_or(0xFFFD, u32::from), len),
        _ => (0xFFFD, 1),
    }
}

/// Unicode lowercase, as Go's `strings.ToLower` (Coraza): ASCII fast path;
/// otherwise simple case mapping per rune, invalid UTF-8 becomes U+FFFD.
pub fn lowercase_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let n = input.len();
    let mut i = 0;
    let mut next_check = 8192;

    // Fast path: find first byte that is non-ASCII or uppercase ASCII
    while i < n {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        let b = input[i];
        if b >= 0x80 || b.is_ascii_uppercase() {
            break;
        }
        i += 1;
    }

    if i == n {
        return Ok(Cow::Borrowed(input));
    }

    if input[i] < 0x80 && input[i..].is_ascii() {
        let mut out = Vec::with_capacity(n);
        out.extend_from_slice(&input[..i]);
        while i < n {
            if i >= next_check {
                if let Some(bgt) = budget.as_deref_mut() {
                    bgt.check()?;
                }
                next_check = i + 8192;
            }
            out.push(input[i].to_ascii_lowercase());
            i += 1;
        }
        return Ok(Cow::Owned(out));
    }

    let mut out = Vec::with_capacity(n);
    out.extend_from_slice(&input[..i]);
    while i < n {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        let (r, w) = decode_rune(&input[i..]);
        let lower = match char::from_u32(r) {
            // simple mapping: one code point (Go has no special casing here)
            Some('\u{130}') => 'i',
            Some(c) => {
                let mut l = c.to_lowercase();
                match (l.next(), l.next()) {
                    (Some(x), None) => x,
                    _ => c,
                }
            }
            None => '\u{FFFD}',
        };
        push_char(&mut out, u32::from(lower));
        i += w;
    }
    if out == input {
        Ok(Cow::Borrowed(input))
    } else {
        Ok(Cow::Owned(out))
    }
}

pub fn lowercase(input: &[u8]) -> Cow<'_, [u8]> {
    lowercase_with_budget(input, None).unwrap()
}

pub fn remove_nulls_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    if input.len() >= 8192
        && let Some(bgt) = budget.as_mut()
    {
        bgt.check()?;
    }
    if input.contains(&0) {
        Ok(Cow::Owned(
            input.iter().copied().filter(|&c| c != 0).collect(),
        ))
    } else {
        Ok(Cow::Borrowed(input))
    }
}

pub fn remove_nulls(input: &[u8]) -> Cow<'_, [u8]> {
    remove_nulls_with_budget(input, None).unwrap()
}

/// Runs of Latin whitespace (\t \n \v \f \r space, U+0085, U+00A0, and a
/// raw 0xA0 byte) become one space, decoding runes like Coraza.
pub fn compress_whitespace_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let is_space = |r: u32, b: u8| matches!(r, 0x09..=0x0D | 0x20 | 0x85 | 0xA0) || b == 0xA0;
    let mut i = 0;
    let mut first = None;
    let mut next_check = 8192;
    while i < input.len() {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        let (r, w) = decode_rune(&input[i..]);
        if is_space(r, input[i]) {
            first = Some(i);
            break;
        }
        i += w;
    }
    let Some(first) = first else {
        return Ok(Cow::Borrowed(input));
    };
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..first]);
    let mut in_space = false;
    let mut i = first;
    next_check = i + 8192;
    while i < input.len() {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        let (r, w) = decode_rune(&input[i..]);
        if is_space(r, input[i]) {
            if !in_space {
                in_space = true;
                out.push(b' ');
            }
        } else {
            in_space = false;
            out.extend_from_slice(&input[i..i + w]);
        }
        i += w;
    }
    if out == input {
        Ok(Cow::Borrowed(input))
    } else {
        Ok(Cow::Owned(out))
    }
}

pub fn compress_whitespace(input: &[u8]) -> Cow<'_, [u8]> {
    compress_whitespace_with_budget(input, None).unwrap()
}

/// Go's `path.Clean` (lexical: "//", "/./", "/x/../"), as `filepath.Clean`
/// on Unix.
fn clean(path: &[u8], mut budget: Option<&mut TxBudget>) -> Result<Vec<u8>, BudgetExceeded> {
    if path.is_empty() {
        return Ok(b".".to_vec());
    }
    let rooted = path[0] == b'/';
    let n = path.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let (mut r, mut dotdot) = (0, 0);
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }
    let mut next_check = 8192;
    while r < n {
        if r >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = r + 8192;
        }
        if path[r] == b'/' || (path[r] == b'.' && (r + 1 == n || path[r + 1] == b'/')) {
            r += 1;
        } else if path[r] == b'.' && path[r + 1] == b'.' && (r + 2 == n || path[r + 2] == b'/') {
            r += 2;
            if out.len() > dotdot {
                // back to the last '/', which is dropped too (Go's out.w)
                let mut w = out.len() - 1;
                while w > dotdot && out[w] != b'/' {
                    w -= 1;
                }
                out.truncate(w);
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && path[r] != b'/' {
                out.push(path[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        return Ok(b".".to_vec());
    }
    Ok(out)
}

/// Coraza's normalisePath: `filepath.Clean`, "." becomes empty, and a
/// trailing '/' of the input is kept.
pub fn normalize_path_with_budget<'a>(
    input: &'a [u8],
    budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    if input.is_empty() {
        return Ok(Cow::Borrowed(input));
    }
    let mut c = clean(input, budget)?;
    if c == b"." {
        return if input.is_empty() {
            Ok(Cow::Borrowed(input))
        } else {
            Ok(Cow::Owned(vec![]))
        };
    }
    if input[input.len() - 1] == b'/' {
        c.push(b'/');
    }
    if c == input {
        Ok(Cow::Borrowed(input))
    } else {
        Ok(Cow::Owned(c))
    }
}

pub fn normalize_path(input: &[u8]) -> Cow<'_, [u8]> {
    normalize_path_with_budget(input, None).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transform_borrows_when_unchanged() {
        for (code, s) in [
            (URL_DECODE_UNI, &b"/plain/path"[..]),
            (HTML_ENTITY_DECODE, b"no entities"),
            (LOWERCASE, b"lower"),
            (REMOVE_NULLS, b"abc"),
            (COMPRESS_WHITESPACE, b"a b"),
            (NORMALIZE_PATH, b"/a/b"),
        ] {
            assert!(
                matches!(apply(code, s), Some(Cow::Borrowed(_))),
                "code {code}"
            );
        }
    }

    #[test]
    fn transform_chain_and_unimplemented() {
        let out = apply_chain(
            &[URL_DECODE_UNI, LOWERCASE, NORMALIZE_PATH],
            b"/A/%2E%2E/B%2f./C",
        )
        .unwrap();
        assert_eq!(&*out, b"/b/c");
        // a code past the table: not implemented, the condition is skipped
        assert!(apply_chain(&[URL_DECODE_UNI, LENGTH + 1], b"x").is_none());
    }

    #[test]
    fn transform_html_entities() {
        assert_eq!(&*html_entity_decode(b"&lt;script&gt;"), b"<script>");
        assert_eq!(&*html_entity_decode(b"&#x3c;&#60;&#X3C"), b"<<<");
        assert_eq!(
            &*html_entity_decode(b"&ampx &notit; &zzz;"),
            "&x ¬it; &zzz;".as_bytes()
        );
        assert_eq!(&*html_entity_decode(b"&#128;&#0;"), "€\u{FFFD}".as_bytes());
        assert_eq!(
            &*html_entity_decode(b"&NotEqualTilde;"),
            "\u{2242}\u{338}".as_bytes()
        );
    }

    #[test]
    fn transform_url_decode_uni_iis_and_best_fit() {
        assert_eq!(&*url_decode_uni(b"%u0041%uff1c%u2018"), b"A<'");
        assert_eq!(&*url_decode_uni(b"a+b%zz%"), b"a b%zz%");
        assert_eq!(&*url_decode_uni(b"%u12"), b"%u12");
    }

    #[test]
    fn transform_boundary_8192_straddling() {
        // &amp; straddling byte 8192 (starts at 8190, ends at 8195)
        let mut input_html = vec![b'a'; 8190];
        input_html.extend_from_slice(b"&amp;b");
        let decoded_no_budget = html_entity_decode(&input_html);
        let mut budget = TxBudget::new(100_000);
        let _ = budget.enter();
        let decoded_with_budget =
            html_entity_decode_with_budget(&input_html, Some(&mut budget)).unwrap();
        assert_eq!(decoded_no_budget, decoded_with_budget);
        assert_eq!(&decoded_with_budget[8190..], b"&b");

        // \u0041 straddling byte 8192 (starts at 8190, ends at 8196)
        let mut input_js = vec![b'a'; 8190];
        input_js.extend_from_slice(b"\\u0041b");
        let decoded_js_no_budget = js_decode(&input_js);
        let mut budget_js = TxBudget::new(100_000);
        let _ = budget_js.enter();
        let decoded_js_with_budget =
            js_decode_with_budget(&input_js, Some(&mut budget_js)).unwrap();
        assert_eq!(decoded_js_no_budget, decoded_js_with_budget);
        assert_eq!(&decoded_js_with_budget[8190..], b"Ab");
    }

    #[test]
    fn transform_lowercase_budget_chunks() {
        // 1. Existing vectors: matches lowercase()
        for s in [
            &b""[..],
            b"abc",
            b"ABC",
            b"AbCdEf",
            b"Hello World!",
            "Tiếng Việt".as_bytes(),
            "TIẾNG VIỆT".as_bytes(),
            b"\x80\xFF",
        ] {
            let expected = lowercase(s);
            let with_budget = lowercase_with_budget(s, None).unwrap();
            assert_eq!(expected, with_budget, "mismatch on {:?}", s);
            if !s.iter().any(u8::is_ascii_uppercase) && s.is_ascii() {
                assert!(matches!(with_budget, Cow::Borrowed(_)));
            }
        }

        // 2. Small budget on 8 MiB ASCII returns BudgetExceeded
        let big_ascii = vec![b'a'; 8 << 20];
        let mut budget = TxBudget::new(10); // 10 µs budget
        let _ = budget.enter();
        std::thread::sleep(std::time::Duration::from_micros(100)); // ensure budget is expired
        let res = lowercase_with_budget(&big_ascii, Some(&mut budget));
        assert!(matches!(res, Err(BudgetExceeded)));

        // 3. Small budget on 8 MiB ASCII with uppercase also returns BudgetExceeded
        let mut big_ascii_upper = vec![b'a'; 8 << 20];
        big_ascii_upper[10_000] = b'A';
        let mut budget2 = TxBudget::new(10);
        let _ = budget2.enter();
        std::thread::sleep(std::time::Duration::from_micros(100));
        let res2 = lowercase_with_budget(&big_ascii_upper, Some(&mut budget2));
        assert!(matches!(res2, Err(BudgetExceeded)));
    }
}
