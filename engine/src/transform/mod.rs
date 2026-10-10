//! Transformations, batch 1 (W05-R-01): urlDecodeUni, htmlEntityDecode,
//! lowercase, removeNulls, compressWhitespace, normalizePath.
//!
//! Semantics follow Coraza v3.8.1 (and, through it, ModSecurity and Go's
//! standard library) byte for byte, so that differential runs against
//! Coraza agree; they are checked against Coraza's test vectors in
//! `engine/tests/transform_vectors.rs`. Every function is a single loop with
//! no recursion and returns `Cow::Borrowed` when nothing changes.
#![forbid(unsafe_code)]

mod tables;

use std::borrow::Cow;

use tables::{BEST_FIT, ENTITY, ENTITY2, LONGEST_ENTITY_WITHOUT_SEMICOLON, REPLACEMENT};

/// Codes as in `rules::TRANSFORMS`.
pub const URL_DECODE_UNI: u8 = 0;
pub const HTML_ENTITY_DECODE: u8 = 1;
pub const LOWERCASE: u8 = 4;
pub const REMOVE_NULLS: u8 = 5;
pub const COMPRESS_WHITESPACE: u8 = 7;
pub const NORMALIZE_PATH: u8 = 9;

/// Applies one transformation; `None` when this engine does not implement
/// it yet (the condition using it is then skipped).
pub fn apply(code: u8, input: &[u8]) -> Option<Cow<'_, [u8]>> {
    Some(match code {
        URL_DECODE_UNI => url_decode_uni(input),
        HTML_ENTITY_DECODE => html_entity_decode(input),
        LOWERCASE => lowercase(input),
        REMOVE_NULLS => remove_nulls(input),
        COMPRESS_WHITESPACE => compress_whitespace(input),
        NORMALIZE_PATH => normalize_path(input),
        _ => return None,
    })
}

/// Applies a chain left to right; `None` if one of them is not implemented.
pub fn apply_chain<'a>(codes: &[u8], input: &'a [u8]) -> Option<Cow<'a, [u8]>> {
    let mut cur = Cow::Borrowed(input);
    for &c in codes {
        cur = match cur {
            Cow::Borrowed(b) => apply(c, b)?,
            Cow::Owned(o) => Cow::Owned(apply(c, &o)?.into_owned()),
        };
    }
    Some(cur)
}

pub fn is_implemented(code: u8) -> bool {
    matches!(
        code,
        URL_DECODE_UNI
            | HTML_ENTITY_DECODE
            | LOWERCASE
            | REMOVE_NULLS
            | COMPRESS_WHITESPACE
            | NORMALIZE_PATH
    )
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// `%XX`, `%uXXXX` (IIS, with ModSecurity's best-fit table) and `+`.
/// Invalid or truncated escapes are copied as they are.
pub fn url_decode_uni(input: &[u8]) -> Cow<'_, [u8]> {
    let Some(first) = input.iter().position(|&c| c == b'%' || c == b'+') else {
        return Cow::Borrowed(input);
    };
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..first]);
    let n = input.len();
    let mut i = first;
    while i < n {
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
        Cow::Borrowed(input)
    } else {
        Cow::Owned(out)
    }
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
pub fn html_entity_decode(input: &[u8]) -> Cow<'_, [u8]> {
    let Some(first) = input.iter().position(|&c| c == b'&') else {
        return Cow::Borrowed(input);
    };
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..first]);
    let mut src = first;
    while src < input.len() {
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
        Cow::Borrowed(input)
    } else {
        Cow::Owned(out)
    }
}

/// Decodes one UTF-8 sequence like Go's `utf8.DecodeRune`: invalid input
/// gives (U+FFFD, 1).
fn decode_rune(b: &[u8]) -> (u32, usize) {
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
pub fn lowercase(input: &[u8]) -> Cow<'_, [u8]> {
    if input.is_ascii() {
        if !input.iter().any(u8::is_ascii_uppercase) {
            return Cow::Borrowed(input);
        }
        return Cow::Owned(input.to_ascii_lowercase());
    }
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
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
        Cow::Borrowed(input)
    } else {
        Cow::Owned(out)
    }
}

pub fn remove_nulls(input: &[u8]) -> Cow<'_, [u8]> {
    if input.contains(&0) {
        Cow::Owned(input.iter().copied().filter(|&c| c != 0).collect())
    } else {
        Cow::Borrowed(input)
    }
}

/// Runs of Latin whitespace (\t \n \v \f \r space, U+0085, U+00A0, and a
/// raw 0xA0 byte) become one space, decoding runes like Coraza.
pub fn compress_whitespace(input: &[u8]) -> Cow<'_, [u8]> {
    let is_space = |r: u32, b: u8| matches!(r, 0x09..=0x0D | 0x20 | 0x85 | 0xA0) || b == 0xA0;
    let mut i = 0;
    let mut first = None;
    while i < input.len() {
        let (r, w) = decode_rune(&input[i..]);
        if is_space(r, input[i]) {
            first = Some(i);
            break;
        }
        i += w;
    }
    let Some(first) = first else {
        return Cow::Borrowed(input);
    };
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..first]);
    let mut in_space = false;
    let mut i = first;
    while i < input.len() {
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
        Cow::Borrowed(input)
    } else {
        Cow::Owned(out)
    }
}

/// Go's `path.Clean` (lexical: "//", "/./", "/x/../"), as `filepath.Clean`
/// on Unix.
fn clean(path: &[u8]) -> Vec<u8> {
    if path.is_empty() {
        return b".".to_vec();
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
    while r < n {
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
        return b".".to_vec();
    }
    out
}

/// Coraza's normalisePath: `filepath.Clean`, "." becomes empty, and a
/// trailing '/' of the input is kept.
pub fn normalize_path(input: &[u8]) -> Cow<'_, [u8]> {
    if input.is_empty() {
        return Cow::Borrowed(input);
    }
    let mut c = clean(input);
    if c == b"." {
        return if input.is_empty() {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(vec![])
        };
    }
    if input[input.len() - 1] == b'/' {
        c.push(b'/');
    }
    if c == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(c)
    }
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
        assert!(apply_chain(&[URL_DECODE_UNI, 2 /* js_decode */], b"x").is_none());
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
}
