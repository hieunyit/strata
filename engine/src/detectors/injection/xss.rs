//! XSS detection: a port of libinjection v3.10.0 `libinjection_xss.c`
//! (BSD-3-Clause, Copyright (c) 2012-2016 Nick Galbreath; see
//! engine/NOTICE).
//!
//! The input is tokenized as HTML5 from five starting contexts (text,
//! unquoted / single / double / back-quoted attribute value); dangerous
//! tags, attributes, URL schemes and comment forms are reported. Where the
//! C code reads past the input, the port reads a NUL byte.
#![forbid(unsafe_code)]

use super::html5::{Flags, Html5, TokenType};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attr {
    None,
    /// ban always
    Black,
    /// the value is URL-like
    Url,
    Style,
    /// the attribute *name* is given in the value
    Indirect,
}

const BLACKATTR: &[(&[u8], Attr)] = &[
    (b"ACTION", Attr::Url),
    (b"ATTRIBUTENAME", Attr::Indirect),
    (b"BY", Attr::Url),
    (b"BACKGROUND", Attr::Url),
    (b"DATAFORMATAS", Attr::Black),
    (b"DATASRC", Attr::Black),
    (b"DYNSRC", Attr::Url),
    (b"FILTER", Attr::Style),
    (b"FORMACTION", Attr::Url),
    (b"FOLDER", Attr::Url),
    (b"FROM", Attr::Url),
    (b"HANDLER", Attr::Url),
    (b"HREF", Attr::Url),
    (b"LOWSRC", Attr::Url),
    (b"POSTER", Attr::Url),
    (b"SRC", Attr::Url),
    (b"STYLE", Attr::Style),
    (b"TO", Attr::Url),
    (b"VALUES", Attr::Url),
    (b"XLINK:HREF", Attr::Url),
];

const BLACKTAG: &[&[u8]] = &[
    b"APPLET",
    b"BASE",
    b"COMMENT",
    b"EMBED",
    b"FRAME",
    b"FRAMESET",
    b"HANDLER",
    b"IFRAME",
    b"IMPORT",
    b"ISINDEX",
    b"LINK",
    b"LISTENER",
    b"META",
    b"NOSCRIPT",
    b"OBJECT",
    b"SCRIPT",
    b"STYLE",
    b"VMLFRAME",
    b"XML",
    b"XSS",
];

fn hex(c: u8) -> Option<u32> {
    (c as char).to_digit(16)
}

/// `html_decode_char_at`: (decoded value, bytes consumed); `None` for an
/// empty input.
fn html_decode_char_at(src: &[u8]) -> Option<(u32, usize)> {
    let len = src.len();
    if len == 0 {
        return None;
    }
    let at = |i: usize| src.get(i).copied().unwrap_or(0);
    if src[0] != b'&' || len < 2 {
        return Some((src[0] as u32, 1));
    }
    if src[1] != b'#' {
        // named entities: not needed here
        return Some((b'&' as u32, 1));
    }
    if at(2) == b'x' || at(2) == b'X' {
        let Some(mut val) = hex(at(3)) else {
            return Some((b'&' as u32, 1)); // "&#x?"
        };
        let mut i = 4;
        while i < len {
            let ch = src[i];
            if ch == b';' {
                return Some((val, i + 1));
            }
            let Some(d) = hex(ch) else {
                return Some((val, i));
            };
            val = val * 16 + d;
            if val > 0x1000FF {
                return Some((b'&' as u32, 1));
            }
            i += 1;
        }
        Some((val, i))
    } else {
        let ch = at(2);
        if !ch.is_ascii_digit() {
            return Some((b'&' as u32, 1));
        }
        let mut val = (ch - b'0') as u32;
        let mut i = 3;
        while i < len {
            let ch = src[i];
            if ch == b';' {
                return Some((val, i + 1));
            }
            if !ch.is_ascii_digit() {
                return Some((val, i));
            }
            val = val * 10 + (ch - b'0') as u32;
            if val > 0x1000FF {
                return Some((b'&' as u32, 1));
            }
            i += 1;
        }
        Some((val, i))
    }
}

/// `cstrcasecmp_with_null`: `a` (upper case) equals `b` ignoring NULs in
/// `b`; 0 when equal.
fn cstrcasecmp_with_null(a: &[u8], b: &[u8]) -> bool {
    let mut ai = 0;
    for &cb in b {
        if cb == 0 {
            continue;
        }
        let ca = a.get(ai).copied().unwrap_or(0);
        ai += 1;
        if ca != cb.to_ascii_uppercase() || ca == 0 && cb != 0 {
            return false;
        }
    }
    ai >= a.len()
}

/// Does HTML-encoded `b` start with upper-case `a` (case-insensitive,
/// ignoring leading blanks/control bytes, NULs and newlines)?
fn htmlencode_startswith(a: &[u8], mut b: &[u8]) -> bool {
    let mut ai = 0;
    let mut first = true;
    while !b.is_empty() {
        if ai == a.len() {
            return true;
        }
        let Some((mut cb, consumed)) = html_decode_char_at(b) else {
            break;
        };
        b = &b[consumed..];
        if first && cb <= 32 {
            continue;
        }
        first = false;
        if cb == 0 || cb == 10 {
            continue;
        }
        if (b'a' as u32..=b'z' as u32).contains(&cb) {
            cb -= 0x20;
        }
        // compared as a C `char`
        if a[ai] != cb as u8 {
            return false;
        }
        ai += 1;
    }
    ai == a.len()
}

fn is_black_tag(s: &[u8]) -> bool {
    if s.len() < 3 {
        return false;
    }
    if BLACKTAG.iter().any(|t| cstrcasecmp_with_null(t, s)) {
        return true;
    }
    // anything SVG or XSL(T)
    s[..3].eq_ignore_ascii_case(b"svg") || s[..3].eq_ignore_ascii_case(b"xsl")
}

fn is_black_attr(s: &[u8]) -> Attr {
    if s.len() < 2 {
        return Attr::None;
    }
    if s.len() >= 5 {
        // JavaScript on* handlers
        if s[..2].eq_ignore_ascii_case(b"on") {
            return Attr::Black;
        }
        // XMLNS, XLINK can create arbitrary tags
        if cstrcasecmp_with_null(b"XMLNS", &s[..5]) || cstrcasecmp_with_null(b"XLINK", &s[..5]) {
            return Attr::Black;
        }
    }
    BLACKATTR
        .iter()
        .find(|(name, _)| cstrcasecmp_with_null(name, s))
        .map_or(Attr::None, |(_, t)| *t)
}

fn is_black_url(mut s: &[u8]) -> bool {
    // skip blanks, control bytes and high-bit bytes (signed char <= 32)
    while let Some(&c) = s.first() {
        if c <= 32 || c >= 127 {
            s = &s[1..];
        } else {
            break;
        }
    }
    [&b"DATA"[..], b"VIEW-SOURCE", b"JAVA", b"VBSCRIPT"]
        .iter()
        .any(|p| htmlencode_startswith(p, s))
}

/// `libinjection_is_xss` in one starting context.
pub fn is_xss_in(s: &[u8], flags: Flags) -> bool {
    let mut h5 = Html5::new(s, flags);
    let mut attr = Attr::None;
    while h5.next_token() {
        let t = h5.token();
        if h5.token_type != TokenType::AttrValue {
            attr = Attr::None;
        }
        match h5.token_type {
            TokenType::Doctype => return true,
            TokenType::TagNameOpen => {
                if is_black_tag(t) {
                    return true;
                }
            }
            TokenType::AttrName => attr = is_black_attr(t),
            TokenType::AttrValue => {
                match attr {
                    Attr::None => {}
                    Attr::Black | Attr::Style => return true,
                    Attr::Url => {
                        if is_black_url(t) {
                            return true;
                        }
                    }
                    Attr::Indirect => {
                        if is_black_attr(t) != Attr::None {
                            return true;
                        }
                    }
                }
                attr = Attr::None;
            }
            TokenType::TagComment => {
                // IE: '`' ends a tag
                if t.contains(&b'`') {
                    return true;
                }
                // IE conditional comments, XML
                if t.len() > 3
                    && ((t[0] == b'[' && t[1..3].eq_ignore_ascii_case(b"if"))
                        || t[..3].eq_ignore_ascii_case(b"xml"))
                {
                    return true;
                }
                // IE <?import, XML entity definitions
                if t.len() > 5
                    && (cstrcasecmp_with_null(b"IMPORT", &t[..6])
                        || cstrcasecmp_with_null(b"ENTITY", &t[..6]))
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// `libinjection_xss`: XSS in any of the five contexts.
pub fn detect(s: &[u8]) -> bool {
    [
        Flags::DataState,
        Flags::ValueNoQuote,
        Flags::ValueSingleQuote,
        Flags::ValueDoubleQuote,
        Flags::ValueBackQuote,
    ]
    .into_iter()
    .any(|f| is_xss_in(s, f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attacks_and_text() {
        for x in [
            &b"<script>alert(1)</script>"[..],
            b"<img src=x onerror=alert(1)>",
            b"<a href=\"javascript:alert(1)\">x</a>",
            b"<a href=\"&#x6A;avascript:alert(1)\">",
            b"\" onmouseover=alert(1) x=\"",
            b"<svg/onload=alert(1)>",
            b"<!DOCTYPE html>",
        ] {
            assert!(detect(x), "{}", x.escape_ascii());
        }
        for x in [
            &b"hello world"[..],
            b"a < b and c > d",
            b"<b>bold</b>",
            b"O'Reilly",
            b"",
        ] {
            assert!(!detect(x), "{}", x.escape_ascii());
        }
    }

    #[test]
    fn decode_entities() {
        assert_eq!(html_decode_char_at(b"&#106;"), Some((106, 6)));
        assert_eq!(html_decode_char_at(b"&#x6a"), Some((0x6a, 5)));
        assert_eq!(html_decode_char_at(b"&#"), Some((b'&' as u32, 1)));
        assert_eq!(html_decode_char_at(b"&amp;"), Some((b'&' as u32, 1)));
    }
}
