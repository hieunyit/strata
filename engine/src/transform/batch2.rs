//! Transformations, batch 2 (W06-S-01): jsDecode, cssDecode,
//! removeWhitespace, cmdLine, utf8toUnicode, base64Decode, and four more
//! that CRS paranoia level 1 rules use: urlDecode, normalizePathWin,
//! replaceComments, removeCommentsChar. Ported from Coraza v3.8.1
//! (internal/transformations), checked against its test vectors. Single
//! loops, no recursion, `Cow::Borrowed` when nothing changes.
#![forbid(unsafe_code)]

use std::borrow::Cow;

use crate::budget::{BudgetExceeded, TxBudget};

use super::{decode_rune, hex, normalize_path_with_budget};

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// Value of two hex digits (both valid).
fn x2c(a: u8, b: u8) -> u8 {
    hex(a).unwrap_or(0) << 4 | hex(b).unwrap_or(0)
}

/// jsDecode: \uHHHH (lower byte, full-width ASCII folded), \u{H..H},
/// \xHH, \OOO, \C.
pub fn js_decode_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let Some(pos) = input.iter().position(|&c| c == b'\\') else {
        return Ok(Cow::Borrowed(input));
    };
    let n = input.len();
    let mut d = input[..pos].to_vec();
    let mut i = pos;
    let mut next_check = 8192;
    while i < n {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        if input[i] != b'\\' {
            d.push(input[i]);
            i += 1;
            continue;
        }
        // \u{H...H}: 1-6 hex digits then '}'
        let mut ext = 0;
        if i + 2 < n && input[i + 1] == b'u' && input[i + 2] == b'{' {
            let p = i + 3;
            let mut j = 0;
            while j < 6 && p + j < n && is_hex(input[p + j]) {
                j += 1;
            }
            if j > 0 && p + j < n && input[p + j] == b'}' {
                ext = j;
            }
        }
        if ext > 0 {
            let mut code: u32 = 0;
            for k in 0..ext {
                code = code << 4 | u32::from(hex(input[i + 3 + k]).unwrap_or(0));
            }
            let mut b = code as u8;
            if (0xff01..=0xff5e).contains(&code) {
                b = b.wrapping_add(0x20);
            }
            d.push(b);
            i += ext + 4;
        } else if i + 5 < n
            && input[i + 1] == b'u'
            && input[i + 2..i + 6].iter().all(|&c| is_hex(c))
        {
            let mut b = x2c(input[i + 4], input[i + 5]);
            if b > 0 && b < 0x5f && (input[i + 2] | 0x20) == b'f' && (input[i + 3] | 0x20) == b'f' {
                b += 0x20;
            }
            d.push(b);
            i += 6;
        } else if i + 3 < n && input[i + 1] == b'x' && is_hex(input[i + 2]) && is_hex(input[i + 3])
        {
            d.push(x2c(input[i + 2], input[i + 3]));
            i += 4;
        } else if i + 1 < n && (b'0'..=b'7').contains(&input[i + 1]) {
            let mut j = 0;
            while i + 1 + j < n && j < 3 {
                j += 1;
                if i + 1 + j >= n || !(b'0'..=b'7').contains(&input[i + 1 + j]) {
                    break;
                }
            }
            if j == 3 && input[i + 1] > b'3' {
                j = 2;
            }
            let mut v: u32 = 0;
            for k in 0..j {
                v = v * 8 + u32::from(input[i + 1 + k] - b'0');
            }
            d.push(v as u8);
            i += 1 + j;
        } else if i + 1 < n {
            d.push(match input[i + 1] {
                b'a' => 7,
                b'b' => 8,
                b'f' => 12,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'v' => 11,
                c => c,
            });
            i += 2;
        } else {
            d.extend_from_slice(&input[i..]);
            i = n;
        }
    }
    Ok(Cow::Owned(d))
}

pub fn js_decode(input: &[u8]) -> Cow<'_, [u8]> {
    js_decode_with_budget(input, None).unwrap()
}

fn css_space(c: u8) -> bool {
    matches!(c, b' ' | 12 | b'\n' | b'\t' | b'\r' | 11)
}

/// cssDecode: \H..H (1-6 hex digits, one code point, UTF-8, full-width
/// ASCII folded, 0 -> U+FFFD, one following whitespace eaten), \newline
/// dropped, \C -> C.
pub fn css_decode_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let Some(pos) = input.iter().position(|&c| c == b'\\') else {
        return Ok(Cow::Borrowed(input));
    };
    let n = input.len();
    let mut d = input[..pos].to_vec();
    let mut i = pos;
    let mut next_check = 8192;
    while i < n {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        if input[i] != b'\\' {
            d.push(input[i]);
            i += 1;
            continue;
        }
        if i + 1 >= n {
            i += 1; // a trailing backslash is dropped
            continue;
        }
        i += 1;
        let mut j = 0;
        while j < 6 && i + j < n && is_hex(input[i + j]) {
            j += 1;
        }
        if j > 0 {
            let mut code: u32 = 0;
            for k in 0..j {
                code = code << 4 | u32::from(hex(input[i + k]).unwrap_or(0));
            }
            if code == 0 {
                code = 0xFFFD;
            }
            if (0xff01..=0xff5e).contains(&code) {
                code -= 0xfee0;
            }
            let ch = char::from_u32(code).unwrap_or('\u{FFFD}');
            d.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
            if i + j < n && css_space(input[i + j]) {
                j += 1;
            }
            i += j;
        } else if input[i] == b'\n' {
            i += 1;
        } else {
            d.push(input[i]);
            i += 1;
        }
    }
    Ok(Cow::Owned(d))
}

pub fn css_decode(input: &[u8]) -> Cow<'_, [u8]> {
    css_decode_with_budget(input, None).unwrap()
}

/// removeWhitespace: drops Unicode white space (Go's unicode.IsSpace).
pub fn remove_whitespace_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    let mut next_check = 8192;
    while i < input.len() {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        let (cp, len) = decode_rune(&input[i..]);
        let space =
            char::from_u32(cp).is_some_and(char::is_whitespace) && !(cp == 0xFFFD && len == 1);
        if space {
            out.get_or_insert_with(|| input[..i].to_vec());
        } else if let Some(o) = out.as_mut() {
            o.extend_from_slice(&input[i..i + len]);
        }
        i += len;
    }
    Ok(out.map_or(Cow::Borrowed(input), Cow::Owned))
}

pub fn remove_whitespace(input: &[u8]) -> Cow<'_, [u8]> {
    remove_whitespace_with_budget(input, None).unwrap()
}

/// cmdLine: drops \ " ' ^, turns , ; and white space into one space, drops
/// a space before / or (, lowercases ASCII.
pub fn cmd_line_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let needs = |c: u8| {
        c.is_ascii_uppercase()
            || matches!(
                c,
                b'"' | b'\''
                    | b'\\'
                    | b'^'
                    | b' '
                    | b','
                    | b';'
                    | b'\t'
                    | b'\r'
                    | b'\n'
                    | b'/'
                    | b'('
            )
    };
    let Some(pos) = input.iter().position(|&c| needs(c)) else {
        return Ok(Cow::Borrowed(input));
    };
    let mut ret = input[..pos].to_vec();
    let mut changed = false;
    let mut space = false;
    let mut next_check = pos + 8192;
    for (offset, &a) in input[pos..].iter().enumerate() {
        let curr = pos + offset;
        if curr >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = curr + 8192;
        }
        match a {
            b'"' | b'\'' | b'\\' | b'^' => changed = true,
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !space {
                    changed |= a != b' ';
                    ret.push(b' ');
                    space = true;
                } else {
                    changed = true;
                }
            }
            b'/' | b'(' => {
                if space {
                    ret.pop();
                    changed = true;
                }
                space = false;
                ret.push(a);
            }
            _ => {
                changed |= a.is_ascii_uppercase();
                ret.push(a.to_ascii_lowercase());
                space = false;
            }
        }
    }
    if changed {
        Ok(Cow::Owned(ret))
    } else {
        Ok(Cow::Borrowed(input))
    }
}

pub fn cmd_line(input: &[u8]) -> Cow<'_, [u8]> {
    cmd_line_with_budget(input, None).unwrap()
}

/// utf8toUnicode: every non-ASCII code point as %uHHHH (lowercase hex, at
/// least 4 digits); invalid bytes count as U+FFFD, as in Go.
pub fn utf8_to_unicode_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let Some(pos) = input.iter().position(|&c| c >= 0x80) else {
        return Ok(Cow::Borrowed(input));
    };
    let mut out = input[..pos].to_vec();
    let mut i = pos;
    let mut next_check = 8192;
    while i < input.len() {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        let (cp, len) = decode_rune(&input[i..]);
        if cp < 0x80 {
            out.push(cp as u8);
        } else {
            out.extend_from_slice(format!("%u{cp:04x}").as_bytes());
        }
        i += len;
    }
    Ok(Cow::Owned(out))
}

pub fn utf8_to_unicode(input: &[u8]) -> Cow<'_, [u8]> {
    utf8_to_unicode_with_budget(input, None).unwrap()
}

const B64: [u8; 128] = {
    let mut t = [127u8; 128];
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0;
    while i < 64 {
        t[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    t[b'=' as usize] = 64;
    t
};

/// base64Decode: optional padding, \r \n ignored, '=' or ' ' ends, an
/// invalid character ends with what was decoded so far.
pub fn base64_decode_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    if input.is_empty() {
        return Ok(Cow::Borrowed(input));
    }
    let mut out = Vec::with_capacity(input.len());
    let (mut x, mut n) = (0u32, 0);
    let mut next_check = 8192;
    for (i, &c) in input.iter().enumerate() {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        if c == b'\r' || c == b'\n' {
            continue;
        }
        if c == b'=' || c == b' ' {
            break;
        }
        let v = if c < 128 { B64[c as usize] } else { 127 };
        if v == 127 {
            break;
        }
        x = x << 6 | u32::from(v & 0x3f);
        n += 1;
        if n == 4 {
            out.extend_from_slice(&[(x >> 16) as u8, (x >> 8) as u8, x as u8]);
            (x, n) = (0, 0);
        }
    }
    match n {
        2 => out.push((x << 12 >> 16) as u8),
        3 => {
            let y = x << 6;
            out.extend_from_slice(&[(y >> 16) as u8, (y >> 8) as u8]);
        }
        _ => {}
    }
    Ok(Cow::Owned(out))
}

pub fn base64_decode(input: &[u8]) -> Cow<'_, [u8]> {
    base64_decode_with_budget(input, None).unwrap()
}

/// urlDecode: %HH and '+' (no %u, unlike urlDecodeUni).
pub fn url_decode_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let Some(pos) = input.iter().position(|&c| c == b'%' || c == b'+') else {
        return Ok(Cow::Borrowed(input));
    };
    let n = input.len();
    let mut d = input[..pos].to_vec();
    let mut i = pos;
    let mut next_check = 8192;
    while i < n {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        match input[i] {
            b'%' if i + 2 < n && is_hex(input[i + 1]) && is_hex(input[i + 2]) => {
                d.push(x2c(input[i + 1], input[i + 2]));
                i += 3;
            }
            b'+' => {
                d.push(b' ');
                i += 1;
            }
            c => {
                d.push(c);
                i += 1;
            }
        }
    }
    Ok(Cow::Owned(d))
}

pub fn url_decode(input: &[u8]) -> Cow<'_, [u8]> {
    url_decode_with_budget(input, None).unwrap()
}

/// normalizePathWin: backslashes become slashes, normalizePath, then the
/// Windows rules: an alternate data stream suffix of the last component
/// and trailing dots and spaces of every component are dropped.
pub fn normalize_path_win_with_budget<'a>(
    input: &'a [u8],
    budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    if input.is_empty() {
        return Ok(Cow::Borrowed(input));
    }
    let slashed: Vec<u8> = input
        .iter()
        .map(|&c| if c == b'\\' { b'/' } else { c })
        .collect();
    let clean = normalize_path_with_budget(&slashed, budget)?.into_owned();
    let out = strip_trailing_dots_and_spaces(&strip_ads(&clean));
    if out == input {
        Ok(Cow::Borrowed(input))
    } else {
        Ok(Cow::Owned(out))
    }
}

pub fn normalize_path_win(input: &[u8]) -> Cow<'_, [u8]> {
    normalize_path_win_with_budget(input, None).unwrap()
}

fn strip_ads(data: &[u8]) -> Vec<u8> {
    let (prefix, mut rest) = if data.len() >= 2 && data[1] == b':' && data[0].is_ascii_alphabetic()
    {
        (&data[..2], &data[2..])
    } else {
        (&data[..0], data)
    };
    let mut trailing = &data[..0];
    if rest.last() == Some(&b'/') {
        trailing = b"/";
        rest = &rest[..rest.len() - 1];
    }
    let cut = match rest.iter().rposition(|&c| c == b'/') {
        Some(idx) => rest[idx + 1..]
            .iter()
            .position(|&c| c == b':')
            .map(|c| idx + 1 + c),
        None => rest.iter().position(|&c| c == b':'),
    };
    let rest = cut.map_or(rest, |c| &rest[..c]);
    [prefix, rest, trailing].concat()
}

fn all_dots(s: &[u8]) -> bool {
    s.iter().all(|&c| c == b'.')
}

fn strip_trailing_dots_and_spaces(data: &[u8]) -> Vec<u8> {
    let trimmable = data
        .split(|&c| c == b'/')
        .any(|seg| !all_dots(seg) && matches!(seg.last(), Some(b'.' | b' ')));
    if !trimmable {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len());
    let mut wrote = false;
    for seg in data.split(|&c| c == b'/') {
        let piece: &[u8] = if all_dots(seg) {
            seg
        } else {
            let end = seg
                .iter()
                .rposition(|&c| c != b'.' && c != b' ')
                .map_or(0, |e| e + 1);
            if end == 0 {
                continue; // a component of only dots and spaces is dropped
            }
            &seg[..end]
        };
        if wrote {
            out.push(b'/');
        }
        out.extend_from_slice(piece);
        wrote = true;
    }
    out
}

/// replaceComments: each /* ... */ (or an unterminated /* ...) becomes one
/// space.
pub fn replace_comments_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    if !input.windows(2).any(|w| w == b"/*") {
        return Ok(Cow::Borrowed(input));
    }
    let n = input.len();
    let mut out = Vec::with_capacity(n);
    let (mut i, mut inc) = (0, false);
    let mut next_check = 8192;
    while i < n {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        if !inc {
            if input[i] == b'/' && i + 1 < n && input[i + 1] == b'*' {
                inc = true;
                i += 2;
            } else {
                out.push(input[i]);
                i += 1;
            }
        } else if input[i] == b'*' && i + 1 < n && input[i + 1] == b'/' {
            inc = false;
            i += 2;
            out.push(b' ');
        } else {
            i += 1;
        }
    }
    if inc {
        out.push(b' ');
    }
    Ok(Cow::Owned(out))
}

pub fn replace_comments(input: &[u8]) -> Cow<'_, [u8]> {
    replace_comments_with_budget(input, None).unwrap()
}

/// removeCommentsChar: drops /* */ <!-- --> -- and #.
pub fn remove_comments_char_with_budget<'a>(
    input: &'a [u8],
    mut budget: Option<&mut TxBudget>,
) -> Result<Cow<'a, [u8]>, BudgetExceeded> {
    let n = input.len();
    let mut out = Vec::with_capacity(n);
    let mut changed = false;
    let mut i = 0;
    let mut next_check = 8192;
    while i < n {
        if i >= next_check {
            if let Some(bgt) = budget.as_deref_mut() {
                bgt.check()?;
            }
            next_check = i + 8192;
        }
        let rest = &input[i..];
        let skip = if rest.starts_with(b"/*") || rest.starts_with(b"*/") {
            2
        } else if rest.starts_with(b"<!--") {
            4
        } else if rest.starts_with(b"-->") {
            3
        } else if rest.starts_with(b"--") {
            2
        } else if rest[0] == b'#' {
            1
        } else {
            0
        };
        if skip > 0 {
            changed = true;
            i += skip;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    if changed {
        Ok(Cow::Owned(out))
    } else {
        Ok(Cow::Borrowed(input))
    }
}

pub fn remove_comments_char(input: &[u8]) -> Cow<'_, [u8]> {
    remove_comments_char_with_budget(input, None).unwrap()
}

#[cfg(test)]
mod tests {
    use super::super::{REMOVE_COMMENTS_CHAR, apply, apply_chain};

    /// Seeded random inputs through every transformation and every pair:
    /// no panic, and outputs stay within a bound of the input.
    #[test]
    fn random_inputs_never_panic() {
        let mut x: u64 = 0x2026_1011_00b2;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let alphabet: &[u8] =
            b"\\\\/*#-<!>%uU{}xX0123456789aAbBfF \t\n\r'\",;^(:.=+&\xc3\xa9\xef\xbc\x81\xff\x80";
        for _ in 0..200_000 {
            let len = (next() % 40) as usize;
            let input: Vec<u8> = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            for code in 0..=REMOVE_COMMENTS_CHAR {
                let out = apply(code, &input).unwrap();
                // utf8_to_unicode turns one byte into "%ufffd": 6 bytes
                assert!(
                    out.len() <= 6 * input.len() + 4,
                    "code {code} grew {:?}",
                    input
                );
            }
            let (a, b) = ((next() % 16) as u8, (next() % 16) as u8);
            let _ = apply_chain(&[a, b], &input);
        }
    }
}
