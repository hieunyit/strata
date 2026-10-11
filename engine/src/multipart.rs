//! `multipart/form-data` bodies (RFC 7578), for rule targets: a part with
//! a `filename` is a file (`files`: the file name, `files_names`: the
//! field name); any other part is a field, added to `args_post` as
//! ModSecurity does. Iterative, bounded, borrowing from the body; a body
//! that does not parse yields what was read before the damage.
#![forbid(unsafe_code)]

/// At most this many parts are read.
pub const MAX_PARTS: usize = 1024;
/// A part's headers longer than this end the parse.
const MAX_PART_HEADERS: usize = 8 * 1024;
/// RFC 2046 allows 70; some clients send a little more.
const MAX_BOUNDARY: usize = 200;

/// A part of the body: field name, file name (for a file), content.
#[derive(Debug, PartialEq, Eq)]
pub struct Part<'a> {
    pub name: &'a [u8],
    pub filename: Option<&'a [u8]>,
    pub content: &'a [u8],
}

fn position_8k<F>(slice: &[u8], mut pred: F) -> Option<usize>
where
    F: FnMut(u8) -> bool,
{
    let mut curr = 0;
    while curr < slice.len() {
        let end = (curr + 8192).min(slice.len());
        if let Some(i) = slice[curr..end].iter().position(|&c| pred(c)) {
            return Some(curr + i);
        }
        curr = end;
    }
    None
}

fn find_8k(
    finder: &memchr::memmem::Finder<'_>,
    haystack: &[u8],
    needle_len: usize,
) -> Option<usize> {
    let mut curr = 0;
    while curr < haystack.len() {
        let end = (curr + 8192 + needle_len.saturating_sub(1)).min(haystack.len());
        if end < curr + needle_len {
            break;
        }
        if let Some(pos) = finder.find(&haystack[curr..end]) {
            return Some(curr + pos);
        }
        curr += 8192;
    }
    None
}

/// The boundary of a `multipart/form-data` Content-Type, if it is one.
pub fn boundary(content_type: &[u8]) -> Option<&[u8]> {
    let mut params = content_type.split(|&c| c == b';');
    let kind = trim(params.next()?);
    if !kind.eq_ignore_ascii_case(b"multipart/form-data") {
        return None;
    }
    for p in params {
        let p = trim(p);
        let Some(eq) = position_8k(p, |c| c == b'=') else {
            continue;
        };
        if !trim(&p[..eq]).eq_ignore_ascii_case(b"boundary") {
            continue;
        }
        let mut v = trim(&p[eq + 1..]);
        if v.len() >= 2 && v[0] == b'"' && v[v.len() - 1] == b'"' {
            v = &v[1..v.len() - 1];
        }
        return (!v.is_empty() && v.len() <= MAX_BOUNDARY).then_some(v);
    }
    None
}

/// The parts of `body`, at most [`MAX_PARTS`].
pub fn parts<'a>(body: &'a [u8], boundary: &[u8]) -> Vec<Part<'a>> {
    let delim = [b"--".as_slice(), boundary].concat();
    // after the first, a delimiter starts a line
    let line_delim = [b"\n".as_slice(), &delim].concat();
    let next_delim = memchr::memmem::Finder::new(&line_delim);
    let mut out = vec![];
    let first = if body.starts_with(&delim) {
        0
    } else {
        // after a preamble
        match find_8k(&next_delim, body, line_delim.len()) {
            Some(i) => i + 1,
            None => return out,
        }
    };
    let mut at = first + delim.len();
    while out.len() < MAX_PARTS {
        let rest = &body[at..];
        if rest.starts_with(b"--") {
            break; // close delimiter
        }
        // the rest of the delimiter line (transport padding), then CRLF
        let Some(eol) = position_8k(rest, |c| c == b'\n') else {
            break;
        };
        let part_start = at + eol + 1;
        // content ends at the CRLF (or LF) of the next delimiter's line
        let Some(next) =
            find_8k(&next_delim, &body[part_start..], line_delim.len()).map(|i| part_start + i)
        else {
            break;
        };
        let mut end = next;
        if end > part_start && body[end - 1] == b'\r' {
            end -= 1;
        }
        if let Some(p) = part(&body[part_start..end]) {
            out.push(p);
        }
        at = next + line_delim.len();
    }
    out
}

/// One part: headers, an empty line, the content.
fn part(p: &[u8]) -> Option<Part<'_>> {
    let (head, content) = split_headers(p)?;
    let mut name = None;
    let mut filename = None;
    for line in head.split(|&c| c == b'\n') {
        let line = strip_cr(line);
        let Some(colon) = position_8k(line, |c| c == b':') else {
            continue;
        };
        if !trim(&line[..colon]).eq_ignore_ascii_case(b"content-disposition") {
            continue;
        }
        let v = &line[colon + 1..];
        name = param(v, b"name");
        filename = param(v, b"filename");
    }
    Some(Part {
        name: name?,
        filename,
        content,
    })
}

/// Splits at the first empty line (CRLF CRLF or LF LF).
fn split_headers(p: &[u8]) -> Option<(&[u8], &[u8])> {
    let limit = p.len().min(MAX_PART_HEADERS);
    let mut i = 0;
    while i < limit {
        if p[i] == b'\n' {
            let after = &p[i + 1..];
            if after.starts_with(b"\r\n") {
                return Some((&p[..i], &after[2..]));
            }
            if after.starts_with(b"\n") {
                return Some((&p[..i], &after[1..]));
            }
        }
        i += 1;
    }
    None
}

/// A `key=value` or `key="value"` parameter of a header value. A quoted
/// value ends at the first unescaped quote; it is returned as written.
fn param<'a>(v: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;
    while i < v.len() {
        // start of a parameter: after ';' (the first token is form-data)
        let semi = v[i..].iter().position(|&c| c == b';')?;
        let start = i + semi + 1;
        let rest = &v[start..];
        let eq = rest.iter().position(|&c| c == b'=' || c == b';')?;
        if rest[eq] == b';' {
            i = start;
            continue;
        }
        let k = trim(&rest[..eq]);
        let val_start = start + eq + 1;
        let (val, next) = value(v, val_start);
        if k.eq_ignore_ascii_case(key) {
            return Some(val);
        }
        i = next;
    }
    None
}

/// The parameter value at `at`: quoted (to the closing quote, `\` escapes
/// one byte) or a token (to `;`). Returns it and where parsing goes on.
fn value(v: &[u8], at: usize) -> (&[u8], usize) {
    let mut s = at;
    while s < v.len() && (v[s] == b' ' || v[s] == b'\t') {
        s += 1;
    }
    if s < v.len() && v[s] == b'"' {
        let mut j = s + 1;
        while j < v.len() {
            match v[j] {
                b'\\' => j += 2,
                b'"' => return (&v[s + 1..j], j + 1),
                _ => j += 1,
            }
        }
        return (&v[s + 1..], v.len());
    }
    let end = v[s..]
        .iter()
        .position(|&c| c == b';')
        .map_or(v.len(), |e| s + e);
    (trim(&v[s..end]), end)
}

fn strip_cr(l: &[u8]) -> &[u8] {
    l.strip_suffix(b"\r").unwrap_or(l)
}

fn trim(v: &[u8]) -> &[u8] {
    let is_space = |c: &u8| *c == b' ' || *c == b'\t' || *c == b'\r' || *c == b'\n';
    let start = v.iter().position(|c| !is_space(c)).unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|c| !is_space(c))
        .map_or(start, |e| e + 1);
    &v[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_from_content_type() {
        assert_eq!(
            boundary(b"multipart/form-data; boundary=abc"),
            Some(&b"abc"[..])
        );
        assert_eq!(
            boundary(b"Multipart/Form-Data; charset=utf-8; boundary=\"a b\""),
            Some(&b"a b"[..])
        );
        assert_eq!(boundary(b"multipart/mixed; boundary=abc"), None);
        assert_eq!(boundary(b"multipart/form-data"), None);
        assert_eq!(boundary(b"multipart/form-data; boundary="), None);
        assert_eq!(
            boundary(&[b"multipart/form-data; boundary=".as_slice(), &[b'x'; 201]].concat()),
            None
        );
    }

    const BODY: &[u8] = b"preamble\r\n--XyZ\r\n\
Content-Disposition: form-data; name=\"title\"\r\n\r\n\
hello\r\n--XyZ\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\
Content-Type: application/octet-stream\r\n\r\n\
<?php system($_GET['c']); ?>\r\n--XyZ\n\
content-disposition: form-data; filename=\"a\\\"b.txt\"; name=up2\n\n\
x\n--XyZ--\r\nepilogue";

    #[test]
    fn fields_and_files() {
        let p = parts(BODY, b"XyZ");
        assert_eq!(p.len(), 3, "{p:?}");
        assert_eq!(
            p[0],
            Part {
                name: b"title",
                filename: None,
                content: b"hello"
            }
        );
        assert_eq!(p[1].name, b"file");
        assert_eq!(p[1].filename, Some(&b"shell.php"[..]));
        assert_eq!(p[1].content, b"<?php system($_GET['c']); ?>");
        assert_eq!(
            p[2].name, b"up2",
            "unquoted, after the filename, LF line ends"
        );
        assert_eq!(
            p[2].filename,
            Some(&br#"a\"b.txt"#[..]),
            "escaped quote kept as written"
        );
    }

    #[test]
    fn damaged_bodies_end_the_parse() {
        assert!(parts(b"no delimiter", b"XyZ").is_empty());
        // unterminated part: nothing after the last delimiter is a part
        let p = parts(
            b"--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv",
            b"XyZ",
        );
        assert!(p.is_empty());
        // a part without a name is skipped, the next one is read
        let p = parts(b"--b\r\nX: y\r\n\r\nv\r\n--b\r\nContent-Disposition: form-data; name=n\r\n\r\nw\r\n--b--", b"b");
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].name, p[0].content), (&b"n"[..], &b"w"[..]));
        // headers without an end
        let long = [
            b"--b\r\n".as_slice(),
            &[b'h'; MAX_PART_HEADERS + 10],
            b"\r\n--b--",
        ]
        .concat();
        assert!(parts(&long, b"b").is_empty());
    }

    #[test]
    fn a_delimiter_starts_a_line() {
        let p = parts(
            b"--b\r\nContent-Disposition: form-data; name=a\r\n\r\nx --b y\r\n--b--",
            b"b",
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].content, b"x --b y");
    }

    #[test]
    fn hostile_body_is_linear() {
        // many near-delimiters: one memmem pass, not one per position
        let body = [
            b"--".as_slice(),
            &[b'a'; 199],
            b"\r\n",
            &b"\n--".repeat(1 << 20),
        ]
        .concat();
        let t = std::time::Instant::now();
        let _ = parts(&body, &[b'a'; 200]);
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn at_most_max_parts() {
        let one = b"--b\r\nContent-Disposition: form-data; name=a\r\n\r\nv\r\n";
        let body = [one.repeat(MAX_PARTS + 5), b"--b--".to_vec()].concat();
        assert_eq!(parts(&body, b"b").len(), MAX_PARTS);
    }
}
