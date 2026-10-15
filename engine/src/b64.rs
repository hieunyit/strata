//! Values that look base64-encoded (docs/decisions/base64-args.md): an
//! argument or cookie whose value is all base64 characters and decodes to
//! text is inspected a second time, decoded, under its name with
//! [`SUFFIX`]. Rules need no `base64_decode` transform for it: every rule
//! that reads ARGS or REQUEST_COOKIES sees the decoded text too, the way
//! Cloudflare's attack score and F5's base64 parameters do.
//!
//! The test is strict, so that ordinary values are not decoded:
//! - 8 to [`MAX_LEN`] bytes, one alphabet (standard `+/` or URL-safe
//!   `-_`), at most two `=` at the end, no length that leaves one
//!   character over. A space counts as `+`: a `+` in a query string or form
//!   body was decoded to a space before the engine sees the value;
//! - the decoded bytes hold [`TEXT_RUN`] bytes of text in a row (see
//!   `holds_text`), and then the whole value is inspected.
//!
//! A random byte is text with a probability of about 0.37, so most tokens
//! and hashes of base64 characters are not decoded; base64 of text always
//! is, padded with binary bytes or not. The work is bounded per request
//! ([`Left`]).
#![forbid(unsafe_code)]

/// Appended to the field name of a decoded value: `ARGS:q|base64`.
pub const SUFFIX: &[u8] = SUFFIX_STR.as_bytes();
pub const SUFFIX_STR: &str = "|base64";
/// Longest value tested (bytes, encoded).
pub const MAX_LEN: usize = 16 * 1024;
/// Shortest value tested: shorter ones decode to at most 5 bytes.
pub const MIN_LEN: usize = 8;
/// At most this many decoded values per request, and this many decoded
/// bytes in all: bounded work on hostile input.
pub const MAX_VALUES: usize = 32;
pub const MAX_TOTAL: usize = 64 * 1024;
/// At most this many bytes of values tested per request, decoded or not.
pub const MAX_TESTED: usize = 256 * 1024;

const INVALID: u8 = 0xff;

const fn table(c62: u8, c63: u8) -> [u8; 256] {
    let mut t = [INVALID; 256];
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut i = 0;
    while i < 62 {
        t[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    t[c62 as usize] = 62;
    t[c63 as usize] = 63;
    t
}

static STD: [u8; 256] = {
    let mut t = table(b'+', b'/');
    // '+' decoded to a space by form decoding
    t[b' ' as usize] = 62;
    t
};
static URL: [u8; 256] = table(b'-', b'_');

/// The name a decoded value is inspected under.
pub fn name(n: &[u8]) -> Vec<u8> {
    [n, SUFFIX].concat()
}

/// `n` without [`SUFFIX`]: the name rules key and exclusions compare with.
pub fn base_name(n: &[u8]) -> &[u8] {
    n.strip_suffix(SUFFIX).unwrap_or(n)
}

/// The decoded bytes when `v` looks base64-encoded, else None. Checks the
/// alphabet before it allocates anything.
pub fn decode(v: &[u8]) -> Option<Vec<u8>> {
    if !(MIN_LEN..=MAX_LEN).contains(&v.len()) {
        return None;
    }
    let body = v
        .strip_suffix(b"==")
        .or_else(|| v.strip_suffix(b"="))
        .unwrap_or(v);
    if body.len() % 4 == 1 || (body.len() != v.len() && !v.len().is_multiple_of(4)) {
        return None;
    }
    let t = if body.iter().any(|&c| c == b'-' || c == b'_') {
        &URL
    } else {
        &STD
    };
    if body.iter().any(|&c| t[c as usize] == INVALID) {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    let (mut x, mut n) = (0u32, 0);
    for &c in body {
        x = x << 6 | u32::from(t[c as usize]);
        n += 1;
        if n == 4 {
            out.extend_from_slice(&[(x >> 16) as u8, (x >> 8) as u8, x as u8]);
            (x, n) = (0, 0);
        }
    }
    match n {
        2 => out.push((x >> 4) as u8),
        3 => out.extend_from_slice(&[(x >> 10) as u8, (x >> 2) as u8]),
        _ => {}
    }
    holds_text(&out).then_some(out)
}

/// Bytes of text in a row that make a decoded value worth inspecting.
pub const TEXT_RUN: usize = 8;

/// `b` holds [`TEXT_RUN`] bytes of text in a row (all of it when it is
/// shorter): UTF-8 characters other than control characters, whitespace
/// included (tab, LF, VT, FF, CR: SQL and shells take VT and FF for
/// spaces). Not a share of text: an attacker could pad a payload with
/// binary bytes (in an SQL comment, say) to bring the share down, while the
/// payload itself is text in a row. The whole value is inspected then.
fn holds_text(b: &[u8]) -> bool {
    let want = TEXT_RUN.min(b.len());
    let mut run = 0;
    for chunk in b.utf8_chunks() {
        for ch in chunk.valid().chars() {
            if !ch.is_control() || matches!(ch, '\t' | '\n' | '\x0b' | '\x0c' | '\r') {
                run += ch.len_utf8();
                if run >= want {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        if !chunk.invalid().is_empty() {
            run = 0;
        }
    }
    false
}

/// Decoded copies of the values of `pairs` that look base64-encoded, named
/// with [`SUFFIX`]. `left` counts down what the request may still do: the
/// values decoded, the bytes decoded, and the bytes tested (every value of
/// the base64 alphabet costs its length, decoded or not).
pub fn decode_all<'p, I>(pairs: I, left: &mut Left) -> Vec<(Vec<u8>, Vec<u8>)>
where
    I: IntoIterator<Item = (&'p [u8], &'p [u8])>,
{
    let mut out = vec![];
    for (n, v) in pairs {
        if left.values == 0 || left.decoded < MIN_LEN || left.tested < MIN_LEN {
            break;
        }
        if v.len() < MIN_LEN || v.len() > left.tested || v.len() / 4 * 3 > left.decoded {
            continue;
        }
        left.tested -= v.len();
        if let Some(d) = decode(v) {
            left.values -= 1;
            left.decoded = left.decoded.saturating_sub(d.len());
            out.push((name(n), d));
        }
    }
    out
}

/// What a request may still decode (see [`decode_all`]).
#[derive(Clone, Copy, Debug)]
pub struct Left {
    pub values: usize,
    pub decoded: usize,
    pub tested: usize,
}

impl Default for Left {
    fn default() -> Self {
        Left {
            values: MAX_VALUES,
            decoded: MAX_TOTAL,
            tested: MAX_TESTED,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(s: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut o = String::new();
        for c in s.chunks(3) {
            let x = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    o.push(A[(x >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    o.push('=');
                }
            }
        }
        o
    }

    #[test]
    fn decodes_encoded_text() {
        for s in [
            &b"<script>alert(1)</script>"[..],
            b"1' or '1'='1",
            b"; cat /etc/passwd",
            b"{\"$where\": \"sleep(1000)\"}",
            b"union select password from users",
            "xin chào thế giới".as_bytes(),
        ] {
            let e = enc(s);
            assert_eq!(decode(e.as_bytes()).as_deref(), Some(s), "{e}");
            // without padding (GoTestWAF's Base64Flat)
            let flat = e.trim_end_matches('=');
            if flat.len() >= MIN_LEN {
                assert_eq!(decode(flat.as_bytes()).as_deref(), Some(s), "{flat}");
            }
            // '+' form-decoded to a space, and the URL-safe alphabet
            assert_eq!(decode(e.replace('+', " ").as_bytes()).as_deref(), Some(s));
            let url = e.replace('+', "-").replace('/', "_");
            assert_eq!(decode(url.as_bytes()).as_deref(), Some(s), "{url}");
        }
    }

    #[test]
    fn leaves_ordinary_values() {
        for v in [
            &b"password"[..],                             // decodes to bytes, not text
            b"administrator",                             // length leaves one character over
            b"hello world",                               // decodes to bytes
            b"user@example.test",                         // not base64
            b"123456789012",                              // decodes to bytes
            b"d41d8cd98f00b204e9800998ecf8427e",          // a hash
            b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", // a JWT: dots
            b"abc",                                       // short
            b"YWJj=ZGVm",                                 // '=' in the middle
            b"YWJjZGVmZ===",                              // three '='
            b"YWJj-ZGVm/Zw",                              // two alphabets
        ] {
            assert_eq!(decode(v), None, "{}", String::from_utf8_lossy(v));
        }
        // control bytes all along
        assert_eq!(decode(enc(b"ab\x01cd\x02ef\x03gh\x04ij").as_bytes()), None);
        // too long
        let long = enc(&b"a".repeat(MAX_LEN));
        assert_eq!(decode(long.as_bytes()), None);
    }

    /// Review 15/10/2026: VT and FF are spaces to SQL and shells, and binary
    /// padding (in an SQL comment) must not hide the payload.
    #[test]
    fn whitespace_and_padding_do_not_hide_a_payload() {
        for s in [
            &b"1' UNION\x0cSELECT password FROM users--"[..],
            b"1'\x0bor\x0b'1'='1",
            b"1' union select pass from users-- \x00\xff\xfe\x01\x02\x03\x80\x81\x82\x83\x84\x85\x86\x87",
            b"\xff\xfe\x00<script>alert(1)</script>\x00\xff",
        ] {
            let e = enc(s);
            assert_eq!(decode(e.as_bytes()).as_deref(), Some(s), "{e}");
        }
    }

    #[test]
    fn names_carry_the_suffix() {
        assert_eq!(name(b"q"), b"q|base64");
        assert_eq!(base_name(b"q|base64"), b"q");
        assert_eq!(base_name(b"q"), b"q");
    }

    #[test]
    fn bounded_per_request() {
        let v = enc(b"<script>alert(1)</script>");
        let pairs: Vec<(&[u8], &[u8])> = (0..100).map(|_| (&b"q"[..], v.as_bytes())).collect();
        let mut left = Left::default();
        assert_eq!(
            decode_all(pairs.iter().copied(), &mut left).len(),
            MAX_VALUES
        );
        let mut left = Left {
            decoded: 60,
            ..Left::default()
        };
        assert_eq!(decode_all(pairs.iter().copied(), &mut left).len(), 2);

        // review 15/10/2026: values that fail the test cost their length
        // too, so 1024 values of 16 KB stop after 256 KB tested
        let junk = "A".repeat(MAX_LEN);
        let pairs: Vec<(&[u8], &[u8])> = (0..1024).map(|_| (&b"q"[..], junk.as_bytes())).collect();
        let mut left = Left::default();
        assert!(decode_all(pairs.iter().copied(), &mut left).is_empty());
        assert_eq!(left.tested, 0);
        assert_eq!(left.values, MAX_VALUES);
    }
}
