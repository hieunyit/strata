//! Protocol layer v1 (W03-R-01): ambiguous framing and URI evasions.
//!
//! | Rule   | Violation                                                    | Effect      |
//! |--------|--------------------------------------------------------------|-------------|
//! | 100001 | `Content-Length` and `Transfer-Encoding` together            | block alone |
//! | 100002 | `Content-Length` repeated, empty or not a decimal number     | block alone |
//! | 100003 | `Transfer-Encoding` other than a single `chunked`            | block alone |
//! | 100010 | double URL encoding (`%25` followed by two hex digits)       | +50         |
//! | 100011 | dot-segment with an encoded dot (`%2e%2e/`, `.%2e`, `%2e/`)  | +100        |
//! | 100012 | `;` inside a path segment (matrix parameters)                | +20         |
//! | 100013 | null byte, raw or `%00`, in the URI or a header              | +100        |
//! | 100014 | control character (0x01-0x1f except tab, 0x7f) raw in the URI or a header | +50 |
//! | 100020 | request body larger than the connector inspects | policy `oversize`: block alone, or recorded (0) |
//!
//! Inputs are the raw URI exactly as sent (`r->unparsed_uri`) and the raw
//! headers; nothing is allocated or copied. Scores and the block threshold
//! are provisional until policies carry per-route weights.
#![forbid(unsafe_code)]

use super::Violation;

pub const CL_TE_CONFLICT: u32 = 100_001;
pub const CL_INVALID: u32 = 100_002;
pub const TE_INVALID: u32 = 100_003;
pub const DOUBLE_ENCODING: u32 = 100_010;
pub const ENCODED_DOT_SEGMENT: u32 = 100_011;
pub const MATRIX_PARAMETER: u32 = 100_012;
pub const NULL_BYTE: u32 = 100_013;
pub const CONTROL_CHAR: u32 = 100_014;
pub const BODY_OVER_LIMIT: u32 = 100_020;

fn alone(rule: u32, field: &str, snippet: &[u8]) -> Violation {
    Violation {
        rule,
        score: 0,
        block_alone: true,
        layer: "protocol",
        field: field.to_string(),
        snippet: snippet.to_vec(),
    }
}

fn scored(rule: u32, score: i32, field: &str, snippet: &[u8]) -> Violation {
    Violation {
        rule,
        score,
        block_alone: false,
        layer: "protocol",
        field: field.to_string(),
        snippet: snippet.to_vec(),
    }
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// `%xx` at `i`, case-insensitive on the hex digits.
fn pct(b: &[u8], i: usize, hi: u8, lo: u8) -> bool {
    b.len() >= i + 3 && b[i] == b'%' && b[i + 1] == hi && b[i + 2].eq_ignore_ascii_case(&lo)
}

/// Checks the raw request URI (path and query).
pub fn check_uri(raw: &[u8], report: &mut impl FnMut(Violation)) {
    let path_end = raw.iter().position(|&c| c == b'?').unwrap_or(raw.len());
    let path = &raw[..path_end];

    let mut double_pos = None;
    let mut null_pos = None;
    let mut ctl_pos = None;

    for (i, &c) in raw.iter().enumerate() {
        if c == b'%' {
            if pct(raw, i, b'2', b'5')
                && raw.len() >= i + 5
                && is_hex(raw[i + 3])
                && is_hex(raw[i + 4])
                && double_pos.is_none()
            {
                double_pos = Some(i);
            }
            if pct(raw, i, b'0', b'0') && null_pos.is_none() {
                null_pos = Some((i, 3));
            }
        } else if c == 0 {
            if null_pos.is_none() {
                null_pos = Some((i, 1));
            }
        } else if ((c > 0 && c < 0x20) || c == 0x7f) && ctl_pos.is_none() {
            ctl_pos = Some((i, 1));
        }
    }

    let window = |pos: usize, len: usize| {
        let start = pos.saturating_sub(16);
        let end = (pos + len + 16).min(raw.len());
        &raw[start..end]
    };

    if let Some(pos) = double_pos {
        report(scored(
            DOUBLE_ENCODING,
            50,
            "REQUEST_URI_RAW",
            window(pos, 5),
        ));
    }
    if let Some((pos, len)) = null_pos {
        report(scored(NULL_BYTE, 100, "REQUEST_URI_RAW", window(pos, len)));
    }
    if let Some((pos, len)) = ctl_pos {
        report(scored(
            CONTROL_CHAR,
            50,
            "REQUEST_URI_RAW",
            window(pos, len),
        ));
    }

    let mut dot_seg = None;
    let mut matrix_seg = None;
    for seg in path.split(|&c| c == b'/') {
        if seg.contains(&b';') && matrix_seg.is_none() {
            matrix_seg = Some(seg);
        }
        if encoded_dot_segment(seg) && dot_seg.is_none() {
            dot_seg = Some(seg);
        }
    }
    if let Some(seg) = dot_seg {
        let snip = if seg.len() > 128 { &seg[..128] } else { seg };
        report(scored(ENCODED_DOT_SEGMENT, 100, "REQUEST_URI_RAW", snip));
    }
    if let Some(seg) = matrix_seg {
        let snip = if seg.len() > 128 { &seg[..128] } else { seg };
        report(scored(MATRIX_PARAMETER, 20, "REQUEST_URI_RAW", snip));
    }
}

/// A segment that is "." or ".." once `%2e` is decoded, and used `%2e`.
fn encoded_dot_segment(seg: &[u8]) -> bool {
    let mut dots = 0;
    let mut encoded = false;
    let mut i = 0;
    while i < seg.len() {
        if seg[i] == b'.' {
            i += 1;
        } else if pct(seg, i, b'2', b'e') {
            encoded = true;
            i += 3;
        } else {
            return false;
        }
        dots += 1;
        if dots > 2 {
            return false;
        }
    }
    encoded && dots > 0
}

/// Raw headers, in arrival order: framing and character checks.
#[derive(Debug, Default)]
pub struct Headers {
    cl_count: u32,
    cl_bad: bool,
    cl_snippet: Vec<u8>,
    te_count: u32,
    te_bad: bool,
    te_snippet: Vec<u8>,
    null_field: String,
    null_snippet: Vec<u8>,
    ctl_field: String,
    ctl_snippet: Vec<u8>,
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

impl Headers {
    pub fn header(&mut self, name: &[u8], value: &[u8]) {
        if name.eq_ignore_ascii_case(b"content-length") {
            self.cl_count += 1;
            let v = trim(value);
            if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
                self.cl_bad = true;
                if self.cl_snippet.is_empty() {
                    self.cl_snippet = value[..value.len().min(128)].to_vec();
                }
            } else if self.cl_count > 1 && self.cl_snippet.is_empty() {
                self.cl_snippet = value[..value.len().min(128)].to_vec();
            }
            if self.te_count > 0 && self.te_snippet.is_empty() {
                self.te_snippet = b"chunked".to_vec();
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            self.te_count += 1;
            if !trim(value).eq_ignore_ascii_case(b"chunked") {
                self.te_bad = true;
                if self.te_snippet.is_empty() {
                    self.te_snippet = value[..value.len().min(128)].to_vec();
                }
            } else if (self.cl_count > 0 || self.te_count > 1) && self.te_snippet.is_empty() {
                self.te_snippet = value[..value.len().min(128)].to_vec();
            }
        }

        if self.null_field.is_empty() {
            if let Some(pos) = name.iter().position(|&c| c == 0) {
                self.null_field = format!("REQUEST_HEADERS:{}", String::from_utf8_lossy(name));
                let start = pos.saturating_sub(16);
                let end = (pos + 17).min(name.len());
                self.null_snippet = name[start..end].to_vec();
            } else if let Some(pos) = value.iter().position(|&c| c == 0) {
                self.null_field = format!("REQUEST_HEADERS:{}", String::from_utf8_lossy(name));
                let start = pos.saturating_sub(16);
                let end = (pos + 17).min(value.len());
                self.null_snippet = value[start..end].to_vec();
            }
        }
        if self.ctl_field.is_empty() {
            let is_ctl = |&c: &u8| (c > 0 && c < 0x20 && c != b'\t') || c == 0x7f;
            if let Some(pos) = name.iter().position(is_ctl) {
                self.ctl_field = format!("REQUEST_HEADERS:{}", String::from_utf8_lossy(name));
                let start = pos.saturating_sub(16);
                let end = (pos + 17).min(name.len());
                self.ctl_snippet = name[start..end].to_vec();
            } else if let Some(pos) = value.iter().position(is_ctl) {
                self.ctl_field = format!("REQUEST_HEADERS:{}", String::from_utf8_lossy(name));
                let start = pos.saturating_sub(16);
                let end = (pos + 17).min(value.len());
                self.ctl_snippet = value[start..end].to_vec();
            }
        }
    }

    pub fn finish(&self, report: &mut impl FnMut(Violation)) {
        if self.cl_count > 0 && self.te_count > 0 {
            report(alone(
                CL_TE_CONFLICT,
                "REQUEST_HEADERS:Transfer-Encoding",
                &self.te_snippet,
            ));
        }
        if self.cl_count > 1 || self.cl_bad {
            report(alone(
                CL_INVALID,
                "REQUEST_HEADERS:Content-Length",
                &self.cl_snippet,
            ));
        }
        if self.te_count > 1 || self.te_bad {
            report(alone(
                TE_INVALID,
                "REQUEST_HEADERS:Transfer-Encoding",
                &self.te_snippet,
            ));
        }
        if !self.null_field.is_empty() {
            report(scored(NULL_BYTE, 100, &self.null_field, &self.null_snippet));
        }
        if !self.ctl_field.is_empty() {
            report(scored(CONTROL_CHAR, 50, &self.ctl_field, &self.ctl_snippet));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(raw: &[u8]) -> Vec<u32> {
        let mut out = vec![];
        check_uri(raw, &mut |v| out.push(v.rule));
        out
    }

    fn headers(h: &[(&[u8], &[u8])]) -> Vec<Violation> {
        let mut s = Headers::default();
        for (k, v) in h {
            s.header(k, v);
        }
        let mut out = vec![];
        s.finish(&mut |v| out.push(v));
        out
    }

    fn rules(h: &[(&[u8], &[u8])]) -> Vec<u32> {
        headers(h).iter().map(|v| v.rule).collect()
    }

    #[test]
    fn protocol_clean_requests_have_no_violation() {
        assert!(uri(b"/a/b/c.html?x=1&y=%41%2F").is_empty());
        assert!(uri(b"/files/v1.2/..hidden/./not-encoded").is_empty());
        assert!(uri(b"/").is_empty());
        assert!(rules(&[(b"Host", b"api.example.test"), (b"Content-Length", b"42")]).is_empty());
        assert!(rules(&[(b"Transfer-Encoding", b"chunked")]).is_empty());
        assert!(rules(&[(b"User-Agent", b"a\tb")]).is_empty()); // tab is allowed
    }

    #[test]
    fn protocol_cl_and_te_together() {
        let v = headers(&[
            (b"Content-Length", b"5"),
            (b"Transfer-Encoding", b"chunked"),
        ]);
        assert_eq!(
            v,
            vec![alone(
                CL_TE_CONFLICT,
                "REQUEST_HEADERS:Transfer-Encoding",
                b"chunked"
            )]
        );
    }

    #[test]
    fn protocol_cl_te_any_case() {
        assert_eq!(
            rules(&[
                (b"content-LENGTH", b"5"),
                (b"TRANSFER-encoding", b"chunked")
            ]),
            [CL_TE_CONFLICT]
        );
    }

    #[test]
    fn protocol_cl_duplicated() {
        assert_eq!(
            rules(&[(b"Content-Length", b"5"), (b"Content-Length", b"5")]),
            [CL_INVALID]
        );
        assert_eq!(
            rules(&[(b"Content-Length", b"5"), (b"Content-Length", b"6")]),
            [CL_INVALID]
        );
    }

    #[test]
    fn protocol_cl_not_a_number() {
        assert_eq!(rules(&[(b"Content-Length", b"5, 5")]), [CL_INVALID]);
        assert_eq!(rules(&[(b"Content-Length", b"-1")]), [CL_INVALID]);
        assert_eq!(rules(&[(b"Content-Length", b"0x10")]), [CL_INVALID]);
        assert_eq!(rules(&[(b"Content-Length", b"")]), [CL_INVALID]);
    }

    #[test]
    fn protocol_te_other_than_chunked() {
        assert_eq!(
            rules(&[(b"Transfer-Encoding", b"chunked, identity")]),
            [TE_INVALID]
        );
        assert_eq!(rules(&[(b"Transfer-Encoding", b"identity")]), [TE_INVALID]);
        assert_eq!(rules(&[(b"Transfer-Encoding", b"xchunked")]), [TE_INVALID]);
        assert_eq!(
            rules(&[(b"Transfer-Encoding", b"chunked\x0b")]),
            [TE_INVALID, CONTROL_CHAR]
        );
    }

    #[test]
    fn protocol_te_repeated() {
        assert_eq!(
            rules(&[
                (b"Transfer-Encoding", b"chunked"),
                (b"Transfer-Encoding", b"chunked")
            ]),
            [TE_INVALID]
        );
    }

    #[test]
    fn protocol_te_whitespace_is_trimmed() {
        assert!(rules(&[(b"Transfer-Encoding", b" Chunked\t")]).is_empty());
    }

    #[test]
    fn protocol_double_encoding() {
        assert_eq!(uri(b"/a/%252e%252e/etc/passwd"), [DOUBLE_ENCODING]);
        assert_eq!(uri(b"/search?q=%253Cscript%253E"), [DOUBLE_ENCODING]);
        assert!(uri(b"/discount?p=%25").is_empty()); // a literal percent sign
        assert!(uri(b"/discount?p=%25x1").is_empty());
    }

    #[test]
    fn protocol_encoded_dot_segments() {
        assert_eq!(uri(b"/a/%2e%2e/b?x=1"), [ENCODED_DOT_SEGMENT]);
        assert_eq!(uri(b"/a/%2E%2E/b"), [ENCODED_DOT_SEGMENT]);
        assert_eq!(uri(b"/a/.%2e/b"), [ENCODED_DOT_SEGMENT]);
        assert_eq!(uri(b"/a/%2e./b"), [ENCODED_DOT_SEGMENT]);
        assert_eq!(uri(b"/a/%2e/b"), [ENCODED_DOT_SEGMENT]);
        assert_eq!(uri(b"/a/%2e%2e"), [ENCODED_DOT_SEGMENT]);
    }

    #[test]
    fn protocol_encoded_dots_that_are_not_segments() {
        assert!(uri(b"/a/file%2ejson").is_empty());
        assert!(uri(b"/a/%2e%2e%2e/b").is_empty());
        assert!(uri(b"/a/b?path=%2e%2e/").is_empty()); // query, not path
    }

    #[test]
    fn protocol_semicolon_in_segment() {
        assert_eq!(uri(b"/app;jsessionid=ABC/page"), [MATRIX_PARAMETER]);
        assert_eq!(uri(b"/a/..;/admin"), [MATRIX_PARAMETER]);
        assert!(uri(b"/a/b?x=1;y=2").is_empty()); // query is not a segment
    }

    #[test]
    fn protocol_null_byte() {
        assert_eq!(uri(b"/a/b.php%00.jpg"), [NULL_BYTE]);
        assert_eq!(uri(b"/a?f=x%00"), [NULL_BYTE]);
        assert_eq!(uri(b"/a\x00b"), [NULL_BYTE]);
        assert_eq!(rules(&[(b"X-Name", b"a\x00b")]), [NULL_BYTE]);
    }

    #[test]
    fn protocol_control_characters() {
        assert_eq!(uri(b"/a\x01b"), [CONTROL_CHAR]);
        assert_eq!(uri(b"/a\x7fb"), [CONTROL_CHAR]);
        assert_eq!(rules(&[(b"X-Note", b"line\rbreak")]), [CONTROL_CHAR]);
        assert_eq!(rules(&[(b"X-\x1bName", b"v")]), [CONTROL_CHAR]);
    }

    #[test]
    fn protocol_reports_each_rule_once() {
        assert_eq!(uri(b"/%00/%00?x=%00"), [NULL_BYTE]);
        assert_eq!(
            rules(&[
                (b"Content-Length", b"1"),
                (b"Content-Length", b"x"),
                (b"Content-Length", b"2")
            ]),
            [CL_INVALID]
        );
    }

    #[test]
    fn protocol_several_violations() {
        assert_eq!(
            uri(b"/a;b/%2e%2e/%2500"),
            [DOUBLE_ENCODING, ENCODED_DOT_SEGMENT, MATRIX_PARAMETER]
        );
        assert_eq!(
            rules(&[
                (b"Content-Length", b"5"),
                (b"Transfer-Encoding", b"gzip, chunked")
            ]),
            [CL_TE_CONFLICT, TE_INVALID]
        );
    }

    #[test]
    fn protocol_scores_and_block_alone() {
        let mut v = vec![];
        check_uri(b"/x;y/%2e%2e/%2541%00\x01", &mut |x| v.push(x));
        let score: i32 = v.iter().map(|x| x.score).sum();
        assert_eq!(score, 50 + 100 + 50 + 100 + 20);
        assert!(v.iter().all(|x| !x.block_alone));
        assert!(
            headers(&[
                (b"Content-Length", b"1"),
                (b"Transfer-Encoding", b"chunked")
            ])[0]
                .block_alone
        );
    }

    #[test]
    fn protocol_truncated_escapes_do_not_panic() {
        for raw in [
            &b"%"[..],
            b"%2",
            b"%25",
            b"%252",
            b"/%2e%",
            b"/%2",
            b";",
            b"/%00%",
        ] {
            let _ = uri(raw);
        }
    }

    #[test]
    fn test_clean_headers_no_snippet_allocation() {
        let mut h = Headers::default();
        h.header(b"Host", b"example.test");
        h.header(b"Content-Type", b"application/x-www-form-urlencoded");
        h.header(b"Content-Length", b"5");
        assert!(h.cl_snippet.is_empty());
        assert_eq!(h.cl_snippet.capacity(), 0);
        assert!(h.te_snippet.is_empty());
        assert_eq!(h.te_snippet.capacity(), 0);
        assert!(h.null_field.is_empty());
        assert!(h.ctl_field.is_empty());
    }
}
