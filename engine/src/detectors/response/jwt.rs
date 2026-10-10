//! JSON Web Tokens in a response body: `eyJ<header>.eyJ<payload>.<sig>`
//! (base64url, JWE with more segments too). Rule 600202, masked whole.
//!
//! A token is confirmed once its header and the start of the payload are
//! seen (`eyJ...` `.` `eyJ`); headers longer than `CONFIRM` bytes are not
//! recognised. The rest of the token may be arbitrarily long: when it runs
//! to the end of a window, the matcher remembers it and keeps masking in
//! the next window, so only `CONFIRM` bytes are ever held back.
#![forbid(unsafe_code)]

use crate::guard::{Ctx, Hit, Matcher};

pub const RULE: u32 = 600_202;
/// Longest "header + '.' + 'eyJ'" recognised.
const CONFIRM: usize = 512;
/// Held back: a candidate is told apart within header + ".eyJ".
const HOLD: usize = CONFIRM + 5;

fn b64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

/// Bytes a token may contain once started (masked bytes included).
fn token_byte(c: u8) -> bool {
    b64url(c) || c == b'.' || c == b'*'
}

#[derive(Default)]
pub struct Jwt {
    /// the last window ended inside a token that started this many bytes
    /// before its end
    open: Option<usize>,
}

impl Jwt {
    pub fn new() -> Jwt {
        Jwt::default()
    }

    /// End of the token starting at `start`, if `hay[start..]` is one.
    /// `Err(())`: maybe, the window ends before it can be told.
    fn confirm(hay: &[u8], start: usize, end: bool) -> Result<Option<usize>, ()> {
        let maybe = |end: bool| if end { Ok(None) } else { Err(()) };
        let mut j = start + 3;
        while j < hay.len() && b64url(hay[j]) {
            j += 1;
        }
        if j - start > CONFIRM {
            return Ok(None);
        }
        if j == hay.len() {
            return maybe(end);
        }
        if hay[j] != b'.' {
            return Ok(None);
        }
        let p = &hay[j + 1..];
        if p.len() < 3 {
            return if b"eyJ".starts_with(p) {
                maybe(end)
            } else {
                Ok(None)
            };
        }
        if &p[..3] != b"eyJ" {
            return Ok(None);
        }
        let mut k = j + 4;
        while k < hay.len() && token_byte(hay[k]) {
            k += 1;
        }
        Ok(Some(k))
    }
}

impl Matcher for Jwt {
    fn max_len(&self) -> usize {
        HOLD
    }

    fn masks(&self) -> bool {
        true
    }

    fn find(&mut self, hay: &[u8], ctx: Ctx, out: &mut Vec<Hit>) {
        let mut i = 0;
        let mut open = None;

        if let Some(back) = self.open.take() {
            // continue the token of the last window
            let start = ctx.held.saturating_sub(back);
            let mut k = start;
            while k < hay.len() && token_byte(hay[k]) {
                k += 1;
            }
            out.push(Hit {
                start,
                end: k,
                rule: RULE,
            });
            if k == hay.len() {
                open = Some(hay.len() - start);
            }
            i = k;
        }

        while i + 3 <= hay.len() && open.is_none() {
            let before = if i > 0 { Some(hay[i - 1]) } else { ctx.before };
            if &hay[i..i + 3] != b"eyJ" || before.is_some_and(b64url) {
                i += 1;
                continue;
            }
            match Jwt::confirm(hay, i, ctx.end) {
                Ok(Some(k)) => {
                    out.push(Hit {
                        start: i,
                        end: k,
                        rule: RULE,
                    });
                    if k == hay.len() {
                        open = Some(hay.len() - i);
                    }
                    i = k;
                }
                // undecided: the next window starts with it (held back)
                Err(()) => break,
                Ok(None) => i += 1,
            }
        }
        // after a flush nothing is held: the token goes on from the start
        // of the next window
        self.open = if ctx.end { open.map(|_| 0) } else { open };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::{Feed, Guard, tests::run};

    const TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

    fn mask(chunks: &[&[u8]]) -> (Vec<u8>, Vec<u32>) {
        let mut g = Guard::new(vec![Box::new(Jwt::new())], true);
        let out = run(&mut g, chunks);
        (out, g.found().to_vec())
    }

    fn stars(n: usize) -> String {
        "*".repeat(n)
    }

    #[test]
    fn masks_token_in_json() {
        let body = format!(r#"{{"token":"{TOKEN}","n":1}}"#);
        let (out, found) = mask(&[body.as_bytes()]);
        assert_eq!(
            out,
            format!(r#"{{"token":"{}","n":1}}"#, stars(TOKEN.len())).as_bytes()
        );
        assert_eq!(found, [RULE]);
    }

    #[test]
    fn every_split_point() {
        let body = format!("a {TOKEN} b {TOKEN}");
        let want = format!("a {} b {}", stars(TOKEN.len()), stars(TOKEN.len()));
        for s in 0..=body.len() {
            let (out, _) = mask(&[&body.as_bytes()[..s], &body.as_bytes()[s..]]);
            assert_eq!(out, want.as_bytes(), "{s}");
        }
    }

    #[test]
    fn long_token_over_many_small_chunks() {
        let sig = "A".repeat(6000);
        let token = format!("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.{sig}");
        let body = format!("[{token}]");
        let chunks: Vec<&[u8]> = body.as_bytes().chunks(100).collect();
        let (out, _) = mask(&chunks);
        assert_eq!(out, format!("[{}]", stars(token.len())).as_bytes());
    }

    #[test]
    fn not_tokens() {
        for body in [
            "eyJ alone",
            "eyJhbGciOiJIUzI1NiJ9 no dot",
            "eyJhbGciOiJIUzI1NiJ9.notjson.sig",
            "xeyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig", // inside a longer word
        ] {
            let (out, found) = mask(&[body.as_bytes()]);
            assert_eq!(out, body.as_bytes());
            assert!(found.is_empty(), "{body}");
        }
    }

    #[test]
    fn token_continues_after_a_flush() {
        let mut g = Guard::new(vec![Box::new(Jwt::new())], true);
        let half = TOKEN.len() / 2;
        let mut out = g.chunk(&TOKEN.as_bytes()[..half], Feed::Flush).unwrap();
        out.extend(g.chunk(&TOKEN.as_bytes()[half..], Feed::Last).unwrap());
        assert_eq!(out, stars(TOKEN.len()).as_bytes());
    }
}
