//! Data guard: masks values in the response body, chunk by chunk, without
//! missing a value split between two chunks (W06-N-01).
//!
//! Each call masks what it can see in (held tail + new chunk) and keeps the
//! last `longest - 1` bytes, which could be the start of a value completed
//! by the next chunk; they are emitted with the next call, the last call
//! flushes everything. A flush (streaming responses, e.g. Server-Sent
//! Events) emits the held bytes early: a value split exactly across it is
//! not masked, the price of not delaying the stream. Masking replaces bytes with '*', so the total length
//! (Content-Length) never changes, only how bytes are split across chunks.
//!
//! Detectors (e.g. Vietnamese citizen ID numbers) come with the response
//! layer (W06-R-01); until then only the test-hooks build has one.
#![forbid(unsafe_code)]

/// Finds byte ranges to mask in a window.
pub trait Matcher: Send + Sync {
    /// Longest value this matcher can mask, context included.
    fn max_len(&self) -> usize;
    /// Ranges of `hay` to replace with '*'.
    fn find(&self, hay: &[u8], out: &mut Vec<(usize, usize)>);
}

/// A literal to mask (tests).
pub struct Literal(pub &'static [u8]);

impl Matcher for Literal {
    fn max_len(&self) -> usize {
        self.0.len()
    }

    fn find(&self, hay: &[u8], out: &mut Vec<(usize, usize)>) {
        let n = self.0.len();
        if n == 0 || hay.len() < n {
            return;
        }
        let mut i = 0;
        while i + n <= hay.len() {
            if &hay[i..i + n] == self.0 {
                out.push((i, i + n));
                i += n;
            } else {
                i += 1;
            }
        }
    }
}

pub struct Guard {
    matchers: Vec<Box<dyn Matcher>>,
    keep: usize,
    held: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    masked: u64,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("matchers", &self.matchers.len())
            .field("held", &self.held.len())
            .field("masked", &self.masked)
            .finish()
    }
}

impl Guard {
    pub fn new(matchers: Vec<Box<dyn Matcher>>) -> Guard {
        let keep = matchers
            .iter()
            .map(|m| m.max_len())
            .max()
            .unwrap_or(1)
            .saturating_sub(1);
        Guard {
            matchers,
            keep,
            held: Vec::new(),
            ranges: Vec::new(),
            masked: 0,
        }
    }

    /// Bytes masked so far.
    pub fn masked(&self) -> u64 {
        self.masked
    }

    /// The bytes to send in place of `data` (possibly fewer or more: the
    /// held tail moves between calls).
    pub fn chunk(&mut self, data: &[u8], last: bool) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(data);

        self.ranges.clear();
        for m in &self.matchers {
            m.find(&buf, &mut self.ranges);
        }
        for &(a, b) in &self.ranges {
            for c in &mut buf[a..b] {
                if *c != b'*' {
                    *c = b'*';
                    self.masked += 1;
                }
            }
        }

        if !last {
            let keep = self.keep.min(buf.len());
            self.held = buf.split_off(buf.len() - keep);
        }
        buf
    }

    /// Everything held back, now: the connector flushes the response.
    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> Guard {
        Guard::new(vec![Box::new(Literal(b"SECRET"))])
    }

    fn run(g: &mut Guard, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![];
        for (i, c) in chunks.iter().enumerate() {
            out.extend(g.chunk(c, i + 1 == chunks.len()));
        }
        out
    }

    #[test]
    fn guard_masks_in_one_chunk() {
        assert_eq!(run(&mut guard(), &[b"a SECRET b"]), b"a ****** b");
    }

    #[test]
    fn guard_masks_across_every_split() {
        let body = b"xx SECRET yy SECRET";
        for s1 in 0..=body.len() {
            for s2 in s1..=body.len() {
                let mut g = guard();
                let out = run(&mut g, &[&body[..s1], &body[s1..s2], &body[s2..]]);
                assert_eq!(out, b"xx ****** yy ******", "{s1} {s2}");
                assert_eq!(g.masked(), 12);
            }
        }
    }

    #[test]
    fn guard_keeps_the_length_and_holds_at_most_keep_bytes() {
        let mut g = guard();
        let first = g.chunk(b"0123456789", false);
        assert_eq!(first, b"01234"); // 5 = len("SECRET") - 1 held
        let second = g.chunk(b"", true);
        assert_eq!(second, b"56789");
    }

    #[test]
    fn guard_flush_emits_the_held_tail_and_keeps_going() {
        let mut g = guard();
        assert_eq!(g.chunk(b"data: 0123456789", false), b"data: 01234");
        assert_eq!(g.flush(), b"56789");
        assert_eq!(g.flush(), b"");
        let mut out = g.chunk(b"data: SECRET x", false);
        out.extend(g.chunk(b"", true));
        assert_eq!(out, b"data: ****** x");
    }

    #[test]
    fn guard_byte_by_byte() {
        let body = b"<id>SECRET</id>";
        let chunks: Vec<&[u8]> = body.chunks(1).collect();
        assert_eq!(run(&mut guard(), &chunks), b"<id>******</id>");
    }
}
