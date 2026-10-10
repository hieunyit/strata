//! Response body scanner: data guard (masks values) and detectors (only
//! record), chunk by chunk, without missing a value split between two
//! chunks (W06-N-01, W06-R-01).
//!
//! Each call scans a window (held tail + new chunk) and keeps the last
//! `longest - 1` bytes, which could be the start of a value completed by
//! the next chunk; they are emitted with the next call. `Feed::Last` and
//! `Feed::Flush` emit everything (a value cut by a flush is not masked; a
//! matcher may still carry state across it). Masking replaces bytes with
//! '*', so the total length (Content-Length) never changes, only how bytes
//! are split across chunks.
//!
//! Without masking (detectors only, or data guard in shadow) the chunks are
//! passed unchanged; the tail is still kept to scan across boundaries.
#![forbid(unsafe_code)]

/// Where the window sits in the stream.
#[derive(Clone, Copy, Debug)]
pub struct Ctx {
    /// bytes at the start of the window that were already in the previous
    /// window
    pub held: usize,
    /// the byte just before the window, if any
    pub before: Option<u8>,
    /// nothing follows the window in this scan (last chunk or flush): a
    /// value touching the end is complete
    pub end: bool,
}

/// A finding: bytes [start, end) of the window, for `rule`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hit {
    pub start: usize,
    pub end: usize,
    pub rule: u32,
}

pub trait Matcher: Send {
    /// Longest value this matcher needs to see whole, context included.
    fn max_len(&self) -> usize;
    /// Whether hits are masked (data guard) or only recorded.
    fn masks(&self) -> bool;
    /// Findings in `hay`.
    fn find(&mut self, hay: &[u8], ctx: Ctx, out: &mut Vec<Hit>);
}

/// A literal to mask (tests); rule 0 is not recorded.
pub struct Literal(pub &'static [u8]);

impl Matcher for Literal {
    fn max_len(&self) -> usize {
        self.0.len()
    }

    fn masks(&self) -> bool {
        true
    }

    fn find(&mut self, hay: &[u8], _ctx: Ctx, out: &mut Vec<Hit>) {
        let n = self.0.len();
        if n == 0 {
            return;
        }
        let mut i = 0;
        while i + n <= hay.len() {
            if &hay[i..i + n] == self.0 {
                out.push(Hit {
                    start: i,
                    end: i + n,
                    rule: 0,
                });
                i += n;
            } else {
                i += 1;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feed {
    /// more chunks follow
    More,
    /// last chunk
    Last,
    /// send everything now (streaming), more chunks follow
    Flush,
}

pub struct Guard {
    matchers: Vec<Box<dyn Matcher>>,
    /// mask the hits of masking matchers (off in shadow)
    rewrite: bool,
    keep: usize,
    held: Vec<u8>,
    before: Option<u8>,
    hits: Vec<Hit>,
    /// rules found so far, each once
    found: Vec<u32>,
    masked: u64,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("matchers", &self.matchers.len())
            .field("rewrite", &self.rewrite)
            .field("held", &self.held.len())
            .field("found", &self.found)
            .field("masked", &self.masked)
            .finish()
    }
}

impl Guard {
    /// `rewrite`: mask what masking matchers find; otherwise every chunk is
    /// passed unchanged and findings are only recorded.
    pub fn new(matchers: Vec<Box<dyn Matcher>>, rewrite: bool) -> Guard {
        let keep = matchers
            .iter()
            .map(|m| m.max_len())
            .max()
            .unwrap_or(1)
            .saturating_sub(1);
        let rewrite = rewrite && matchers.iter().any(|m| m.masks());
        Guard {
            matchers,
            rewrite,
            keep,
            held: Vec::new(),
            before: None,
            hits: Vec::new(),
            found: Vec::new(),
            masked: 0,
        }
    }

    /// Whether chunks are rewritten (else `chunk` always returns `None`).
    pub fn rewrites(&self) -> bool {
        self.rewrite
    }

    /// Bytes masked so far.
    pub fn masked(&self) -> u64 {
        self.masked
    }

    /// Rules found so far (rule 0 excluded), in order of discovery.
    pub fn found(&self) -> &[u32] {
        &self.found
    }

    /// `Some(bytes)`: send these in place of `data` (possibly fewer or more:
    /// the held tail moves between calls). `None`: send `data` unchanged.
    pub fn chunk(&mut self, data: &[u8], feed: Feed) -> Option<Vec<u8>> {
        let held = self.held.len();
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(data);
        let ctx = Ctx {
            held,
            before: self.before,
            end: feed != Feed::More,
        };

        self.hits.clear();
        for m in &mut self.matchers {
            let from = self.hits.len();
            m.find(&buf, ctx, &mut self.hits);
            for h in &mut self.hits[from..] {
                h.end = h.end.min(buf.len());
                h.start = h.start.min(h.end);
                if self.rewrite && m.masks() {
                    for c in &mut buf[h.start..h.end] {
                        if *c != b'*' {
                            *c = b'*';
                            self.masked += 1;
                        }
                    }
                }
            }
        }
        for h in &self.hits {
            if h.rule != 0 && !self.found.contains(&h.rule) {
                self.found.push(h.rule);
            }
        }

        let keep = if feed == Feed::More {
            self.keep.min(buf.len())
        } else {
            0
        };
        let tail = buf.split_off(buf.len() - keep);
        if let Some(&c) = buf.last() {
            self.before = Some(c);
        }
        self.held = tail;
        self.rewrite.then_some(buf)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn guard() -> Guard {
        Guard::new(vec![Box::new(Literal(b"SECRET"))], true)
    }

    /// Output of a guard fed with `chunks` (the last one with Feed::Last).
    pub(crate) fn run(g: &mut Guard, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![];
        for (i, c) in chunks.iter().enumerate() {
            let feed = if i + 1 == chunks.len() {
                Feed::Last
            } else {
                Feed::More
            };
            match g.chunk(c, feed) {
                Some(b) => out.extend(b),
                None => out.extend_from_slice(c),
            }
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
        let first = g.chunk(b"0123456789", Feed::More).unwrap();
        assert_eq!(first, b"01234"); // 5 = len("SECRET") - 1 held
        let second = g.chunk(b"", Feed::Last).unwrap();
        assert_eq!(second, b"56789");
    }

    #[test]
    fn guard_byte_by_byte() {
        let body = b"<id>SECRET</id>";
        let chunks: Vec<&[u8]> = body.chunks(1).collect();
        assert_eq!(run(&mut guard(), &chunks), b"<id>******</id>");
    }

    #[test]
    fn flush_emits_everything_held() {
        let mut g = guard();
        assert_eq!(g.chunk(b"data: SEC", Feed::More).unwrap(), b"data");
        assert_eq!(g.chunk(b"", Feed::Flush).unwrap(), b": SEC");
        // cut by the flush: not masked
        assert_eq!(g.chunk(b"RET SECRET", Feed::Last).unwrap(), b"RET ******");
    }

    struct Detect;

    impl Matcher for Detect {
        fn max_len(&self) -> usize {
            6
        }
        fn masks(&self) -> bool {
            false
        }
        fn find(&mut self, hay: &[u8], _ctx: Ctx, out: &mut Vec<Hit>) {
            let n = hay.windows(6).position(|w| w == b"SECRET");
            out.extend(n.map(|start| Hit {
                start,
                end: start + 6,
                rule: 7,
            }));
        }
    }

    #[test]
    fn detect_only_passes_chunks_and_finds_across_boundaries() {
        let mut g = Guard::new(vec![Box::new(Detect)], true);
        assert!(!g.rewrites());
        assert_eq!(g.chunk(b"xx SEC", Feed::More), None);
        assert!(g.found().is_empty());
        assert_eq!(g.chunk(b"RET", Feed::Last), None);
        assert_eq!(g.found(), [7]);
    }

    #[test]
    fn shadow_records_without_masking() {
        let mut g = Guard::new(vec![Box::new(Literal(b"SECRET"))], false);
        assert_eq!(run(&mut g, &[b"a SEC", b"RET"]), b"a SECRET");
        assert_eq!(g.masked(), 0);
    }
}
