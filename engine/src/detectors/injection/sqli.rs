//! SQL injection detection: a port of libinjection v3.10.0
//! `libinjection_sqli.c` (BSD-3-Clause, Copyright (c) 2012-2016 Nick
//! Galbreath; see engine/NOTICE).
//!
//! The input is tokenized as SQL (several quoting contexts), tokens are
//! folded into a fingerprint of at most 5 token types, and the fingerprint
//! is looked up in the list of known SQLi fingerprints; a few rules then
//! remove common false positives.
//!
//! The port keeps the C behaviour byte for byte, including its quirks
//! (NUL bytes count as members of every character set, `char` is signed,
//! token values are truncated to 31 bytes), so that results match the
//! original test suite. Where the C code reads past the input, the port
//! reads a NUL byte, as with a NUL-terminated C string. Every loop moves
//! forward; nothing recurses.
//!
//! The branches follow the C code one for one (same order, same bodies) so
//! the two can be compared side by side; hence the allowed lints.
#![forbid(unsafe_code)]
#![allow(clippy::if_same_then_else, clippy::collapsible_if)]

use super::sqli_data::KEYWORDS;

pub const FLAG_QUOTE_NONE: u32 = 1;
pub const FLAG_QUOTE_SINGLE: u32 = 2;
pub const FLAG_QUOTE_DOUBLE: u32 = 4;
pub const FLAG_SQL_ANSI: u32 = 8;
pub const FLAG_SQL_MYSQL: u32 = 16;

/// Bytes of a token value, NUL included.
pub const TOKEN_SIZE: usize = 32;
const MAX_TOKENS: usize = 5;

pub const TYPE_NONE: u8 = 0;
pub const TYPE_KEYWORD: u8 = b'k';
pub const TYPE_UNION: u8 = b'U';
pub const TYPE_GROUP: u8 = b'B';
pub const TYPE_EXPRESSION: u8 = b'E';
pub const TYPE_SQLTYPE: u8 = b't';
pub const TYPE_FUNCTION: u8 = b'f';
pub const TYPE_BAREWORD: u8 = b'n';
pub const TYPE_NUMBER: u8 = b'1';
pub const TYPE_VARIABLE: u8 = b'v';
pub const TYPE_STRING: u8 = b's';
pub const TYPE_OPERATOR: u8 = b'o';
pub const TYPE_LOGIC_OPERATOR: u8 = b'&';
pub const TYPE_COMMENT: u8 = b'c';
pub const TYPE_COLLATE: u8 = b'A';
pub const TYPE_LEFTPARENS: u8 = b'(';
pub const TYPE_RIGHTPARENS: u8 = b')';
pub const TYPE_LEFTBRACE: u8 = b'{';
pub const TYPE_RIGHTBRACE: u8 = b'}';
pub const TYPE_DOT: u8 = b'.';
pub const TYPE_COMMA: u8 = b',';
pub const TYPE_COLON: u8 = b':';
pub const TYPE_SEMICOLON: u8 = b';';
pub const TYPE_TSQL: u8 = b'T';
pub const TYPE_UNKNOWN: u8 = b'?';
pub const TYPE_EVIL: u8 = b'X';
pub const TYPE_FINGERPRINT: u8 = b'F';
pub const TYPE_BACKSLASH: u8 = b'\\';

const CHAR_NULL: u8 = 0;
const CHAR_SINGLE: u8 = b'\'';
const CHAR_DOUBLE: u8 = b'"';
const CHAR_TICK: u8 = b'`';

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Token {
    /// position and length in the input (length truncated like the value)
    pub pos: usize,
    pub len: usize,
    /// type 'v': number of leading '@'
    pub count: i32,
    pub kind: u8,
    pub str_open: u8,
    pub str_close: u8,
    /// NUL-terminated, at most 31 bytes
    pub val: [u8; TOKEN_SIZE],
}

impl Token {
    /// The value as the C code sees it (up to the first NUL).
    pub fn value(&self) -> &[u8] {
        let n = self.val.iter().position(|&c| c == 0).unwrap_or(TOKEN_SIZE);
        &self.val[..n]
    }

    fn clear(&mut self) {
        *self = Token::default();
    }

    fn assign_char(&mut self, kind: u8, pos: usize, value: u8) {
        self.kind = kind;
        self.pos = pos;
        self.len = 1;
        self.val[0] = value;
        self.val[1] = CHAR_NULL;
    }

    /// `value` holds at least min(len, 31) bytes.
    fn assign(&mut self, kind: u8, pos: usize, len: usize, value: &[u8]) {
        let last = len.min(TOKEN_SIZE - 1);
        self.kind = kind;
        self.pos = pos;
        self.len = last;
        self.val[..last].copy_from_slice(&value[..last]);
        self.val[last] = CHAR_NULL;
    }

    fn is_arithmetic_op(&self) -> bool {
        let ch = self.val[0];
        self.kind == TYPE_OPERATOR && self.len == 1 && b"*/-+%".contains(&ch)
    }

    fn is_unary_op(&self) -> bool {
        if self.kind != TYPE_OPERATOR {
            return false;
        }
        let s = &self.val;
        match self.len {
            1 => b"+-!~".contains(&s[0]),
            2 => s[0] == b'!' && s[1] == b'!',
            3 => cstrcasecmp(b"NOT", &s[..3], 3) == 0,
            _ => false,
        }
    }
}

/// `strchr(set, c) != NULL`: the terminating NUL is part of every set.
fn in_set(set: &[u8], c: u8) -> bool {
    c == 0 || set.contains(&c)
}

fn strlenspn(s: &[u8], accept: &[u8]) -> usize {
    s.iter()
        .position(|&c| !in_set(accept, c))
        .unwrap_or(s.len())
}

fn strlencspn(s: &[u8], reject: &[u8]) -> usize {
    s.iter().position(|&c| in_set(reject, c)).unwrap_or(s.len())
}

fn char_is_white(c: u8) -> bool {
    in_set(b" \t\n\x0b\x0c\r\xa0", c)
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// First index of the pair (c0, c1).
fn memchr2(h: &[u8], c0: u8, c1: u8) -> Option<usize> {
    h.windows(2).position(|w| w[0] == c0 && w[1] == c1)
}

fn memchr(h: &[u8], c: u8) -> Option<usize> {
    h.iter().position(|&x| x == c)
}

fn memmem(h: &[u8], needle: &[u8]) -> Option<usize> {
    if h.len() < needle.len() {
        return None;
    }
    h.windows(needle.len()).position(|w| w == needle)
}

/// libinjection's `cstrcasecmp`: `a` is an upper-case C string, `b` any
/// `n` bytes (signed `char` arithmetic, as in C).
fn cstrcasecmp(a: &[u8], b: &[u8], n: usize) -> i32 {
    let at = |i: usize| a.get(i).copied().unwrap_or(0) as i8 as i32;
    for (i, &bi) in b.iter().take(n).enumerate() {
        let mut cb = bi as i8 as i32;
        if (b'a' as i32..=b'z' as i32).contains(&cb) {
            cb -= 0x20;
        }
        let ca = at(i);
        if ca != cb {
            return ca - cb;
        } else if ca == 0 {
            return -1;
        }
    }
    if at(n) == 0 { 0 } else { 1 }
}

/// Type of an upper-cased word, or 0.
fn lookup_word(key: &[u8]) -> u8 {
    let len = key.len();
    let (mut left, mut right) = (0usize, KEYWORDS.len() - 1);
    while left < right {
        let pos = (left + right) >> 1;
        if cstrcasecmp(KEYWORDS[pos].0, key, len) < 0 {
            left = pos + 1;
        } else {
            right = pos;
        }
    }
    if left == right && cstrcasecmp(KEYWORDS[left].0, key, len) == 0 {
        KEYWORDS[left].1
    } else {
        CHAR_NULL
    }
}

fn flag2delim(flags: u32) -> u8 {
    if flags & FLAG_QUOTE_SINGLE != 0 {
        CHAR_SINGLE
    } else if flags & FLAG_QUOTE_DOUBLE != 0 {
        CHAR_DOUBLE
    } else {
        CHAR_NULL
    }
}

/// Odd number of backslashes in `s[start..=end]`, counted from `end` down.
fn is_backslash_escaped(s: &[u8], end: isize, start: usize) -> bool {
    let mut p = end;
    while p >= start as isize && s[p as usize] == b'\\' {
        p -= 1;
    }
    (end - p) & 1 == 1
}

/// Tokenizer and folding state (`struct libinjection_sqli_state`).
pub struct State<'a> {
    s: &'a [u8],
    flags: u32,
    pos: usize,
    tokens: [Token; 8],
    /// index of the token being written (`current`)
    cur: usize,
    fingerprint: [u8; 8],
    pub stats_comment_ddw: i32,
    pub stats_comment_ddx: i32,
    pub stats_comment_c: i32,
    pub stats_comment_hash: i32,
    pub stats_folds: i32,
    pub stats_tokens: i32,
}

impl<'a> State<'a> {
    pub fn new(s: &'a [u8], flags: u32) -> State<'a> {
        let flags = if flags == 0 {
            FLAG_QUOTE_NONE | FLAG_SQL_ANSI
        } else {
            flags
        };
        State {
            s,
            flags,
            pos: 0,
            tokens: [Token::default(); 8],
            cur: 0,
            fingerprint: [0; 8],
            stats_comment_ddw: 0,
            stats_comment_ddx: 0,
            stats_comment_c: 0,
            stats_comment_hash: 0,
            stats_folds: 0,
            stats_tokens: 0,
        }
    }

    fn reset(&mut self, flags: u32) {
        *self = State::new(self.s, flags);
    }

    /// Byte at `i`, NUL past the end (C string).
    fn at(&self, i: usize) -> u8 {
        self.s.get(i).copied().unwrap_or(0)
    }

    pub fn token(&self, i: usize) -> &Token {
        &self.tokens[i]
    }

    /// The token written by the last `tokenize`.
    pub fn current(&self) -> &Token {
        &self.tokens[self.cur]
    }

    /// The fingerprint of the last `fingerprint` call.
    pub fn fingerprint_str(&self) -> &[u8] {
        let n = self.fingerprint.iter().position(|&c| c == 0).unwrap_or(8);
        &self.fingerprint[..n]
    }

    fn tok(&mut self) -> &mut Token {
        &mut self.tokens[self.cur]
    }

    // ---- parsers: each returns the next position ----

    fn parse_white(&mut self) -> usize {
        self.pos + 1
    }

    fn parse_operator1(&mut self) -> usize {
        let pos = self.pos;
        let c = self.s[pos];
        self.tok().assign_char(TYPE_OPERATOR, pos, c);
        pos + 1
    }

    fn parse_other(&mut self) -> usize {
        let pos = self.pos;
        let c = self.s[pos];
        self.tok().assign_char(TYPE_UNKNOWN, pos, c);
        pos + 1
    }

    fn parse_char(&mut self) -> usize {
        let pos = self.pos;
        let c = self.s[pos];
        self.tok().assign_char(c, pos, c);
        pos + 1
    }

    fn parse_eol_comment(&mut self) -> usize {
        let (s, pos) = (self.s, self.pos);
        match memchr(&s[pos..], b'\n') {
            None => {
                self.tok()
                    .assign(TYPE_COMMENT, pos, s.len() - pos, &s[pos..]);
                s.len()
            }
            Some(i) => {
                self.tok().assign(TYPE_COMMENT, pos, i, &s[pos..]);
                pos + i + 1
            }
        }
    }

    fn parse_hash(&mut self) -> usize {
        self.stats_comment_hash += 1;
        if self.flags & FLAG_SQL_MYSQL != 0 {
            self.stats_comment_hash += 1;
            self.parse_eol_comment()
        } else {
            let pos = self.pos;
            self.tok().assign_char(TYPE_OPERATOR, pos, b'#');
            pos + 1
        }
    }

    fn parse_dash(&mut self) -> usize {
        let (s, pos, slen) = (self.s, self.pos, self.s.len());
        if pos + 2 < slen && s[pos + 1] == b'-' && char_is_white(s[pos + 2]) {
            self.parse_eol_comment()
        } else if pos + 2 == slen && s[pos + 1] == b'-' {
            self.parse_eol_comment()
        } else if pos + 1 < slen && s[pos + 1] == b'-' && self.flags & FLAG_SQL_ANSI != 0 {
            self.stats_comment_ddx += 1;
            self.parse_eol_comment()
        } else {
            self.tok().assign_char(TYPE_OPERATOR, pos, b'-');
            pos + 1
        }
    }

    fn parse_slash(&mut self) -> usize {
        let (s, pos, slen) = (self.s, self.pos, self.s.len());
        if pos + 1 == slen || s[pos + 1] != b'*' {
            return self.parse_operator1();
        }
        // skip the initial "/*"
        let end = memchr2(&s[pos + 2..], b'*', b'/').map(|i| pos + 2 + i);
        let clen = match end {
            None => slen - pos,
            Some(e) => e + 2 - pos,
        };
        // nested "/*" (PostgreSQL) or MySQL "/*!": unparsable. Nested
        // comments are searched up to the closing "*/" only: for an
        // unterminated comment the C code computes the length from a NULL
        // pointer, which wraps around and searches nothing; kept so.
        let nested = end.is_some_and(|e| memchr2(&s[pos + 2..e + 1], b'/', b'*').is_some());
        let kind = if nested || (pos + 2 < slen && s[pos + 2] == b'!') {
            TYPE_EVIL
        } else {
            TYPE_COMMENT
        };
        self.tok().assign(kind, pos, clen, &s[pos..]);
        pos + clen
    }

    fn parse_backslash(&mut self) -> usize {
        let (s, pos) = (self.s, self.pos);
        if pos + 1 < s.len() && s[pos + 1] == b'N' {
            self.tok().assign(TYPE_NUMBER, pos, 2, &s[pos..]);
            pos + 2
        } else {
            self.tok().assign_char(TYPE_BACKSLASH, pos, s[pos]);
            pos + 1
        }
    }

    fn parse_operator2(&mut self) -> usize {
        let (s, pos, slen) = (self.s, self.pos, self.s.len());
        if pos + 1 >= slen {
            return self.parse_operator1();
        }
        if pos + 2 < slen && s[pos] == b'<' && s[pos + 1] == b'=' && s[pos + 2] == b'>' {
            self.tok().assign(TYPE_OPERATOR, pos, 3, &s[pos..]);
            return pos + 3;
        }
        let ch = lookup_word(&s[pos..pos + 2]);
        if ch != CHAR_NULL {
            self.tok().assign(ch, pos, 2, &s[pos..]);
            return pos + 2;
        }
        if s[pos] == b':' {
            self.tok().assign(TYPE_COLON, pos, 1, &s[pos..]);
            pos + 1
        } else {
            self.parse_operator1()
        }
    }

    /// String starting at `pos + offset`, closed by `delim` (doubled or
    /// backslash-escaped delimiters do not close it).
    fn parse_string_core(&mut self, pos: usize, delim: u8, offset: usize) -> usize {
        let s = self.s;
        let len = s.len();
        let start = pos + offset;
        let mut q = memchr(&s[start..], delim).map(|i| start + i);
        self.tok().str_open = if offset > 0 { delim } else { CHAR_NULL };
        loop {
            match q {
                None => {
                    self.tok()
                        .assign(TYPE_STRING, start, len - start, &s[start..]);
                    self.tok().str_close = CHAR_NULL;
                    return len;
                }
                Some(qp) if is_backslash_escaped(s, qp as isize - 1, start) => {
                    q = memchr(&s[qp + 1..], delim).map(|i| qp + 1 + i);
                }
                Some(qp) if qp + 1 < len && s[qp + 1] == s[qp] => {
                    q = memchr(&s[qp + 2..], delim).map(|i| qp + 2 + i);
                }
                Some(qp) => {
                    self.tok()
                        .assign(TYPE_STRING, start, qp - start, &s[start..]);
                    self.tok().str_close = delim;
                    return qp + 1;
                }
            }
        }
    }

    fn parse_string(&mut self) -> usize {
        let pos = self.pos;
        self.parse_string_core(pos, self.s[pos], 1)
    }

    fn parse_estring(&mut self) -> usize {
        let (s, pos) = (self.s, self.pos);
        if pos + 2 >= s.len() || s[pos + 1] != CHAR_SINGLE {
            return self.parse_word();
        }
        self.parse_string_core(pos, CHAR_SINGLE, 2)
    }

    fn parse_ustring(&mut self) -> usize {
        let (s, pos) = (self.s, self.pos);
        if pos + 2 < s.len() && s[pos + 1] == b'&' && s[pos + 2] == b'\'' {
            self.pos += 2;
            let next = self.parse_string();
            self.tok().str_open = b'u';
            if self.tok().str_close == b'\'' {
                self.tok().str_close = b'u';
            }
            next
        } else {
            self.parse_word()
        }
    }

    fn parse_qstring_core(&mut self, offset: usize) -> usize {
        let s = self.s;
        let slen = s.len();
        let pos = self.pos + offset;
        if pos >= slen
            || (s[pos] != b'q' && s[pos] != b'Q')
            || pos + 2 >= slen
            || s[pos + 1] != b'\''
        {
            return self.parse_word();
        }
        let mut ch = s[pos + 2];
        // signed char: bytes >= 128 are negative
        if (ch as i8) < 33 {
            return self.parse_word();
        }
        ch = match ch {
            b'(' => b')',
            b'[' => b']',
            b'{' => b'}',
            b'<' => b'>',
            c => c,
        };
        match memchr2(&s[pos + 3..], ch, b'\'') {
            None => {
                self.tok()
                    .assign(TYPE_STRING, pos + 3, slen - pos - 3, &s[pos + 3..]);
                self.tok().str_open = b'q';
                self.tok().str_close = CHAR_NULL;
                slen
            }
            Some(i) => {
                self.tok().assign(TYPE_STRING, pos + 3, i, &s[pos + 3..]);
                self.tok().str_open = b'q';
                self.tok().str_close = b'q';
                pos + 3 + i + 2
            }
        }
    }

    fn parse_qstring(&mut self) -> usize {
        self.parse_qstring_core(0)
    }

    fn parse_nqstring(&mut self) -> usize {
        let (s, pos) = (self.s, self.pos);
        if pos + 2 < s.len() && s[pos + 1] == CHAR_SINGLE {
            return self.parse_estring();
        }
        self.parse_qstring_core(1)
    }

    /// `[bB]'[01]*'` (bstring) and `[xX]'[0-9a-fA-F]*'` (xstring)
    fn parse_literal_string(&mut self, digits: &[u8]) -> usize {
        let (s, pos, slen) = (self.s, self.pos, self.s.len());
        if pos + 2 >= slen || s[pos + 1] != b'\'' {
            return self.parse_word();
        }
        let wlen = strlenspn(&s[pos + 2..], digits);
        if pos + 2 + wlen >= slen || s[pos + 2 + wlen] != b'\'' {
            return self.parse_word();
        }
        self.tok().assign(TYPE_NUMBER, pos, wlen + 3, &s[pos..]);
        pos + 2 + wlen + 1
    }

    fn parse_bstring(&mut self) -> usize {
        self.parse_literal_string(b"01")
    }

    fn parse_xstring(&mut self) -> usize {
        self.parse_literal_string(b"0123456789ABCDEFabcdef")
    }

    fn parse_bword(&mut self) -> usize {
        let (s, pos) = (self.s, self.pos);
        match memchr(&s[pos..], b']') {
            None => {
                self.tok()
                    .assign(TYPE_BAREWORD, pos, s.len() - pos, &s[pos..]);
                s.len()
            }
            Some(i) => {
                self.tok().assign(TYPE_BAREWORD, pos, i + 1, &s[pos..]);
                pos + i + 1
            }
        }
    }

    fn parse_word(&mut self) -> usize {
        let (s, pos) = (self.s, self.pos);
        let wlen = strlencspn(
            &s[pos..],
            b" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r\"\xa0",
        );
        self.tok().assign(TYPE_BAREWORD, pos, wlen, &s[pos..]);

        // "SELECT.1", "SELECT`column`": a keyword before '.' or '`'
        let tlen = self.tok().len;
        for i in 0..tlen {
            let delim = self.tok().val[i];
            if delim == b'.' || delim == b'`' {
                let ch = lookup_word(&self.tok().val[..i]);
                if ch != TYPE_NONE && ch != TYPE_BAREWORD {
                    self.tok().clear();
                    self.tok().assign(ch, pos, i, &s[pos..]);
                    return pos + i;
                }
            }
        }

        if wlen < TOKEN_SIZE {
            let ch = lookup_word(&self.tok().val[..wlen]);
            self.tok().kind = if ch == CHAR_NULL { TYPE_BAREWORD } else { ch };
        }
        pos + wlen
    }

    fn parse_tick(&mut self) -> usize {
        let pos = self.pos;
        let next = self.parse_string_core(pos, CHAR_TICK, 1);
        let len = self.tok().len;
        let ch = lookup_word(&self.tok().val[..len]);
        self.tok().kind = if ch == TYPE_FUNCTION {
            TYPE_FUNCTION
        } else {
            TYPE_BAREWORD
        };
        next
    }

    fn parse_var(&mut self) -> usize {
        let (s, slen) = (self.s, self.s.len());
        let mut pos = self.pos + 1;
        if pos < slen && s[pos] == b'@' {
            pos += 1;
            self.tok().count = 2;
        } else {
            self.tok().count = 1;
        }
        // MySQL allows @@`version`
        if pos < slen {
            if s[pos] == b'`' {
                self.pos = pos;
                let next = self.parse_tick();
                self.tok().kind = TYPE_VARIABLE;
                return next;
            } else if s[pos] == CHAR_SINGLE || s[pos] == CHAR_DOUBLE {
                self.pos = pos;
                let next = self.parse_string();
                self.tok().kind = TYPE_VARIABLE;
                return next;
            }
        }
        let xlen = strlencspn(&s[pos..], b" <>:\\?=@!#~+-*/&|^%(),';\t\n\x0b\x0c\r'`\"");
        self.tok().assign(TYPE_VARIABLE, pos, xlen, &s[pos..]);
        pos + xlen
    }

    fn parse_money(&mut self) -> usize {
        let (s, pos, slen) = (self.s, self.pos, self.s.len());
        if pos + 1 == slen {
            self.tok().assign_char(TYPE_BAREWORD, pos, b'$');
            return slen;
        }
        // $1,000.00 or $1.000,00
        let xlen = strlenspn(&s[pos + 1..], b"0123456789.,");
        if xlen == 0 {
            if s[pos + 1] == b'$' {
                // $$ ... $$
                return match memchr2(&s[pos + 2..], b'$', b'$') {
                    None => {
                        self.tok()
                            .assign(TYPE_STRING, pos + 2, slen - (pos + 2), &s[pos + 2..]);
                        self.tok().str_open = b'$';
                        self.tok().str_close = CHAR_NULL;
                        slen
                    }
                    Some(i) => {
                        self.tok().assign(TYPE_STRING, pos + 2, i, &s[pos + 2..]);
                        self.tok().str_open = b'$';
                        self.tok().str_close = b'$';
                        pos + 2 + i + 2
                    }
                };
            }
            // PostgreSQL $tag$ ... $tag$
            let xlen = strlenspn(
                &s[pos + 1..],
                b"abcdefghjiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            );
            if xlen == 0 {
                self.tok().assign_char(TYPE_BAREWORD, pos, b'$');
                return pos + 1;
            }
            if pos + xlen + 1 == slen || s[pos + xlen + 1] != b'$' {
                self.tok().assign_char(TYPE_BAREWORD, pos, b'$');
                return pos + 1;
            }
            // The C code searches from offset xlen + 2 of the input (not
            // pos + xlen + 2), over slen - (pos + xlen + 2) bytes; kept.
            let from = xlen + 2;
            let hay = &s[from.min(slen)..(from + slen - (pos + xlen + 2)).min(slen)];
            let tag = &s[pos..pos + xlen + 2];
            let start = pos + xlen + 2;
            return match memmem(hay, tag).map(|i| from + i) {
                Some(e) if e >= start => {
                    self.tok()
                        .assign(TYPE_STRING, start, e - start, &s[start..]);
                    self.tok().str_open = b'$';
                    self.tok().str_close = b'$';
                    e + xlen + 2
                }
                _ => {
                    self.tok()
                        .assign(TYPE_STRING, start, slen - start, &s[start..]);
                    self.tok().str_open = b'$';
                    self.tok().str_close = CHAR_NULL;
                    slen
                }
            };
        }
        if xlen == 1 && s[pos + 1] == b'.' {
            // "$." is a word
            return self.parse_word();
        }
        self.tok().assign(TYPE_NUMBER, pos, 1 + xlen, &s[pos..]);
        pos + 1 + xlen
    }

    fn parse_number(&mut self) -> usize {
        let (s, slen) = (self.s, self.s.len());
        let mut pos = self.pos;
        if s[pos] == b'0' && pos + 1 < slen {
            let digits: Option<&[u8]> = match s[pos + 1] {
                b'X' | b'x' => Some(b"0123456789ABCDEFabcdef"),
                b'B' | b'b' => Some(b"01"),
                _ => None,
            };
            if let Some(d) = digits {
                let xlen = strlenspn(&s[pos + 2..], d);
                if xlen == 0 {
                    self.tok().assign(TYPE_BAREWORD, pos, 2, &s[pos..]);
                    return pos + 2;
                }
                self.tok().assign(TYPE_NUMBER, pos, 2 + xlen, &s[pos..]);
                return pos + 2 + xlen;
            }
        }

        let start = pos;
        while pos < slen && is_digit(s[pos]) {
            pos += 1;
        }
        if pos < slen && s[pos] == b'.' {
            pos += 1;
            while pos < slen && is_digit(s[pos]) {
                pos += 1;
            }
            if pos - start == 1 {
                // only "."
                self.tok().assign_char(TYPE_DOT, start, b'.');
                return pos;
            }
        }

        let (mut have_e, mut have_exp) = (false, false);
        if pos < slen && (s[pos] == b'E' || s[pos] == b'e') {
            have_e = true;
            pos += 1;
            if pos < slen && (s[pos] == b'+' || s[pos] == b'-') {
                pos += 1;
            }
            while pos < slen && is_digit(s[pos]) {
                have_exp = true;
                pos += 1;
            }
        }

        // Oracle float/double suffix
        if pos < slen && b"dDfF".contains(&s[pos]) {
            if pos + 1 == slen
                || char_is_white(s[pos + 1])
                || s[pos + 1] == b';'
                || s[pos + 1] == b'u'
                || s[pos + 1] == b'U'
            {
                pos += 1;
            }
        }

        let kind = if have_e && !have_exp {
            TYPE_BAREWORD // "1234.e", ".E"
        } else {
            TYPE_NUMBER
        };
        self.tok().assign(kind, start, pos - start, &s[start..]);
        pos
    }

    fn dispatch(&mut self, ch: u8) -> usize {
        match ch {
            0..=32 | 127 | 160 => self.parse_white(),
            b'!' | b'&' | b'*' | b':' | b'<' | b'=' | b'>' | b'|' => self.parse_operator2(),
            b'"' | b'\'' => self.parse_string(),
            b'#' => self.parse_hash(),
            b'$' => self.parse_money(),
            b'%' | b'+' | b'^' | b'~' => self.parse_operator1(),
            b'(' | b')' | b',' | b';' | b'{' | b'}' => self.parse_char(),
            b'-' => self.parse_dash(),
            b'.' | b'0'..=b'9' => self.parse_number(),
            b'/' => self.parse_slash(),
            b'?' | b']' => self.parse_other(),
            b'@' => self.parse_var(),
            b'B' | b'b' => self.parse_bstring(),
            b'E' | b'e' => self.parse_estring(),
            b'N' | b'n' => self.parse_nqstring(),
            b'Q' | b'q' => self.parse_qstring(),
            b'U' | b'u' => self.parse_ustring(),
            b'X' | b'x' => self.parse_xstring(),
            b'[' => self.parse_bword(),
            b'\\' => self.parse_backslash(),
            b'`' => self.parse_tick(),
            _ => self.parse_word(),
        }
    }

    /// Next token into the current slot; false at the end of the input.
    pub fn tokenize(&mut self) -> bool {
        if self.s.is_empty() {
            return false;
        }
        self.tok().clear();

        // quoting context: pretend the input starts with a quote
        if self.pos == 0 && self.flags & (FLAG_QUOTE_SINGLE | FLAG_QUOTE_DOUBLE) != 0 {
            self.pos = self.parse_string_core(0, flag2delim(self.flags), 0);
            self.stats_tokens += 1;
            return true;
        }

        while self.pos < self.s.len() {
            let ch = self.s[self.pos];
            self.pos = self.dispatch(ch);
            if self.tok().kind != CHAR_NULL {
                self.stats_tokens += 1;
                return true;
            }
        }
        false
    }

    /// Tokenizes into slot `slot`.
    fn tokenize_into(&mut self, slot: usize) -> bool {
        self.cur = slot;
        self.tokenize()
    }

    /// "UNION" + "ALL" -> "UNION ALL" when the pair is a known phrase.
    fn merge_words(&mut self, a: usize, b: usize) -> bool {
        const LEFT: &[u8] = &[
            TYPE_KEYWORD,
            TYPE_BAREWORD,
            TYPE_OPERATOR,
            TYPE_UNION,
            TYPE_FUNCTION,
            TYPE_EXPRESSION,
            TYPE_TSQL,
            TYPE_SQLTYPE,
        ];
        let (ta, tb) = (self.tokens[a], self.tokens[b]);
        if !LEFT.contains(&ta.kind) || !(LEFT.contains(&tb.kind) || tb.kind == TYPE_LOGIC_OPERATOR)
        {
            return false;
        }
        let (sz1, sz2) = (ta.len, tb.len);
        let sz3 = sz1 + sz2 + 1;
        if sz3 >= TOKEN_SIZE {
            return false;
        }
        let mut tmp = [0u8; TOKEN_SIZE];
        tmp[..sz1].copy_from_slice(&ta.val[..sz1]);
        tmp[sz1] = b' ';
        tmp[sz1 + 1..sz3].copy_from_slice(&tb.val[..sz2]);
        let ch = lookup_word(&tmp[..sz3]);
        if ch != CHAR_NULL {
            let pos = ta.pos;
            self.tokens[a].assign(ch, pos, sz3, &tmp);
            true
        } else {
            false
        }
    }

    fn kind(&self, i: usize) -> u8 {
        self.tokens[i].kind
    }

    fn is_word(&self, i: usize, word: &[u8]) -> bool {
        let t = &self.tokens[i];
        cstrcasecmp(word, &t.val[..t.len], t.len) == 0
    }

    /// Folds the tokens; returns how many are in the fingerprint: at most
    /// 5, or up to 7 when MySQL "{ ``" is flagged (as the C code does).
    pub fn fold(&mut self) -> usize {
        let mut last_comment = Token::default();
        let mut pos = 0usize; // where the next token goes
        let mut left = 0usize; // tokens already folded
        let mut more;

        // skip initial comments, '(', sql types and unary operators
        self.cur = 0;
        loop {
            more = self.tokenize();
            let t = &self.tokens[self.cur];
            if !(t.kind == TYPE_COMMENT
                || t.kind == TYPE_LEFTPARENS
                || t.kind == TYPE_SQLTYPE
                || t.is_unary_op())
            {
                break;
            }
            if !more {
                break;
            }
        }
        if !more {
            return 0;
        }
        pos += 1;

        loop {
            if pos >= MAX_TOKENS {
                let k = |i: usize| self.tokens[i].kind;
                if (k(0) == TYPE_NUMBER
                    && (k(1) == TYPE_OPERATOR || k(1) == TYPE_COMMA)
                    && k(2) == TYPE_LEFTPARENS
                    && k(3) == TYPE_NUMBER
                    && k(4) == TYPE_RIGHTPARENS)
                    || (k(0) == TYPE_BAREWORD
                        && k(1) == TYPE_OPERATOR
                        && k(2) == TYPE_LEFTPARENS
                        && (k(3) == TYPE_BAREWORD || k(3) == TYPE_NUMBER)
                        && k(4) == TYPE_RIGHTPARENS)
                    || (k(0) == TYPE_NUMBER
                        && k(1) == TYPE_RIGHTPARENS
                        && k(2) == TYPE_COMMA
                        && k(3) == TYPE_LEFTPARENS
                        && k(4) == TYPE_NUMBER)
                    || (k(0) == TYPE_BAREWORD
                        && k(1) == TYPE_RIGHTPARENS
                        && k(2) == TYPE_OPERATOR
                        && k(3) == TYPE_LEFTPARENS
                        && k(4) == TYPE_BAREWORD)
                {
                    if pos > MAX_TOKENS {
                        self.tokens[1] = self.tokens[MAX_TOKENS];
                        pos = 2;
                    } else {
                        pos = 1;
                    }
                    left = 0;
                }
            }

            if !more || left >= MAX_TOKENS {
                left = pos;
                break;
            }

            // get up to two tokens
            while more && pos <= MAX_TOKENS && pos - left < 2 {
                more = self.tokenize_into(pos);
                if more {
                    if self.kind(pos) == TYPE_COMMENT {
                        last_comment = self.tokens[pos];
                    } else {
                        last_comment.kind = CHAR_NULL;
                        pos += 1;
                    }
                }
            }
            if pos - left < 2 {
                left = pos;
                continue;
            }

            let (l, r) = (left, left + 1);
            let (kl, kr) = (self.kind(l), self.kind(r));

            if kl == TYPE_STRING && kr == TYPE_STRING {
                pos -= 1;
                self.stats_folds += 1;
                continue;
            } else if kl == TYPE_SEMICOLON && kr == TYPE_SEMICOLON {
                pos -= 1;
                self.stats_folds += 1;
                continue;
            } else if (kl == TYPE_OPERATOR || kl == TYPE_LOGIC_OPERATOR)
                && (self.tokens[r].is_unary_op() || kr == TYPE_SQLTYPE)
            {
                pos -= 1;
                self.stats_folds += 1;
                left = 0;
                continue;
            } else if kl == TYPE_LEFTPARENS && self.tokens[r].is_unary_op() {
                pos -= 1;
                self.stats_folds += 1;
                left = left.saturating_sub(1);
                continue;
            } else if self.merge_words(l, r) {
                pos -= 1;
                self.stats_folds += 1;
                left = left.saturating_sub(1);
                continue;
            } else if kl == TYPE_SEMICOLON
                && kr == TYPE_FUNCTION
                && (self.tokens[r].val[0] == b'I' || self.tokens[r].val[0] == b'i')
                && (self.tokens[r].val[1] == b'F' || self.tokens[r].val[1] == b'f')
            {
                // T-SQL "; IF ..."
                self.tokens[r].kind = TYPE_TSQL;
                continue;
            } else if (kl == TYPE_BAREWORD || kl == TYPE_VARIABLE)
                && kr == TYPE_LEFTPARENS
                && [
                    &b"USER_ID"[..],
                    b"USER_NAME",
                    b"DATABASE",
                    b"PASSWORD",
                    b"USER",
                    b"CURRENT_USER",
                    b"CURRENT_DATE",
                    b"CURRENT_TIME",
                    b"CURRENT_TIMESTAMP",
                    b"LOCALTIME",
                    b"LOCALTIMESTAMP",
                ]
                .iter()
                .any(|w| self.is_word(l, w))
            {
                self.tokens[l].kind = TYPE_FUNCTION;
                continue;
            } else if kl == TYPE_KEYWORD && (self.is_word(l, b"IN") || self.is_word(l, b"NOT IN")) {
                self.tokens[l].kind = if kr == TYPE_LEFTPARENS {
                    TYPE_OPERATOR
                } else {
                    TYPE_BAREWORD
                };
                continue;
            } else if kl == TYPE_OPERATOR
                && (self.is_word(l, b"LIKE") || self.is_word(l, b"NOT LIKE"))
            {
                if kr == TYPE_LEFTPARENS {
                    self.tokens[l].kind = TYPE_FUNCTION;
                }
            } else if kl == TYPE_SQLTYPE
                && [
                    TYPE_BAREWORD,
                    TYPE_NUMBER,
                    TYPE_SQLTYPE,
                    TYPE_LEFTPARENS,
                    TYPE_FUNCTION,
                    TYPE_VARIABLE,
                    TYPE_STRING,
                ]
                .contains(&kr)
            {
                self.tokens[l] = self.tokens[r];
                pos -= 1;
                self.stats_folds += 1;
                left = 0;
                continue;
            } else if kl == TYPE_COLLATE && kr == TYPE_BAREWORD {
                if self.tokens[r].value().contains(&b'_') {
                    self.tokens[r].kind = TYPE_SQLTYPE;
                    left = 0;
                }
            } else if kl == TYPE_BACKSLASH {
                if self.tokens[r].is_arithmetic_op() {
                    // T-SQL: '\%1' is '0 % 1'
                    self.tokens[l].kind = TYPE_NUMBER;
                } else {
                    // T-SQL: '\1' is '1'
                    self.tokens[l] = self.tokens[r];
                    pos -= 1;
                    self.stats_folds += 1;
                }
                left = 0;
                continue;
            } else if (kl == TYPE_LEFTPARENS && kr == TYPE_LEFTPARENS)
                || (kl == TYPE_RIGHTPARENS && kr == TYPE_RIGHTPARENS)
            {
                pos -= 1;
                left = 0;
                self.stats_folds += 1;
                continue;
            } else if kl == TYPE_LEFTBRACE && kr == TYPE_BAREWORD {
                // MySQL "{ ``.``.id }": blacklisted
                if self.tokens[r].len == 0 {
                    self.tokens[r].kind = TYPE_EVIL;
                    return left + 2;
                }
                // ODBC "{foo expr}" -> expr
                left = 0;
                pos -= 2;
                self.stats_folds += 2;
                continue;
            } else if kr == TYPE_RIGHTBRACE {
                pos -= 1;
                left = 0;
                self.stats_folds += 1;
                continue;
            }

            // no two-token fold: get a third token
            while more && pos <= MAX_TOKENS && pos - left < 3 {
                more = self.tokenize_into(pos);
                if more {
                    if self.kind(pos) == TYPE_COMMENT {
                        last_comment = self.tokens[pos];
                    } else {
                        last_comment.kind = CHAR_NULL;
                        pos += 1;
                    }
                }
            }
            if pos - left < 3 {
                left = pos;
                continue;
            }

            let (a, b, c) = (left, left + 1, left + 2);
            let (ka, kb, kc) = (self.kind(a), self.kind(b), self.kind(c));
            let unary_b = self.tokens[b].is_unary_op();

            if ka == TYPE_NUMBER && kb == TYPE_OPERATOR && kc == TYPE_NUMBER {
                pos -= 2;
                left = 0;
                continue;
            } else if ka == TYPE_OPERATOR && kb != TYPE_LEFTPARENS && kc == TYPE_OPERATOR {
                left = 0;
                pos -= 2;
                continue;
            } else if ka == TYPE_LOGIC_OPERATOR && kc == TYPE_LOGIC_OPERATOR {
                pos -= 2;
                left = 0;
                continue;
            } else if ka == TYPE_VARIABLE
                && kb == TYPE_OPERATOR
                && (kc == TYPE_VARIABLE || kc == TYPE_NUMBER || kc == TYPE_BAREWORD)
            {
                pos -= 2;
                left = 0;
                continue;
            } else if (ka == TYPE_BAREWORD || ka == TYPE_NUMBER)
                && kb == TYPE_OPERATOR
                && (kc == TYPE_NUMBER || kc == TYPE_BAREWORD)
            {
                pos -= 2;
                left = 0;
                continue;
            } else if (ka == TYPE_BAREWORD
                || ka == TYPE_NUMBER
                || ka == TYPE_VARIABLE
                || ka == TYPE_STRING)
                && kb == TYPE_OPERATOR
                && self.tokens[b].value() == b"::"
                && kc == TYPE_SQLTYPE
            {
                pos -= 2;
                left = 0;
                self.stats_folds += 2;
                continue;
            } else if (ka == TYPE_BAREWORD
                || ka == TYPE_NUMBER
                || ka == TYPE_STRING
                || ka == TYPE_VARIABLE)
                && kb == TYPE_COMMA
                && (kc == TYPE_NUMBER
                    || kc == TYPE_BAREWORD
                    || kc == TYPE_STRING
                    || kc == TYPE_VARIABLE)
            {
                pos -= 2;
                left = 0;
                continue;
            } else if (ka == TYPE_EXPRESSION || ka == TYPE_GROUP || ka == TYPE_COMMA)
                && unary_b
                && kc == TYPE_LEFTPARENS
            {
                // "SELECT + (", "LIMIT + (": drop the unary operator
                self.tokens[b] = self.tokens[c];
                pos -= 1;
                left = 0;
                continue;
            } else if (ka == TYPE_KEYWORD || ka == TYPE_EXPRESSION || ka == TYPE_GROUP)
                && unary_b
                && (kc == TYPE_NUMBER
                    || kc == TYPE_BAREWORD
                    || kc == TYPE_VARIABLE
                    || kc == TYPE_STRING
                    || kc == TYPE_FUNCTION)
            {
                // "select - 1"
                self.tokens[b] = self.tokens[c];
                pos -= 1;
                left = 0;
                continue;
            } else if ka == TYPE_COMMA
                && unary_b
                && (kc == TYPE_NUMBER
                    || kc == TYPE_BAREWORD
                    || kc == TYPE_VARIABLE
                    || kc == TYPE_STRING)
            {
                // ", -1" -> ",1", then back up: "1,-1" -> "1"
                self.tokens[b] = self.tokens[c];
                left = 0;
                pos -= 3;
                continue;
            } else if ka == TYPE_COMMA && unary_b && kc == TYPE_FUNCTION {
                // "1,-sin(1)" -> "1,sin(1)"
                self.tokens[b] = self.tokens[c];
                pos -= 1;
                left = 0;
                continue;
            } else if ka == TYPE_BAREWORD && kb == TYPE_DOT && kc == TYPE_BAREWORD {
                // databasename.table
                pos -= 2;
                left = 0;
                continue;
            } else if ka == TYPE_EXPRESSION && kb == TYPE_DOT && kc == TYPE_BAREWORD {
                // "select . `foo`" -> "select `foo`"
                self.tokens[b] = self.tokens[c];
                pos -= 1;
                left = 0;
                continue;
            } else if ka == TYPE_FUNCTION && kb == TYPE_LEFTPARENS && kc != TYPE_RIGHTPARENS {
                // USER(foo): not the 0-argument function
                if self.is_word(a, b"USER") {
                    self.tokens[a].kind = TYPE_BAREWORD;
                }
            }

            left += 1;
        }

        // 4 tokens or less and a trailing comment: add it back
        if left < MAX_TOKENS && last_comment.kind == TYPE_COMMENT {
            self.tokens[left] = last_comment;
            left += 1;
        }
        left.min(MAX_TOKENS)
    }

    /// Fingerprint of the input in a quoting/dialect context.
    pub fn fingerprint(&mut self, flags: u32) -> &[u8] {
        self.reset(flags);
        let tlen = self.fold();

        // PHP: an empty, unclosed backtick bareword at the end is a comment
        if tlen > 2 {
            let t = &mut self.tokens[tlen - 1];
            if t.kind == TYPE_BAREWORD
                && t.str_open == CHAR_TICK
                && t.len == 0
                && t.str_close == CHAR_NULL
            {
                t.kind = TYPE_COMMENT;
            }
        }
        for i in 0..tlen {
            self.fingerprint[i] = self.tokens[i].kind;
        }
        self.fingerprint[tlen] = CHAR_NULL;

        // unparsable input
        if self.fingerprint[..tlen].contains(&TYPE_EVIL) {
            self.fingerprint = [0; 8];
            self.tokens[0].val = [0; TOKEN_SIZE];
            self.fingerprint[0] = TYPE_EVIL;
            self.tokens[0].kind = TYPE_EVIL;
            self.tokens[0].val[0] = TYPE_EVIL;
            self.tokens[1].kind = CHAR_NULL;
        }
        self.fingerprint_str()
    }

    /// The fingerprint is in the SQLi list.
    pub fn blacklist(&self) -> bool {
        let fp = self.fingerprint_str();
        if fp.is_empty() {
            return false;
        }
        let mut fp2 = [0u8; 8];
        fp2[0] = b'0';
        for (i, &c) in fp.iter().enumerate() {
            fp2[i + 1] = c.to_ascii_uppercase();
        }
        lookup_word(&fp2[..fp.len() + 1]) == TYPE_FINGERPRINT
    }

    /// False positive filters for a blacklisted fingerprint: true = SQLi.
    pub fn not_whitelist(&self) -> bool {
        let fp = self.fingerprint_str();
        let tlen = fp.len();
        let t = &self.tokens;

        if tlen > 1 && fp[tlen - 1] == TYPE_COMMENT && memmem(self.s, b"sp_password").is_some() {
            // MS SQL audit logs skip statements mentioning sp_password
            return true;
        }

        match tlen {
            2 => {
                if fp[1] == TYPE_UNION {
                    // "1 union": SQLi only with folding or comments
                    return self.stats_tokens != 2;
                }
                // '#' comments: too many false positives
                if t[1].val[0] == b'#' {
                    return false;
                }
                // "nc": only /* comments are SQL
                if t[0].kind == TYPE_BAREWORD && t[1].kind == TYPE_COMMENT && t[1].val[0] != b'/' {
                    return false;
                }
                if t[0].kind == TYPE_NUMBER && t[1].kind == TYPE_COMMENT && t[1].val[0] == b'/' {
                    return true;
                }
                // "1c": the number must really end at whitespace, /* or --
                if t[0].kind == TYPE_NUMBER && t[1].kind == TYPE_COMMENT {
                    if self.stats_tokens > 2 {
                        return true;
                    }
                    let n = t[0].len;
                    let ch = self.at(n);
                    if (ch as i8) <= 32 {
                        return true;
                    }
                    if ch == b'/' && self.at(n + 1) == b'*' {
                        return true;
                    }
                    if ch == b'-' && self.at(n + 1) == b'-' {
                        return true;
                    }
                    return false;
                }
                // "1-- foo" (text with --): only when ending with --
                if t[1].len > 2 && t[1].val[0] == b'-' {
                    return false;
                }
            }
            3 => {
                if fp == b"sos" || fp == b"s&s" {
                    // ...foo' + 'bar...
                    return t[0].str_open == CHAR_NULL
                        && t[2].str_close == CHAR_NULL
                        && t[0].str_close == t[2].str_open;
                } else if [&b"s&n"[..], b"n&1", b"1&1", b"1&v", b"1&s"].contains(&fp) {
                    // 'sexy and 17' is not SQLi, 'sexy and 17<18' is
                    if self.stats_tokens == 3 {
                        return false;
                    }
                } else if t[1].kind == TYPE_KEYWORD
                    && (t[1].len < 5 || cstrcasecmp(b"INTO", &t[1].val[..4], 4) != 0)
                {
                    // only INTO OUTFILE / INTO DUMPFILE
                    return false;
                }
            }
            _ => {}
        }
        true
    }

    fn check_fingerprint(&self) -> bool {
        self.blacklist() && self.not_whitelist()
    }

    fn reparse_as_mysql(&self) -> bool {
        self.stats_comment_ddx != 0 || self.stats_comment_hash != 0
    }

    /// Main check over every quoting context.
    pub fn is_sqli(&mut self) -> bool {
        if self.s.is_empty() {
            return false;
        }
        self.fingerprint(FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
        if self.check_fingerprint() {
            return true;
        } else if self.reparse_as_mysql() {
            self.fingerprint(FLAG_QUOTE_NONE | FLAG_SQL_MYSQL);
            if self.check_fingerprint() {
                return true;
            }
        }
        if self.s.contains(&CHAR_SINGLE) {
            self.fingerprint(FLAG_QUOTE_SINGLE | FLAG_SQL_ANSI);
            if self.check_fingerprint() {
                return true;
            } else if self.reparse_as_mysql() {
                self.fingerprint(FLAG_QUOTE_SINGLE | FLAG_SQL_MYSQL);
                if self.check_fingerprint() {
                    return true;
                }
            }
        }
        if self.s.contains(&CHAR_DOUBLE) {
            self.fingerprint(FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL);
            if self.check_fingerprint() {
                return true;
            }
        }
        false
    }
}

/// `libinjection_sqli`: the fingerprint when `input` is SQLi.
pub fn detect(input: &[u8]) -> Option<Fingerprint> {
    let mut st = State::new(input, 0);
    if st.is_sqli() {
        let fp = st.fingerprint_str();
        let mut out = Fingerprint([0; 8], fp.len() as u8);
        out.0[..fp.len()].copy_from_slice(fp);
        Some(out)
    } else {
        None
    }
}

/// A fingerprint (at most 5 token types).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint([u8; 8], u8);

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..self.1 as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_table_is_sorted_for_the_search() {
        for w in KEYWORDS.windows(2) {
            assert!(
                cstrcasecmp(w[0].0, w[1].0, w[1].0.len()) < 0,
                "{:?}",
                w[0].0
            );
        }
        assert_eq!(lookup_word(b"select"), TYPE_EXPRESSION);
        assert_eq!(lookup_word(b"UNION ALL"), TYPE_UNION);
        assert_eq!(lookup_word(b"0S&1"), TYPE_FINGERPRINT);
        assert_eq!(lookup_word(b"strata"), CHAR_NULL);
    }

    #[test]
    fn classic_injections() {
        for (input, fp) in [
            (&b"1' OR '1'='1"[..], &b"s&sos"[..]),
            (b"1 UNION SELECT password FROM users--", b"1UEnk"),
            (b"admin'--", b"sc"),
        ] {
            assert_eq!(
                detect(input).map(|f| f.as_bytes().to_vec()),
                Some(fp.to_vec()),
                "{}",
                input.escape_ascii()
            );
        }
        for input in [&b"hello world"[..], b"O'Reilly", b"1234", b"", b"a=1&b=2"] {
            assert_eq!(detect(input), None, "{}", input.escape_ascii());
        }
    }
}
