//! HTML5 tokenizer for XSS detection: a port of libinjection v3.10.0
//! `libinjection_html5.c` (BSD-3-Clause, Copyright (c) 2012-2016 Nick
//! Galbreath; see engine/NOTICE).
//!
//! The C code chains states by tail calls (`return h5_state_x(hs)`), which
//! can recurse once per input byte (e.g. "<a ////..."). Here a state either
//! emits a token or names the next state to run, in a loop: no recursion.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenType {
    DataText,
    TagNameOpen,
    TagNameClose,
    TagNameSelfclose,
    TagData,
    TagClose,
    AttrName,
    AttrValue,
    TagComment,
    Doctype,
}

impl TokenType {
    pub fn name(self) -> &'static str {
        match self {
            TokenType::DataText => "DATA_TEXT",
            TokenType::TagNameOpen => "TAG_NAME_OPEN",
            TokenType::TagNameClose => "TAG_NAME_CLOSE",
            TokenType::TagNameSelfclose => "TAG_NAME_SELFCLOSE",
            TokenType::TagData => "TAG_DATA",
            TokenType::TagClose => "TAG_CLOSE",
            TokenType::AttrName => "ATTR_NAME",
            TokenType::AttrValue => "ATTR_VALUE",
            TokenType::TagComment => "TAG_COMMENT",
            TokenType::Doctype => "DOCTYPE",
        }
    }
}

/// Initial context of the input (`enum html5_flags`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flags {
    DataState,
    ValueNoQuote,
    ValueSingleQuote,
    ValueDoubleQuote,
    ValueBackQuote,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    Eof,
    Data,
    TagOpen,
    TagName,
    TagNameClose,
    EndTagOpen,
    SelfClosingStartTag,
    AttributeName,
    AfterAttributeName,
    BeforeAttributeName,
    BeforeAttributeValue,
    ValueDoubleQuote,
    ValueSingleQuote,
    ValueBackQuote,
    ValueNoQuote,
    AfterAttributeValueQuoted,
    Comment,
    Cdata,
    BogusComment,
    BogusComment2,
    MarkupDeclarationOpen,
    Doctype,
}

/// What a state did.
enum Step {
    /// a token is ready (`return 1`)
    Token,
    /// no more tokens (`return 0`)
    End,
    /// run this state now (tail call)
    Go(St),
}

const CHAR_EOF: i32 = -1;

/// `strchr(" \t\n\v\f\r", c)`: the NUL terminator matches too.
fn is_white(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | 0)
}

#[inline(always)]
fn skip_non_delims(s: &[u8], mut pos: usize) -> usize {
    while pos + 8 <= s.len() {
        let v = u64::from_le_bytes(s[pos..pos + 8].try_into().unwrap());
        let sub = v.wrapping_sub(0x3f3f3f3f3f3f3f3f);
        if (sub & !v & 0x8080808080808080) != 0 {
            break;
        }
        pos += 8;
    }
    pos
}

pub struct Html5<'a> {
    s: &'a [u8],
    pos: usize,
    is_close: bool,
    state: St,
    pub token_start: usize,
    pub token_len: usize,
    pub token_type: TokenType,
}

impl<'a> Html5<'a> {
    pub fn new(s: &'a [u8], flags: Flags) -> Html5<'a> {
        let state = match flags {
            Flags::DataState => St::Data,
            Flags::ValueNoQuote => St::BeforeAttributeName,
            Flags::ValueSingleQuote => St::ValueSingleQuote,
            Flags::ValueDoubleQuote => St::ValueDoubleQuote,
            Flags::ValueBackQuote => St::ValueBackQuote,
        };
        Html5 {
            s,
            pos: 0,
            is_close: false,
            state,
            token_start: 0,
            token_len: 0,
            token_type: TokenType::DataText,
        }
    }

    /// The bytes of the current token.
    pub fn token(&self) -> &'a [u8] {
        &self.s[self.token_start..self.token_start + self.token_len]
    }

    /// Next token; false at the end.
    pub fn next_token(&mut self) -> bool {
        let mut st = self.state;
        loop {
            match self.run(st) {
                Step::Token => return true,
                Step::End => return false,
                Step::Go(next) => st = next,
            }
        }
    }

    fn emit(&mut self, start: usize, len: usize, t: TokenType) {
        self.token_start = start;
        self.token_len = len;
        self.token_type = t;
    }

    fn len(&self) -> usize {
        self.s.len()
    }

    /// `h5_skip_white`: the next non-blank byte as a signed C `char`
    /// (bytes >= 128 are negative, 0xFF reads as EOF), or EOF.
    fn skip_white(&mut self) -> i32 {
        while self.pos < self.len() {
            let c = self.s[self.pos];
            match c {
                0x00 | 0x20 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d => self.pos += 1,
                _ => return c as i8 as i32,
            }
        }
        CHAR_EOF
    }

    fn find(&self, from: usize, c: u8) -> Option<usize> {
        memchr::memchr(c, &self.s[from..]).map(|i| from + i)
    }

    fn run(&mut self, st: St) -> Step {
        match st {
            St::Eof => Step::End,
            St::Data => self.data(),
            St::TagOpen => self.tag_open(),
            St::TagName => self.tag_name(),
            St::TagNameClose => self.tag_name_close(),
            St::EndTagOpen => self.end_tag_open(),
            St::SelfClosingStartTag => self.self_closing_start_tag(),
            St::AttributeName => self.attribute_name(),
            St::AfterAttributeName => self.after_attribute_name(),
            St::BeforeAttributeName => self.before_attribute_name(),
            St::BeforeAttributeValue => self.before_attribute_value(),
            St::ValueDoubleQuote => self.attribute_value_quote(b'"'),
            St::ValueSingleQuote => self.attribute_value_quote(b'\''),
            St::ValueBackQuote => self.attribute_value_quote(b'`'),
            St::ValueNoQuote => self.attribute_value_no_quote(),
            St::AfterAttributeValueQuoted => self.after_attribute_value_quoted(),
            St::Comment => self.comment(),
            St::Cdata => self.cdata(),
            St::BogusComment => self.bogus_comment(),
            St::BogusComment2 => self.bogus_comment2(),
            St::MarkupDeclarationOpen => self.markup_declaration_open(),
            St::Doctype => self.doctype(),
        }
    }

    fn data(&mut self) -> Step {
        match self.find(self.pos, b'<') {
            None => {
                self.emit(self.pos, self.len() - self.pos, TokenType::DataText);
                self.state = St::Eof;
                if self.token_len == 0 {
                    return Step::End;
                }
            }
            Some(idx) => {
                self.emit(self.pos, idx - self.pos, TokenType::DataText);
                self.pos = idx + 1;
                self.state = St::TagOpen;
                if self.token_len == 0 {
                    return Step::Go(St::TagOpen);
                }
            }
        }
        Step::Token
    }

    fn tag_open(&mut self) -> Step {
        if self.pos >= self.len() {
            return Step::End;
        }
        let ch = self.s[self.pos];
        match ch {
            b'!' => {
                self.pos += 1;
                Step::Go(St::MarkupDeclarationOpen)
            }
            b'/' => {
                self.pos += 1;
                self.is_close = true;
                Step::Go(St::EndTagOpen)
            }
            b'?' => {
                self.pos += 1;
                Step::Go(St::BogusComment)
            }
            b'%' => {
                // IE <= 9 and Safari < 4.0.3 comments
                self.pos += 1;
                Step::Go(St::BogusComment2)
            }
            // NUL: IE ignores it in tag names
            b'a'..=b'z' | b'A'..=b'Z' | 0 => Step::Go(St::TagName),
            _ => {
                if self.pos == 0 {
                    return Step::Go(St::Data);
                }
                self.emit(self.pos - 1, 1, TokenType::DataText);
                self.state = St::Data;
                Step::Token
            }
        }
    }

    fn end_tag_open(&mut self) -> Step {
        if self.pos >= self.len() {
            return Step::End;
        }
        match self.s[self.pos] {
            b'>' => Step::Go(St::Data),
            b'a'..=b'z' | b'A'..=b'Z' => Step::Go(St::TagName),
            _ => {
                self.is_close = false;
                Step::Go(St::BogusComment)
            }
        }
    }

    fn tag_name_close(&mut self) -> Step {
        self.is_close = false;
        self.emit(self.pos, 1, TokenType::TagNameClose);
        self.pos += 1;
        self.state = if self.pos < self.len() {
            St::Data
        } else {
            St::Eof
        };
        Step::Token
    }

    fn tag_name(&mut self) -> Step {
        let mut pos = self.pos;
        while pos < self.len() {
            pos = skip_non_delims(self.s, pos);
            if pos >= self.len() {
                break;
            }
            let ch = self.s[pos];
            if ch == 0 {
                // nulls in tag names: allowed and ignored by old browsers
                pos += 1;
            } else if is_white(ch) {
                self.emit(self.pos, pos - self.pos, TokenType::TagNameOpen);
                self.pos = pos + 1;
                self.state = St::BeforeAttributeName;
                return Step::Token;
            } else if ch == b'/' {
                self.emit(self.pos, pos - self.pos, TokenType::TagNameOpen);
                self.pos = pos + 1;
                self.state = St::SelfClosingStartTag;
                return Step::Token;
            } else if ch == b'>' {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                if self.is_close {
                    self.pos = pos + 1;
                    self.is_close = false;
                    self.token_type = TokenType::TagClose;
                    self.state = St::Data;
                } else {
                    self.pos = pos;
                    self.token_type = TokenType::TagNameOpen;
                    self.state = St::TagNameClose;
                }
                return Step::Token;
            } else {
                pos += 1;
            }
        }
        self.emit(self.pos, self.len() - self.pos, TokenType::TagNameOpen);
        self.state = St::Eof;
        self.pos = self.len();
        Step::Token
    }

    fn before_attribute_name(&mut self) -> Step {
        let ch = self.skip_white();
        if ch == CHAR_EOF {
            return Step::End;
        }
        if ch == b'/' as i32 {
            self.pos += 1;
            return Step::Go(St::SelfClosingStartTag);
        }
        if ch == b'>' as i32 {
            self.state = St::Data;
            self.emit(self.pos, 1, TokenType::TagNameClose);
            self.pos += 1;
            return Step::Token;
        }
        Step::Go(St::AttributeName)
    }

    fn attribute_name(&mut self) -> Step {
        let mut pos = self.pos + 1;
        while pos < self.len() {
            pos = skip_non_delims(self.s, pos);
            if pos >= self.len() {
                break;
            }
            let ch = self.s[pos];
            let next = if is_white(ch) {
                Some((St::AfterAttributeName, pos + 1))
            } else if ch == b'/' {
                Some((St::SelfClosingStartTag, pos + 1))
            } else if ch == b'=' {
                Some((St::BeforeAttributeValue, pos + 1))
            } else if ch == b'>' {
                Some((St::TagNameClose, pos))
            } else {
                None
            };
            if let Some((state, new_pos)) = next {
                self.emit(self.pos, pos - self.pos, TokenType::AttrName);
                self.state = state;
                self.pos = new_pos;
                return Step::Token;
            }
            pos += 1;
        }
        self.emit(self.pos, self.len() - self.pos, TokenType::AttrName);
        self.state = St::Eof;
        self.pos = self.len();
        Step::Token
    }

    fn after_attribute_name(&mut self) -> Step {
        let c = self.skip_white();
        if c == CHAR_EOF {
            Step::End
        } else if c == b'/' as i32 {
            self.pos += 1;
            Step::Go(St::SelfClosingStartTag)
        } else if c == b'=' as i32 {
            self.pos += 1;
            Step::Go(St::BeforeAttributeValue)
        } else if c == b'>' as i32 {
            Step::Go(St::TagNameClose)
        } else {
            Step::Go(St::AttributeName)
        }
    }

    fn before_attribute_value(&mut self) -> Step {
        let c = self.skip_white();
        if c == CHAR_EOF {
            self.state = St::Eof;
            return Step::End;
        }
        if c == b'"' as i32 {
            Step::Go(St::ValueDoubleQuote)
        } else if c == b'\'' as i32 {
            Step::Go(St::ValueSingleQuote)
        } else if c == b'`' as i32 {
            // non-standard, IE
            Step::Go(St::ValueBackQuote)
        } else {
            Step::Go(St::ValueNoQuote)
        }
    }

    fn attribute_value_quote(&mut self, q: u8) -> Step {
        // skip the opening quote, except when the input starts in this
        // state ('><foo gives a 0-length value)
        if self.pos > 0 {
            self.pos += 1;
        }
        let from = self.pos.min(self.len());
        match self.find(from, q) {
            None => {
                self.emit(from, self.len() - from, TokenType::AttrValue);
                self.state = St::Eof;
            }
            Some(idx) => {
                self.emit(self.pos, idx - self.pos, TokenType::AttrValue);
                self.state = St::AfterAttributeValueQuoted;
                self.pos += self.token_len + 1;
            }
        }
        Step::Token
    }

    fn attribute_value_no_quote(&mut self) -> Step {
        let mut pos = self.pos;
        while pos < self.len() {
            pos = skip_non_delims(self.s, pos);
            if pos >= self.len() {
                break;
            }
            let ch = self.s[pos];
            if is_white(ch) {
                self.emit(self.pos, pos - self.pos, TokenType::AttrValue);
                self.pos = pos + 1;
                self.state = St::BeforeAttributeName;
                return Step::Token;
            } else if ch == b'>' {
                self.emit(self.pos, pos - self.pos, TokenType::AttrValue);
                self.pos = pos;
                self.state = St::TagNameClose;
                return Step::Token;
            }
            pos += 1;
        }
        self.state = St::Eof;
        self.emit(self.pos, self.len() - self.pos, TokenType::AttrValue);
        Step::Token
    }

    fn after_attribute_value_quoted(&mut self) -> Step {
        if self.pos >= self.len() {
            return Step::End;
        }
        let ch = self.s[self.pos];
        if is_white(ch) {
            self.pos += 1;
            Step::Go(St::BeforeAttributeName)
        } else if ch == b'/' {
            self.pos += 1;
            Step::Go(St::SelfClosingStartTag)
        } else if ch == b'>' {
            self.emit(self.pos, 1, TokenType::TagNameClose);
            self.pos += 1;
            self.state = St::Data;
            Step::Token
        } else {
            Step::Go(St::BeforeAttributeName)
        }
    }

    fn self_closing_start_tag(&mut self) -> Step {
        if self.pos >= self.len() {
            return Step::End;
        }
        if self.s[self.pos] == b'>' {
            self.emit(self.pos - 1, 2, TokenType::TagNameSelfclose);
            self.state = St::Data;
            self.pos += 1;
            Step::Token
        } else {
            Step::Go(St::BeforeAttributeName)
        }
    }

    fn bogus_comment(&mut self) -> Step {
        match self.find(self.pos, b'>') {
            None => {
                self.emit(self.pos, self.len() - self.pos, TokenType::TagComment);
                self.pos = self.len();
                self.state = St::Eof;
            }
            Some(idx) => {
                self.emit(self.pos, idx - self.pos, TokenType::TagComment);
                self.pos = idx + 1;
                self.state = St::Data;
            }
        }
        Step::Token
    }

    /// `<% ... %>`
    fn bogus_comment2(&mut self) -> Step {
        let mut pos = self.pos;
        loop {
            match self.find(pos, b'%') {
                Some(idx) if idx + 1 < self.len() => {
                    if self.s[idx + 1] != b'>' {
                        pos = idx + 1;
                        continue;
                    }
                    self.emit(self.pos, idx - self.pos, TokenType::TagComment);
                    self.pos = idx + 2;
                    self.state = St::Data;
                    return Step::Token;
                }
                _ => {
                    self.emit(self.pos, self.len() - self.pos, TokenType::TagComment);
                    self.pos = self.len();
                    self.state = St::Eof;
                    return Step::Token;
                }
            }
        }
    }

    fn markup_declaration_open(&mut self) -> Step {
        let rest = &self.s[self.pos..];
        if rest.len() >= 7 && rest[..7].eq_ignore_ascii_case(b"DOCTYPE") {
            Step::Go(St::Doctype)
        } else if rest.len() >= 7 && &rest[..7] == b"[CDATA[" {
            self.pos += 7;
            Step::Go(St::Cdata)
        } else if rest.len() >= 2 && &rest[..2] == b"--" {
            self.pos += 2;
            Step::Go(St::Comment)
        } else {
            Step::Go(St::BogusComment)
        }
    }

    fn comment_to_eof(&mut self) -> Step {
        self.state = St::Eof;
        self.emit(self.pos, self.len() - self.pos, TokenType::TagComment);
        Step::Token
    }

    /// Comments end at EOF, "-->" or "-!>" (NULs after the first '-' are
    /// skipped).
    fn comment(&mut self) -> Step {
        let end = self.len();
        let mut pos = self.pos;
        loop {
            let idx = match self.find(pos, b'-') {
                Some(i) if i + 3 <= end => i,
                _ => return self.comment_to_eof(),
            };
            let mut offset = 1;
            while idx + offset < end && self.s[idx + offset] == 0 {
                offset += 1;
            }
            if idx + offset == end {
                return self.comment_to_eof();
            }
            let ch = self.s[idx + offset];
            if ch != b'-' && ch != b'!' {
                pos = idx + 1;
                continue;
            }
            offset += 1;
            if idx + offset == end {
                return self.comment_to_eof();
            }
            if self.s[idx + offset] != b'>' {
                pos = idx + 1;
                continue;
            }
            offset += 1;
            self.emit(self.pos, idx - self.pos, TokenType::TagComment);
            self.pos = idx + offset;
            self.state = St::Data;
            return Step::Token;
        }
    }

    fn cdata(&mut self) -> Step {
        let end = self.len();
        let mut pos = self.pos;
        loop {
            match self.find(pos, b']') {
                Some(idx) if idx + 3 <= end => {
                    if self.s[idx + 1] == b']' && self.s[idx + 2] == b'>' {
                        self.state = St::Data;
                        self.emit(self.pos, idx - self.pos, TokenType::DataText);
                        self.pos = idx + 3;
                        return Step::Token;
                    }
                    pos = idx + 1;
                }
                _ => {
                    self.state = St::Eof;
                    self.emit(self.pos, end - self.pos, TokenType::DataText);
                    return Step::Token;
                }
            }
        }
    }

    fn doctype(&mut self) -> Step {
        self.token_start = self.pos;
        self.token_type = TokenType::Doctype;
        match self.find(self.pos, b'>') {
            None => {
                self.state = St::Eof;
                self.token_len = self.len() - self.pos;
            }
            Some(idx) => {
                self.state = St::Data;
                self.token_len = idx - self.pos;
                self.pos = idx + 1;
            }
        }
        Step::Token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(s: &[u8]) -> Vec<(TokenType, Vec<u8>)> {
        let mut h = Html5::new(s, Flags::DataState);
        let mut out = vec![];
        while h.next_token() {
            out.push((h.token_type, h.token().to_vec()));
        }
        out
    }

    #[test]
    fn simple_tag() {
        assert_eq!(
            tokens(b"a<b c=d>e"),
            [
                (TokenType::DataText, b"a".to_vec()),
                (TokenType::TagNameOpen, b"b".to_vec()),
                (TokenType::AttrName, b"c".to_vec()),
                (TokenType::AttrValue, b"d".to_vec()),
                (TokenType::TagNameClose, b">".to_vec()),
                (TokenType::DataText, b"e".to_vec()),
            ]
        );
    }

    #[test]
    fn long_slash_runs_do_not_recurse() {
        let mut s = b"<a ".to_vec();
        s.extend(std::iter::repeat_n(b'/', 1_000_000));
        let n = tokens(&s).len();
        assert!(n >= 1);
    }
}
