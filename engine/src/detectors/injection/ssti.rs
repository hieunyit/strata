//! Server-Side Template Injection (SSTI) Semantic Detector (W17-R-01).
//!
//! Lexical analysis of template engine expressions (Jinja2, Twig, Django, Spring EL,
//! OGNL, ERB, EJS, Freemarker, Velocity). Detects template delimiter enclosures
//! containing math probes, reflection/class traversal, environment access, or
//! execution primitives.
#![forbid(unsafe_code)]

/// Dangerous keywords and attributes associated with SSTI sandbox escapes and reflection.
const SSTI_DANGEROUS_PATTERNS: &[&[u8]] = &[
    b"__class__",
    b"__mro__",
    b"__subclasses__",
    b"__globals__",
    b"__builtins__",
    b"__import__",
    b"__init__",
    b"__base__",
    b"__bases__",
    b"t(java.lang",
    b"java.lang.runtime",
    b"processbuilder",
    b"getclass()",
    b"getruntime()",
    b"getmethod(",
    b"config.items",
    b"request.application",
    b"request.environ",
    b"settings.secret_key",
    b".exec(",
    b".system(",
    b".popen(",
    b"popen(",
    b"eval(",
    b"passthru(",
];

/// Detects SSTI-like template expressions in arbitrary bytes.
///
/// This component does not enable a rule or add an IR operator. Each closer
/// search advances monotonically, including malformed/unclosed templates.
pub fn detect(input: &[u8]) -> bool {
    scan(input, |_| {})
}

#[derive(Default)]
struct Closer {
    searched: bool,
    next: Option<usize>,
}

impl Closer {
    fn find(
        &mut self,
        input: &[u8],
        from: usize,
        delimiter: &[u8],
        searched: &mut impl FnMut(usize),
    ) -> Option<usize> {
        if self.searched {
            match self.next {
                None => return None,
                Some(end) if end >= from => return Some(end),
                Some(_) => {}
            }
        }
        // Cache both matches and exhaustion. Retrying an unclosed opener must
        // not scan the same suffix again. At most three monotonic searches
        // (one per closer family) traverse any input byte.
        let tail = &input[from..];
        let found = tail.windows(delimiter.len()).position(|w| w == delimiter);
        searched(found.map_or(tail.len(), |end| end + delimiter.len()));
        self.searched = true;
        self.next = found.map(|end| from + end);
        self.next
    }
}

fn scan(input: &[u8], mut searched: impl FnMut(usize)) -> bool {
    let mut closers: [Closer; 3] = std::array::from_fn(|_| Closer::default());
    let mut i = 0;
    while i + 1 < input.len() {
        let (family, closing): (usize, &[u8]) = match &input[i..i + 2] {
            b"{{" => (0, b"}}"),
            b"${" | b"#{" | b"*{" => (1, b"}"),
            b"<%" => (2, b"%>"),
            _ => {
                i += 1;
                continue;
            }
        };
        if let Some(end) = closers[family].find(input, i + 2, closing, &mut searched) {
            let inner = &input[i + 2..end];
            if is_dangerous_template_expr(inner) {
                return true;
            }
            // An unmatched outer opener can otherwise hide an arithmetic
            // probe in the innermost expression. Check that suffix once,
            // rather than recursively rescanning every nested opener.
            if let Some(nested) = inner
                .windows(2)
                .rposition(|w| opener_family(w) == Some(family))
                && is_dangerous_template_expr(&inner[nested + 2..])
            {
                return true;
            }
            // Expression slices are disjoint: keyword/math scans also have a
            // linear total bound. Other delimiter families remain searchable
            // after an unmatched opener, preserving mixed-template detection.
            i = end + closing.len();
        } else {
            i += 1;
        }
    }
    false
}

fn opener_family(pair: &[u8]) -> Option<usize> {
    match pair {
        b"{{" => Some(0),
        b"${" | b"#{" | b"*{" => Some(1),
        b"<%" => Some(2),
        _ => None,
    }
}

/// Evaluates lexical indicators inside template delimiters.
fn is_dangerous_template_expr(s: &[u8]) -> bool {
    let trimmed = {
        let mut start = 0;
        while start < s.len() && (s[start].is_ascii_whitespace() || s[start] == b'=') {
            start += 1;
        }
        let mut end = s.len();
        while end > start && s[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        &s[start..end]
    };

    if trimmed.is_empty() {
        return false;
    }

    // Check against dangerous lexical patterns across entire trimmed slice without truncation
    for pattern in SSTI_DANGEROUS_PATTERNS {
        if trimmed.len() >= pattern.len()
            && trimmed
                .windows(pattern.len())
                .any(|w| w.eq_ignore_ascii_case(pattern))
        {
            return true;
        }
    }

    // Check for arithmetic probe expressions: e.g. 7*7, 7*'7', 49/7, 8*8*8
    if is_math_probe(trimmed) {
        return true;
    }

    // Check for method invocation or property chain on objects: e.g. .getClass(), .exec()
    if trimmed.contains(&b'(') && trimmed.contains(&b')') {
        // Disallow arbitrary method calls inside template blocks
        if trimmed.windows(2).any(|w| w == b"()" || w == b"('") || trimmed.contains(&b'.') {
            return true;
        }
    }

    false
}

/// Detects mathematical expressions commonly used to verify SSTI execution (e.g. 7*7, 1337*1337).
fn is_math_probe(s: &[u8]) -> bool {
    let mut has_digit_before = false;
    let mut has_math_op = false;
    let mut has_digit_after = false;

    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c.is_ascii_digit() {
            if !has_math_op {
                has_digit_before = true;
            } else {
                has_digit_after = true;
            }
        } else if c == b'*' || c == b'/' || c == b'+' || c == b'-' || c == b'%' {
            if has_digit_before {
                has_math_op = true;
            }
        } else if c == b'\'' || c == b'"' || c.is_ascii_whitespace() {
            // allow quotes in e.g. 7*'7'
        } else {
            // Non-arithmetic character before operator
            if !has_math_op && !c.is_ascii_whitespace() {
                return false;
            }
        }
        i += 1;
    }

    has_digit_before && has_math_op && has_digit_after
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssti_attacks_detected() {
        for attack in [
            &b"{{7*7}}"[..],
            b"{{ 7 * 7 }}",
            b"{{7*'7'}}",
            b"${7*7}",
            b"#{7*7}",
            b"*{7*7}",
            b"<%= 7*7 %>",
            b"{{config.items()}}",
            b"{{self.__class__}}",
            b"{{''.__class__.__mro__[1].__subclasses__()}}",
            b"${T(java.lang.Runtime).getRuntime().exec('id')}",
            b"${ProcessBuilder.start()}",
            b"${''.getClass().forName('java.lang.Runtime')}",
            b"#{request.getParameter('cmd')}",
            b"{{request.application}}",
            b"<%= system('whoami') %>",
        ] {
            assert!(
                detect(attack),
                "Expected SSTI detected: {}",
                attack.escape_ascii()
            );
        }
    }

    #[test]
    fn test_benign_template_like_inputs_not_detected() {
        for benign in [
            &b"hello world"[..],
            b"Hello ${user}",
            b"Welcome {{name}}",
            b"Total price: $100",
            b"{color: red}",
            b"7 * 7 = 49",
            b"width: 100%;",
            b"",
        ] {
            assert!(
                !detect(benign),
                "Expected benign not detected: {}",
                benign.escape_ascii()
            );
        }
    }
}

#[cfg(test)]
mod malformed_tests {
    use super::*;

    #[test]
    fn unmatched_delimiters_have_linear_search_work() {
        for opener in [b"{{".as_slice(), b"${", b"#{", b"*{", b"<%", b"{{${#{*{<%"] {
            for repeats in [1, 128, 4096, 65536] {
                let input = opener.repeat(repeats);
                let mut work = 0;
                assert!(!scan(&input, |n| work += n));
                assert!(
                    work <= 3 * input.len(),
                    "work={work}, bytes={}",
                    input.len()
                );
            }
        }
    }

    #[test]
    fn unmatched_outer_delimiter_keeps_other_families_visible() {
        for payload in [b"{{${7*7}".as_slice(), b"${<%= 7*7 %>", b"<%{{7*7}}"] {
            assert!(detect(payload), "{}", payload.escape_ascii());
        }
        for (opener, attack) in [
            (b"{{".as_slice(), b"{{7*7}}".as_slice()),
            (b"${", b"${7*7}"),
            (b"<%", b"<%=7*7%>"),
        ] {
            let mut input = opener.repeat(65536);
            input.extend_from_slice(attack);
            assert!(detect(&input), "opener={}", opener.escape_ascii());
        }
    }

    #[test]
    fn arbitrary_bytes_and_repeated_closed_templates_are_bounded() {
        let mut input = b"{{name}}${user}<% title %>".repeat(16384);
        input.extend_from_slice(&[0, 255, 128, 0]);
        let mut work = 0;
        assert!(!scan(&input, |n| work += n));
        assert!(work <= 3 * input.len());
        assert!(!detect(&[0, 255, b'{', 128, b'}']));
        assert!(detect(b"\xff{{__class__}}\x00"));
    }
}
