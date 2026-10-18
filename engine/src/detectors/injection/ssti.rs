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

/// Detects Server-Side Template Injection (SSTI) in an arbitrary byte slice.
pub fn detect(input: &[u8]) -> bool {
    if input.len() < 5 {
        return false;
    }

    let len = input.len();
    let mut i = 0;

    while i < len {
        // 1. Jinja2 / Twig / Django: {{ ... }}
        if i + 1 < len
            && input[i] == b'{'
            && input[i + 1] == b'{'
            && let Some(end) = input[i + 2..].windows(2).position(|w| w == b"}}")
        {
            let inner = &input[i + 2..i + 2 + end];
            if is_dangerous_template_expr(inner) {
                return true;
            }
            i += 2 + end + 2;
            continue;
        }

        // 2. Spring SpEL / JSP EL / Freemarker: ${ ... }
        if i + 1 < len
            && input[i] == b'$'
            && input[i + 1] == b'{'
            && let Some(end) = input[i + 2..].iter().position(|&c| c == b'}')
        {
            let inner = &input[i + 2..i + 2 + end];
            if is_dangerous_template_expr(inner) {
                return true;
            }
            i += 2 + end + 1;
            continue;
        }

        // 3. Ruby ERB / OGNL / Velocity: #{ ... }
        if i + 1 < len
            && input[i] == b'#'
            && input[i + 1] == b'{'
            && let Some(end) = input[i + 2..].iter().position(|&c| c == b'}')
        {
            let inner = &input[i + 2..i + 2 + end];
            if is_dangerous_template_expr(inner) {
                return true;
            }
            i += 2 + end + 1;
            continue;
        }

        // 4. Thymeleaf: *{ ... }
        if i + 1 < len
            && input[i] == b'*'
            && input[i + 1] == b'{'
            && let Some(end) = input[i + 2..].iter().position(|&c| c == b'}')
        {
            let inner = &input[i + 2..i + 2 + end];
            if is_dangerous_template_expr(inner) {
                return true;
            }
            i += 2 + end + 1;
            continue;
        }

        // 5. ERB / EJS: <%= ... %> or <% ... %>
        if i + 1 < len
            && input[i] == b'<'
            && input[i + 1] == b'%'
            && let Some(end) = input[i + 2..].windows(2).position(|w| w == b"%>")
        {
            let inner = &input[i + 2..i + 2 + end];
            if is_dangerous_template_expr(inner) {
                return true;
            }
            i += 2 + end + 2;
            continue;
        }

        i += 1;
    }

    false
}

/// Evaluates if the contents inside template delimiters represent an exploit payload.
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

    // Check lowercase representation against dangerous AST patterns
    let mut buf = [0u8; 256];
    let check_len = trimmed.len().min(buf.len());
    for j in 0..check_len {
        buf[j] = trimmed[j].to_ascii_lowercase();
    }
    let lower_slice = &buf[..check_len];

    for pattern in SSTI_DANGEROUS_PATTERNS {
        if lower_slice.windows(pattern.len()).any(|w| w == *pattern) {
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
        } else if c == b'*' || c == b'/' {
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
            assert!(detect(attack), "Expected SSTI detected: {}", attack.escape_ascii());
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
            assert!(!detect(benign), "Expected benign not detected: {}", benign.escape_ascii());
        }
    }
}
