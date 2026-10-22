//! NoSQL (MongoDB-style) injection lexical detector for the opt-in
//! `detect_nosql` rule operator (22/10/2026).
//!
//! Three shapes, each needing structure rather than a word:
//! - a query operator (`$ne`, `$where`, `$regex`...) used as a key: an
//!   object key (`{"$ne": 1}`, `$where:`), a bracket key (`user[$ne]=`) or the
//!   last segment of a parsed JSON argument name (`json.user.$ne`);
//! - server-side JavaScript: a `db.<collection>.<method>(` call, a
//!   `do { ... } while (` loop, `this.<field>` compared or matched;
//! - a quote broken out of a JavaScript string into a tautology:
//!   `'||'1'=='1`, `" || 1==1//`.
//!
//! Operator names are compared as MongoDB does, case-sensitively. A price
//! (`$10`), a variable in prose (`$where is a keyword`) or a lone operator
//! name without key syntax does not match. Work is linear in the input:
//! each byte is looked at a bounded number of times.
#![forbid(unsafe_code)]

/// Query operators an injection uses (MongoDB names).
const OPERATORS: &[&[u8]] = &[
    b"where",
    b"ne",
    b"eq",
    b"gt",
    b"gte",
    b"lt",
    b"lte",
    b"in",
    b"nin",
    b"regex",
    b"exists",
    b"expr",
    b"function",
    b"accumulator",
    b"or",
    b"and",
    b"nor",
    b"not",
    b"elemMatch",
    b"size",
    b"type",
    b"mod",
    b"all",
    b"jsonSchema",
    b"lookup",
    b"unionWith",
];

/// Longest look-ahead for the second half of a shape.
const WINDOW: usize = 200;

/// Whether `input` holds one of the NoSQL injection shapes.
pub fn detect(input: &[u8]) -> bool {
    operator_key(input) || server_js(input) || quote_tautology(input)
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c)
}

fn skip_spaces(input: &[u8], mut i: usize) -> usize {
    while i < input.len() && is_space(input[i]) {
        i += 1;
    }
    i
}

/// `$op` as a key: after `{ [ , " ' . (` or a space or the start, and
/// followed (past a closing quote and spaces) by `:` or `]`; or the last
/// segment of a dotted name.
fn operator_key(input: &[u8]) -> bool {
    let mut from = 0;
    while let Some(at) = memchr::memchr(b'$', &input[from..]) {
        let d = from + at;
        from = d + 1;
        let left_ok = d == 0
            || matches!(
                input[d - 1],
                b'{' | b'[' | b',' | b'"' | b'\'' | b'.' | b'(' | b':'
            )
            || is_space(input[d - 1]);
        if !left_ok {
            continue;
        }
        let start = d + 1;
        let mut end = start;
        while end < input.len() && input[end].is_ascii_alphabetic() && end - start < 16 {
            end += 1;
        }
        if !OPERATORS.contains(&&input[start..end]) {
            continue;
        }
        if end == input.len() {
            // json.user.$ne, user[$ne (a name the parser cut)
            if d > 0 && matches!(input[d - 1], b'.' | b'[') {
                return true;
            }
            continue;
        }
        let mut j = end;
        if matches!(input[j], b'"' | b'\'') {
            j += 1;
        }
        j = skip_spaces(input, j);
        if j < input.len() && matches!(input[j], b':' | b']') {
            return true;
        }
    }
    false
}

/// `db.x.y(`, `do{...}while(`, `this.x` compared or matched.
fn server_js(input: &[u8]) -> bool {
    let n = input.len();
    let ident = |mut i: usize| {
        let s = i;
        while i < n && (input[i].is_ascii_alphanumeric() || input[i] == b'_') {
            i += 1;
        }
        (i > s).then_some(i)
    };
    let token_start = |i: usize| {
        i == 0
            || !(input[i - 1].is_ascii_alphanumeric()
                || input[i - 1] == b'_'
                || input[i - 1] == b'.')
    };
    // the next `}` from where it was looked for: the search only moves
    // forward, so many `do{` openers cost one pass
    let mut next_brace: Option<Option<usize>> = None;
    let mut i = 0;
    while i < n {
        let rest = &input[i..];
        if rest.starts_with(b"db.") && token_start(i) {
            // db.<collection>.<method>(
            if let Some(a) = ident(i + 3)
                && a < n
                && input[a] == b'.'
                && let Some(b) = ident(a + 1)
            {
                let p = skip_spaces(input, b);
                if p < n && input[p] == b'(' {
                    return true;
                }
            }
        } else if rest.starts_with(b"do") && token_start(i) {
            // do { ... } while (
            let p = skip_spaces(input, i + 2);
            if p < n && input[p] == b'{' {
                let stale = match next_brace {
                    None => true,
                    Some(Some(c)) => c < p,
                    Some(None) => false,
                };
                if stale {
                    next_brace = Some(memchr::memchr(b'}', &input[p..]).map(|c| p + c));
                }
                if let Some(Some(c)) = next_brace
                    && c - p < WINDOW
                {
                    let q = skip_spaces(input, c + 1);
                    if input[q..].starts_with(b"while") {
                        let r = skip_spaces(input, q + 5);
                        if r < n && input[r] == b'(' {
                            return true;
                        }
                    }
                }
            }
        } else if rest.starts_with(b"this.") && token_start(i) {
            // this.<field> == / != / .match(
            if let Some(a) = ident(i + 5) {
                let p = skip_spaces(input, a);
                let tail = &input[p..];
                if tail.starts_with(b"==")
                    || tail.starts_with(b"!=")
                    || tail.starts_with(b".match(")
                    || tail.starts_with(b".length")
                {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// A quote, `||` or `&&`, then a comparison `==` close behind:
/// `'||'1'=='1`, `" || 1==1//`, `' && this.a=='`.
fn quote_tautology(input: &[u8]) -> bool {
    let n = input.len();
    let mut from = 0;
    while from + 1 < n {
        let Some(at) = memchr::memchr2(b'|', b'&', &input[from..]) else {
            return false;
        };
        let o = from + at;
        from = o + 1;
        if o + 1 >= n || input[o + 1] != input[o] {
            continue;
        }
        // a quote right before the operator (spaces between)
        let mut b = o;
        while b > 0 && is_space(input[b - 1]) {
            b -= 1;
        }
        if b == 0 || !matches!(input[b - 1], b'\'' | b'"') {
            continue;
        }
        let end = (o + 2 + 40).min(n);
        if input[o + 2..end].windows(2).any(|w| w == b"==") {
            return true;
        }
        from = o + 2;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::detect;

    #[test]
    fn attacks() {
        for a in [
            &br#"{"$ne": null}"#[..],
            br#"{"username": {"$gt": ""}, "password": {"$gt": ""}}"#,
            b"user[$ne]=x",
            b"json.user.$ne",
            b"user[$regex",
            b"true, $where: '99 == 88'",
            b"', $or: [ {}, { 'order':'order",
            b"{$where: 'sleep(1000)'}",
            b"db.injection.insert({success:1});",
            b"db.users.find( {} )",
            b"0;var date=new Date(); do{curDate = new Date();}while(curDate-date<10000)",
            b"; do { x++ } while (1)",
            b"this.password.match(/^a/)",
            b"' && this.password == 'x",
            b"'||'1'=='1",
            b"\" || 1==1//",
            b"admin' || 'a'=='a",
            br#"{"$expr": {"$function": {"body": "sleep(100)"}}}"#,
        ] {
            assert!(detect(a), "{}", String::from_utf8_lossy(a));
        }
    }

    #[test]
    fn benign() {
        for b in [
            &b"save $10 or more"[..],
            b"$where is a keyword in MongoDB",
            b"the $ne operator",
            b"price: $5",
            b"US$ and VND",
            b"do it while you can",
            b"do {the dishes} quickly",
            b"db.example.test",
            b"see db.config for details",
            b"this.is a sentence",
            b"rock & roll || jazz",
            b"a || b == c",
            b"\"quoted\" and more",
            b"user[name]=alice&user[role]=admin",
            b"json.items.0.price",
            b"{\"ne\": 1, \"where\": \"Hanoi\"}",
            b"",
        ] {
            assert!(!detect(b), "{}", String::from_utf8_lossy(b));
        }
    }

    #[test]
    fn operators_are_case_sensitive() {
        assert!(!detect(br#"{"$NE": 1}"#));
        assert!(detect(br#"{"$elemMatch": {"a": 1}}"#));
    }

    #[test]
    fn long_hostile_inputs_stay_linear() {
        // many openers with no closer: each byte is looked at a bounded
        // number of times
        for unit in [&b"do{"[..], b"$ne", b"'||", b"db.a.", b"this.a"] {
            let v: Vec<u8> = unit.iter().copied().cycle().take(256 * 1024).collect();
            let t = std::time::Instant::now();
            let _ = detect(&v);
            assert!(
                t.elapsed().as_millis() < 500,
                "{:?}",
                String::from_utf8_lossy(unit)
            );
        }
    }
}
