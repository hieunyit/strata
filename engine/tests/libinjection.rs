//! The original libinjection v3.10.0 test suite (tests/test-*.txt, copied
//! unchanged with its licence into tests/libinjection/), run the way
//! libinjection's `testdriver.c` runs it: same flags per file family, same
//! output format, same trimming. The port must match at least 99% of the
//! cases (W06-R-01); every mismatch is printed.

use std::fs;
use std::path::PathBuf;

use libstrata::detectors::injection::html5::{Flags, Html5};
use libstrata::detectors::injection::sqli::{
    self, FLAG_QUOTE_NONE, FLAG_SQL_ANSI, State, TYPE_STRING, TYPE_VARIABLE, Token,
};

/// `modp_rtrim`
fn rtrim(s: &[u8]) -> &[u8] {
    let n = s
        .iter()
        .rposition(|c| !b" \n\t\r".contains(c))
        .map_or(0, |i| i + 1);
    &s[..n]
}

/// (input, expected) of a test file, as `read_file` builds them.
fn parse(text: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (mut part, mut input, mut expected) = (0, vec![], vec![]);
    for line in text.split_inclusive(|&c| c == b'\n') {
        match (part, line) {
            (0, b"--TEST--\n") => part = 1,
            (1, b"--INPUT--\n") => part = 2,
            (2, b"--EXPECTED--\n") => part = 3,
            (2, _) => input.extend_from_slice(line),
            (3, _) => expected.extend_from_slice(line),
            _ => {}
        }
    }
    (part == 3).then(|| (rtrim(&input).to_vec(), rtrim(&expected).to_vec()))
}

/// `print_token`
fn print_token(out: &mut Vec<u8>, t: &Token) {
    out.push(t.kind);
    out.push(b' ');
    let quoted = |out: &mut Vec<u8>| {
        if t.str_open != 0 {
            out.push(t.str_open);
        }
        out.extend_from_slice(t.value());
        if t.str_close != 0 {
            out.push(t.str_close);
        }
    };
    match t.kind {
        TYPE_STRING => quoted(out),
        TYPE_VARIABLE => {
            if t.count >= 1 {
                out.push(b'@');
            }
            if t.count == 2 {
                out.push(b'@');
            }
            quoted(out);
        }
        _ => out.extend_from_slice(t.value()),
    }
    out.push(b'\n');
}

fn actual(family: &str, input: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    match family {
        "tokens" => {
            let mut st = State::new(input, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
            while st.tokenize() {
                print_token(&mut out, st.current());
            }
        }
        "folding" => {
            let mut st = State::new(input, FLAG_QUOTE_NONE | FLAG_SQL_ANSI);
            let n = st.fold();
            for i in 0..n {
                print_token(&mut out, st.token(i));
            }
        }
        "sqli" => {
            if let Some(fp) = sqli::detect(input) {
                out.extend_from_slice(fp.as_bytes());
            }
        }
        "html5" => {
            let mut h = Html5::new(input, Flags::DataState);
            while h.next_token() {
                let t = h.token();
                let shown = &t[..t.iter().position(|&c| c == 0).unwrap_or(t.len())];
                out.extend_from_slice(
                    format!("{},{},", h.token_type.name(), h.token_len).as_bytes(),
                );
                out.extend_from_slice(shown);
                out.push(b'\n');
            }
        }
        _ => unreachable!(),
    }
    rtrim(&out).to_vec()
}

#[test]
fn original_suite_matches() {
    let dir = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/libinjection"),
        PathBuf::from("/workspace/engine/tests/libinjection"),
        PathBuf::from("engine/tests/libinjection"),
        PathBuf::from("tests/libinjection"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/libinjection"));
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    files.sort();

    let mut per_family: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    let mut failures = vec![];
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let family = ["tokens", "folding", "sqli", "html5"]
            .into_iter()
            .find(|f| name.starts_with(&format!("test-{f}-")))
            .unwrap_or_else(|| panic!("unknown test family: {name}"));
        let Some((input, expected)) = parse(&fs::read(path).unwrap()) else {
            panic!("{name}: malformed");
        };
        let got = actual(family, &input);
        let e = per_family.entry(family).or_default();
        e.0 += 1;
        if got == expected {
            e.1 += 1;
        } else {
            failures.push(format!(
                "{name}\n  INPUT: {}\n  EXPECTED: {}\n  GOT: {}",
                input.escape_ascii(),
                expected.escape_ascii(),
                got.escape_ascii()
            ));
        }
    }

    let total: usize = per_family.values().map(|v| v.0).sum();
    let passed: usize = per_family.values().map(|v| v.1).sum();
    for (f, (n, ok)) in &per_family {
        eprintln!("libinjection {f}: {ok}/{n}");
    }
    eprintln!("libinjection total: {passed}/{total}");
    for f in &failures {
        eprintln!("MISMATCH {f}");
    }
    assert_eq!(total, 480, "the whole suite is present");
    assert!(passed * 100 >= total * 99, "{passed}/{total} < 99%");
}
