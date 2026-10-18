//! W07-R-02: operators match Coraza v3.8.1 test vectors (vendored in
//! tests/vectors/coraza/operators, Apache-2.0).
//!
//! Evaluates validateByteRange (6 cases), validateUrlEncoding (15 cases),
//! validateUtf8Encoding (32 cases), and ipMatch (3623 cases).

use std::path::PathBuf;

use libstrata::operators::{
    ByteRangeSet, IpMatchSet, validate_url_encoding, validate_utf8_encoding,
};

struct TestCase {
    input: String,
    param: String,
    ret: i32,
}

/// Go's strconv.Unquote for a double-quoted literal; None on error.
fn go_unquote(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() < 2 || b[0] != b'"' || b[b.len() - 1] != b'"' {
        return None;
    }
    let body = &b[1..b.len() - 1];
    let mut out = vec![];
    let mut i = 0;
    let hex =
        |s: &[u8]| -> Option<u32> { u32::from_str_radix(std::str::from_utf8(s).ok()?, 16).ok() };
    while i < body.len() {
        let c = body[i];
        if c == b'"' || c == b'\n' {
            return None;
        }
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let e = *body.get(i + 1)?;
        i += 2;
        match e {
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(11),
            b'\\' => out.push(b'\\'),
            b'"' => out.push(b'"'),
            b'x' => {
                out.push(hex(body.get(i..i + 2)?)? as u8);
                i += 2;
            }
            b'u' | b'U' => {
                let n = if e == b'u' { 4 } else { 8 };
                let cp = hex(body.get(i..i + n)?)?;
                let ch = char::from_u32(cp)?;
                out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                i += n;
            }
            b'0'..=b'7' => {
                let oct = body.get(i - 1..i + 2)?;
                let v = u32::from_str_radix(std::str::from_utf8(oct).ok()?, 8).ok()?;
                if v > 255 {
                    return None;
                }
                out.push(v as u8);
                i += 2;
            }
            _ => return None,
        }
    }
    Some(out)
}

fn decode(s: &str) -> Vec<u8> {
    let s = s.replace("\\u0000", "\0");
    if s.contains("\\x") {
        go_unquote(&format!("\"{s}\"")).unwrap_or_default()
    } else {
        s.into_bytes()
    }
}

fn vectors_dir() -> PathBuf {
    [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/coraza/operators"),
        PathBuf::from("/workspace/engine/tests/vectors/coraza/operators"),
        PathBuf::from("engine/tests/vectors/coraza/operators"),
        PathBuf::from("tests/vectors/coraza/operators"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/coraza/operators"))
}

fn load_cases(filename: &str) -> Vec<TestCase> {
    let path = vectors_dir().join(filename);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse JSON {}: {e}", path.display()));
    v.as_array()
        .expect("array of cases")
        .iter()
        .map(|item| TestCase {
            input: item["input"].as_str().unwrap_or_default().to_string(),
            param: item["param"].as_str().unwrap_or_default().to_string(),
            ret: item["ret"].as_i64().expect("ret integer") as i32,
        })
        .collect()
}

#[test]
fn coraza_validate_byte_range_vectors() {
    let cases = load_cases("validateByteRange.json");
    assert_eq!(cases.len(), 6);
    for (i, tc) in cases.iter().enumerate() {
        let set = ByteRangeSet::parse(&tc.param)
            .unwrap_or_else(|e| panic!("case {i}: failed to parse param {:?}: {e}", tc.param));
        let input = decode(&tc.input);
        let matched = set.is_match(&input);
        let expected = tc.ret == 1;
        assert_eq!(
            matched, expected,
            "case {i}: input={:?} param={:?} expected {} got {}",
            tc.input, tc.param, expected, matched
        );
    }
    println!("validateByteRange: {} cases passed", cases.len());
}

#[test]
fn coraza_validate_url_encoding_vectors() {
    let cases = load_cases("validateUrlEncoding.json");
    assert_eq!(cases.len(), 15);
    for (i, tc) in cases.iter().enumerate() {
        let input = decode(&tc.input);
        let matched = validate_url_encoding(&input);
        let expected = tc.ret == 1;
        assert_eq!(
            matched, expected,
            "case {i}: input={:?} expected {} got {}",
            tc.input, expected, matched
        );
    }
    println!("validateUrlEncoding: {} cases passed", cases.len());
}

#[test]
fn coraza_validate_utf8_encoding_vectors() {
    let cases = load_cases("validateUtf8Encoding.json");
    assert_eq!(cases.len(), 32);
    for (i, tc) in cases.iter().enumerate() {
        let input = decode(&tc.input);
        let matched = validate_utf8_encoding(&input);
        let expected = tc.ret == 1;
        assert_eq!(
            matched, expected,
            "case {i}: input={:?} expected {} got {}",
            tc.input, expected, matched
        );
    }
    println!("validateUtf8Encoding: {} cases passed", cases.len());
}

#[test]
fn coraza_ip_match_vectors() {
    let cases = load_cases("ipMatch.json");
    assert_eq!(cases.len(), 3623);
    for (i, tc) in cases.iter().enumerate() {
        let entries: Vec<&str> = tc.param.split(',').collect();
        let set = match IpMatchSet::parse_entries(entries) {
            Ok(s) => s,
            Err(e) => {
                panic!("case {i}: failed to parse param {:?}: {e}", tc.param);
            }
        };
        let input = decode(&tc.input);
        let matched = set.is_match(&input);
        let expected = tc.ret == 1;
        assert_eq!(
            matched, expected,
            "case {i}: input={:?} param={:?} expected {} got {}",
            tc.input, tc.param, expected, matched
        );
    }
    println!("ipMatch: {} cases passed", cases.len());
}
