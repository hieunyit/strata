//! W05-R-01, W06-S-01: transformations match Coraza v3.8.1 test vectors (vendored in
//! tests/vectors/coraza, Apache-2.0; originally SpiderLabs
//! secrules-language-tests). Inputs are decoded exactly as Coraza's
//! TestTransformations does: literal `\u0000` becomes NUL, and a string
//! containing `\x` goes through Go's strconv.Unquote (errors give "").

use std::path::PathBuf;

use libstrata::transform;

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

#[test]
fn transformations_match_coraza_vectors() {
    let dir = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/coraza"),
        PathBuf::from("/workspace/engine/tests/vectors/coraza"),
        PathBuf::from("engine/tests/vectors/coraza"),
        PathBuf::from("tests/vectors/coraza"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/coraza"));
    let files = [
        ("urlDecodeUni", transform::URL_DECODE_UNI),
        ("htmlEntityDecode", transform::HTML_ENTITY_DECODE),
        ("lowercase", transform::LOWERCASE),
        ("removeNulls", transform::REMOVE_NULLS),
        ("compressWhitespace", transform::COMPRESS_WHITESPACE),
        ("normalisePath", transform::NORMALIZE_PATH),
        // batch 2 (W06-S-01)
        ("jsDecode", transform::JS_DECODE),
        ("cssDecode", transform::CSS_DECODE),
        ("removeWhitespace", transform::REMOVE_WHITESPACE),
        ("cmdLine", transform::CMD_LINE),
        ("utf8toUnicode", transform::UTF8_TO_UNICODE),
        ("base64Decode", transform::BASE64_DECODE),
        ("urlDecode", transform::URL_DECODE),
        ("normalisePathWin", transform::NORMALIZE_PATH_WIN),
        ("replaceComments", transform::REPLACE_COMMENTS),
        ("removeCommentsChar", transform::REMOVE_COMMENTS_CHAR),
    ];
    let (mut total, mut failures) = (0, vec![]);
    for (name, code) in files {
        let text = std::fs::read_to_string(dir.join(format!("{name}.json"))).unwrap();
        let cases: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
        for case in cases {
            let input = decode(case["input"].as_str().unwrap());
            let expected = decode(case["output"].as_str().unwrap());
            let got = transform::apply(code, &input).unwrap().into_owned();
            total += 1;
            if got != expected {
                failures.push(format!(
                    "{name}: input {:?}\n   expected {:?}\n   got      {:?}",
                    String::from_utf8_lossy(&input),
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&got)
                ));
            }
        }
    }
    assert!(total >= 90, "only {total} vectors");
    assert!(
        failures.is_empty(),
        "{}/{total} vectors differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
    println!("{total} Coraza vectors match");
}
