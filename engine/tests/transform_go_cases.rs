//! Edge cases from Coraza v3.8.1's Go unit tests (internal/transformations/*_test.go,
//! Apache-2.0), extracted mechanically: the input and wanted output of every
//! table entry of normalise_path_win, js_decode, css_decode and cmd_line.

use libstrata::transform;

const CASES: &[(u8, &[u8], &[u8])] = &[
    (transform::NORMALIZE_PATH_WIN, b"", b""),
    (transform::NORMALIZE_PATH_WIN, b"C:\x5cinetpub\x5cwwwroot\x5cindex.html", b"C:/inetpub/wwwroot/index.html"),
    (transform::NORMALIZE_PATH_WIN, b"..\x5c..\x5cetc\x5cpasswd", b"../../etc/passwd"),
    (transform::NORMALIZE_PATH_WIN, b"foo\x5c..\x5cbar", b"bar"),
    (transform::NORMALIZE_PATH_WIN, b"C:\x5cinetpub\x5cwwwroot\x5cweb.config.", b"C:/inetpub/wwwroot/web.config"),
    (transform::NORMALIZE_PATH_WIN, b"C:\x5cinetpub\x5cwwwroot\x5cweb.config ", b"C:/inetpub/wwwroot/web.config"),
    (transform::NORMALIZE_PATH_WIN, b"C:\x5cinetpub\x5cwwwroot\x5cweb.config::$DATA", b"C:/inetpub/wwwroot/web.config"),
    (transform::NORMALIZE_PATH_WIN, b"C:\x5cinetpub\x5cwwwroot\x5cweb.config:hidden", b"C:/inetpub/wwwroot/web.config"),
    (transform::NORMALIZE_PATH_WIN, b"..\x5c..\x5cweb.config.", b"../../web.config"),
    (transform::NORMALIZE_PATH_WIN, b"C:", b"C:"),
    (transform::NORMALIZE_PATH_WIN, b"C:\x5cpath\x5cweb.config:$DATA\x5c", b"C:/path/web.config/"),
    (transform::NORMALIZE_PATH_WIN, b"C:\x5c \x5cfile.txt", b"C:/file.txt"),
    (transform::JS_DECODE, b"", b""),
    (transform::JS_DECODE, b"hello world", b"hello world"),
    (transform::JS_DECODE, b"\x5c\x5c0", b"\x5c0"),
    (transform::JS_DECODE, b"\x5c", b"\x5c"),
    (transform::JS_DECODE, b"\x5cx41", b"A"),
    (transform::JS_DECODE, b"\x5cxff", b"\xff"),
    (transform::JS_DECODE, b"\x5cu0041", b"A"),
    (transform::JS_DECODE, b"\x5cuabcd", b"\xcd"),
    (transform::JS_DECODE, b"\x5cuff21", b"A"),
    (transform::JS_DECODE, b"\x5cuff01", b"!"),
    (transform::JS_DECODE, b"\x5cuff5e", b"~"),
    (transform::JS_DECODE, b"\x5ca", b"\x07"),
    (transform::JS_DECODE, b"\x5cb", b"\x08"),
    (transform::JS_DECODE, b"\x5cf", b"\x0c"),
    (transform::JS_DECODE, b"\x5cn", b"\x0a"),
    (transform::JS_DECODE, b"\x5cr", b"\x0d"),
    (transform::JS_DECODE, b"\x5ct", b"\x09"),
    (transform::JS_DECODE, b"\x5cv", b"\x0b"),
    (transform::JS_DECODE, b"\x5c?", b"?"),
    (transform::JS_DECODE, b"\x5c'", b"'"),
    (transform::JS_DECODE, b"\x5c\x22", b"\x22"),
    (transform::JS_DECODE, b"\x5cu{61}\x5cu{6c}\x5cu{65}\x5cu{72}\x5cu{74}", b"alert"),
    (transform::JS_DECODE, b"\x5cu{ff01}", b"!"),
    (transform::JS_DECODE, b"\x5cu{1}", b"\x01"),
    (transform::JS_DECODE, b"\x5cu{41}", b"A"),
    (transform::JS_DECODE, b"\x5cu{", b"u{"),
    (transform::JS_DECODE, b"\x5cu{41", b"u{41"),
    (transform::JS_DECODE, b"\x5cu{zz}", b"u{zz}"),
    (transform::JS_DECODE, b"\x5cu{0ff01}", b"!"),
    (transform::JS_DECODE, b"\x5cu{00ff01}", b"!"),
    (transform::JS_DECODE, b"\x5cu{0ff5e}", b"~"),
    (transform::JS_DECODE, b"\x5cu{000061}", b"a"),
    (transform::JS_DECODE, b"\x5cu{1234567}", b"u{1234567}"),
    (transform::JS_DECODE, b"\x5cu{0FF5e}", b"~"),
    (transform::JS_DECODE, b"\x5cu{}", b"u{}"),
    (transform::JS_DECODE, b"\x5cu{0}", b"\x00"),
    (transform::JS_DECODE, b"\x5cu{41}\x5cu0042", b"AB"),
    (transform::JS_DECODE, b"\x5c101", b"A"),
    (transform::JS_DECODE, b"\x5c0", b"\x00"),
    (transform::JS_DECODE, b"\x5c1", b"\x01"),
    (transform::JS_DECODE, b"\x5c16", b"\x0e"),
    (transform::JS_DECODE, b"\x5c163\x5c143\x5c162\x5c151\x5c160\x5c164", b"script"),
    (transform::JS_DECODE, b"\x5c377", b"\xff"),
    (transform::JS_DECODE, b"\x5c200", b"\x80"),
    (transform::JS_DECODE, b"\x5c400", b" 0"),
    (transform::JS_DECODE, b"\x5c477", b"'7"),
    (transform::JS_DECODE, b"\x5c168", b"\x0e8"),
    (transform::JS_DECODE, b"<\x5c163\x5c143\x5c162\x5c151\x5c160\x5c164>", b"<script>"),
    (transform::CSS_DECODE, b"", b""),
    (transform::CSS_DECODE, b"Test\x00Case", b"Test\x00Case"),
    (transform::CSS_DECODE, b"test\x5ca\x5cb\x5cf\x5cn\x5cr\x5ct\x5cv\x5c?\x5c'\x5c\x22\x5c\x00\x5c12\x5c123\x5c1234\x5c12345\x5c123456\x5cff01\x5cff5e\x5c\x0a\x5c\x00  string", b"test\x0a\x0b\x0fnrtv?'\x22\x00\x12\xc4\xa3\xe1\x88\xb4\xf0\x92\x8d\x85\xef\xbf\xbd!~\x00  string"),
    (transform::CSS_DECODE, b"caf\x5ce9", b"caf\xc3\xa9"),
    (transform::CSS_DECODE, b"\x5c123", b"\xc4\xa3"),
    (transform::CSS_DECODE, b"\x5c12345", b"\xf0\x92\x8d\x85"),
    (transform::CSS_DECODE, b"\x5c123456", b"\xef\xbf\xbd"),
    (transform::CSS_DECODE, b"\x5c0", b"\xef\xbf\xbd"),
    (transform::CSS_DECODE, b"\x5c000000", b"\xef\xbf\xbd"),
    (transform::CMD_LINE, b"", b""),
    (transform::CMD_LINE, b"test", b"test"),
    (transform::CMD_LINE, b"/etc/passwd", b"/etc/passwd"),
    (transform::CMD_LINE, b"/?file=../../etc/passwd", b"/?file=../../etc/passwd"),
    (transform::CMD_LINE, b"C^OMMAND", b"command"),
    (transform::CMD_LINE, b"\x22command\x22", b"command"),
    (transform::CMD_LINE, b"a , b", b"a b"),
    (transform::CMD_LINE, b"dir /s", b"dir/s"),
    (transform::CMD_LINE, b"a  b", b"a b"),
];

#[test]
fn transformations_match_corazas_unit_tests() {
    let mut failures = vec![];
    for (code, input, want) in CASES {
        let got = transform::apply(*code, input).unwrap();
        if &*got != *want {
            failures.push(format!(
                "code {code}: {:?} -> {:?}, want {:?}",
                String::from_utf8_lossy(input),
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(want)
            ));
        }
    }
    assert!(CASES.len() >= 60, "only {} cases", CASES.len());
    assert!(
        failures.is_empty(),
        "{}/{} differ:\n{}",
        failures.len(),
        CASES.len(),
        failures.join("\n")
    );
}
