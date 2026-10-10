//! `make libinjection-diff`: one input per line on stdin (a trailing '\n'
//! removed), prints "<sqli fingerprint or -> <xss 0/1>" per line, like
//! engine/tools/libinjection/ref.c built on the original C library.

use std::io::{BufRead, Write};

use libstrata::detectors::injection::{detect_sqli, detect_xss};

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout());
    let mut line = vec![];
    let mut input = stdin.lock();
    while input.read_until(b'\n', &mut line).unwrap() > 0 {
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        match detect_sqli(&line) {
            Some(fp) => out.write_all(fp.as_bytes()).unwrap(),
            None => out.write_all(b"-").unwrap(),
        }
        writeln!(out, " {}", detect_xss(&line) as u8).unwrap();
        line.clear();
    }
}
