//! strata-eval — run requests through libstrata, the way the NGINX
//! connector does, and print each verdict. Used by `strata-rules test` and
//! `strata-rules report` (W04-S-01), so rule tests and corpus numbers come
//! from the real engine.
//!
//! ```text
//! strata-eval --bundle <file> --pubkey <file> [--policy <name>] < requests.jsonl > verdicts.jsonl
//! strata-eval --capabilities
//! ```
//! `--capabilities` prints the operators, transformations and targets this
//! libstrata evaluates: `{"operators": [...], "transforms": [...], "vars": [...]}`.
//! Request: `{"id": "...", "method": "GET", "uri": "/a?b=1",
//! "headers": {"Name": "v" | ["v1", "v2"]}, "body": "...", "remote_addr": "192.0.2.1",
//! "protocol": "HTTP/1.1"}` (protocol defaults to HTTP/1.1).
//! Verdict: `{"id": "...", "action": "allow|log|block|challenge", "score": 0,
//! "rules": [100011], "error": 0}`.
//!
//! The URI is passed raw, and normalized as NGINX does for `$uri`
//! (percent-decoding, dot segments, merged slashes); the query is passed as
//! `$args`.

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufWriter, Write};
use std::process::ExitCode;
use std::sync::Arc;

use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_CHALLENGE, ACTION_LOG};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(untagged)]
enum HeaderValue {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    id: serde_json::Value,
    #[serde(default = "get")]
    method: String,
    uri: String,
    #[serde(default)]
    headers: BTreeMap<String, HeaderValue>,
    #[serde(default)]
    body: String,
    #[serde(default)]
    remote_addr: String,
    #[serde(default = "http11")]
    protocol: String,
}

fn get() -> String {
    "GET".into()
}

fn http11() -> String {
    "HTTP/1.1".into()
}

/// The path of a request target: an absolute-form target
/// (`http://host/p?q`) is reduced to its path, as NGINX does for `$uri`.
fn target_path(raw: &[u8]) -> &[u8] {
    let scheme_end = raw
        .windows(3)
        .position(|w| w == b"://")
        .filter(|&i| i > 0 && raw[0].is_ascii_alphabetic() && !raw[..i].contains(&b'/'));
    match scheme_end {
        Some(i) => {
            let host = &raw[i + 3..];
            host.iter()
                .position(|&c| c == b'/' || c == b'?')
                .map_or(&b"/"[..], |p| &host[p..])
        }
        None => raw,
    }
}

#[derive(Serialize)]
struct Out<'a> {
    id: &'a serde_json::Value,
    action: &'static str,
    score: i32,
    rules: &'a [u32],
    error: i32,
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `$uri` as NGINX makes it from the path: percent-decoded, `.` and `..`
/// segments resolved, repeated slashes merged.
fn normalize(path: &[u8]) -> Vec<u8> {
    let mut dec = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        if path[i] == b'%'
            && i + 2 < path.len()
            && let (Some(h), Some(l)) = (hex(path[i + 1]), hex(path[i + 2]))
        {
            dec.push(h << 4 | l);
            i += 3;
            continue;
        }
        dec.push(path[i]);
        i += 1;
    }
    let mut out: Vec<&[u8]> = Vec::new();
    for seg in dec.split(|&c| c == b'/') {
        match seg {
            b"" | b"." => {}
            b".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut norm = Vec::with_capacity(dec.len());
    for s in &out {
        norm.push(b'/');
        norm.extend_from_slice(s);
    }
    if norm.is_empty() || dec.ends_with(b"/") {
        norm.push(b'/');
    }
    norm
}

fn action(a: u32) -> &'static str {
    match a {
        ACTION_ALLOW => "allow",
        ACTION_LOG => "log",
        ACTION_BLOCK => "block",
        ACTION_CHALLENGE => "challenge",
        _ => "unknown",
    }
}

fn capabilities() -> Result<(), String> {
    let (operators, transforms) = libstrata::eval::supported();
    let caps = serde_json::json!({
        "operators": operators,
        "transforms": transforms,
        // user_input is expanded by the compiler (strata_compiler::USER_INPUT)
        "vars": libstrata::eval::SUPPORTED_VARS
            .iter()
            .chain(&["user_input"])
            .collect::<Vec<_>>(),
    });
    println!("{caps}");
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("--capabilities") {
        return capabilities();
    }
    let (mut bundle, mut pubkey, mut policy) = (None, None, String::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--bundle" => bundle = Some(val()?),
            "--pubkey" => pubkey = Some(val()?),
            "--policy" => policy = val()?,
            _ => return Err(format!("unexpected argument {a}")),
        }
    }
    let bytes = std::fs::read(bundle.ok_or("--bundle is required")?).map_err(|e| e.to_string())?;
    let pubkey = std::fs::read(pubkey.ok_or("--pubkey is required")?).map_err(|e| e.to_string())?;
    // The Hyperscan image needs the alignment an mmap gives.
    let mapped = strata_hs::AlignedBuf::from_bytes(&bytes);
    let engine =
        Arc::new(Engine::map(Box::new(mapped), &pubkey).map_err(|(_, m)| format!("bundle: {m}"))?);

    let stdin = io::stdin();
    let mut out = BufWriter::new(io::stdout().lock());
    for (n, line) in stdin.lock().lines().enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let req: Request =
            serde_json::from_str(&line).map_err(|e| format!("line {}: {e}", n + 1))?;
        let raw = req.uri.as_bytes();
        let (path, query) = match target_path(raw).iter().position(|&c| c == b'?') {
            Some(q) => (&target_path(raw)[..q], &target_path(raw)[q + 1..]),
            None => (target_path(raw), &b""[..]),
        };
        let mut tx = Tx::new(Some(engine.clone()), b"strata-eval", 0);
        tx.set_client_addr(req.remote_addr.as_bytes());
        tx.set_policy(policy.as_bytes());
        tx.request_line(
            req.method.as_bytes(),
            raw,
            &normalize(path),
            query,
            req.protocol.as_bytes(),
        );
        // As the connector: all headers in one call (it runs the
        // request_headers rules), then the body, empty for a GET, which
        // runs the request_body rules.
        let mut headers: Vec<(&[u8], &[u8])> = Vec::new();
        for (k, v) in &req.headers {
            match v {
                HeaderValue::One(v) => headers.push((k.as_bytes(), v.as_bytes())),
                HeaderValue::Many(vs) => {
                    headers.extend(vs.iter().map(|v| (k.as_bytes(), v.as_bytes())))
                }
            }
        }
        tx.request_headers(&headers);
        if tx.verdict().need_body {
            tx.request_body_chunk(req.body.as_bytes(), true);
        }
        let v = tx.verdict();
        let o = Out {
            id: &req.id,
            action: action(v.action),
            score: v.score,
            rules: &v.rules[..v.n_rules as usize],
            error: v.error,
        };
        serde_json::to_writer(&mut out, &o).map_err(|e| e.to_string())?;
        out.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("strata-eval: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize, target_path};

    #[test]
    fn absolute_form_targets_keep_their_path() {
        assert_eq!(target_path(b"http://api.example.test/a?b=1"), b"/a?b=1");
        assert_eq!(target_path(b"https://api.example.test"), b"/");
        assert_eq!(target_path(b"/p?u=http://x/y"), b"/p?u=http://x/y");
        assert_eq!(target_path(b"*"), b"*");
    }

    #[test]
    fn normalizes_like_nginx() {
        for (raw, want) in [
            (&b"/a/b"[..], &b"/a/b"[..]),
            (b"/a/%2e%2e/etc/passwd", b"/etc/passwd"),
            (b"//a///b/./c/", b"/a/b/c/"),
            (b"/%41%42", b"/AB"),
            (b"/bad%zz", b"/bad%zz"),
            (b"/", b"/"),
            (b"/../..", b"/"),
        ] {
            assert_eq!(normalize(raw), want, "{}", String::from_utf8_lossy(raw));
        }
    }
}
