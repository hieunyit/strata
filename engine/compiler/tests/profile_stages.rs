//! Profile breakdown of benign request processing across stages.

use std::sync::Arc;
use std::time::Instant;

use libstrata::engine::Engine;
use libstrata::tx::Tx;

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

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

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

struct ParsedReq {
    method: String,
    uri: String,
    protocol: String,
    remote_addr: String,
    body: String,
    headers: Vec<(String, String)>,
}

#[test]
#[ignore]
fn profile_benign_stages() {
    let bundle_path = format!("{}/../../build/bench/b.sbn", env!("CARGO_MANIFEST_DIR"));
    let pubkey_path = format!("{}/../../build/bench/pub", env!("CARGO_MANIFEST_DIR"));
    let req_path = format!(
        "{}/../../corpus/benign/synthetic.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );

    let bytes = std::fs::read(&bundle_path).expect("bundle file");
    let pubkey = std::fs::read(&pubkey_path).expect("pubkey file");
    let mapped = strata_hs::AlignedBuf::from_bytes(&bytes);
    let key: [u8; 32] = pubkey.try_into().expect("pubkey 32 bytes");
    let engine = Arc::new(Engine::map(Box::new(mapped), &key).expect("engine map"));

    let content = std::fs::read_to_string(&req_path).expect("synthetic.jsonl");
    let mut requests: Vec<ParsedReq> = Vec::new();
    for l in content.lines() {
        if l.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        let method = v
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("GET")
            .to_string();
        let uri = v
            .get("uri")
            .and_then(|u| u.as_str())
            .unwrap_or("/")
            .to_string();
        let protocol = v
            .get("protocol")
            .and_then(|p| p.as_str())
            .unwrap_or("HTTP/1.1")
            .to_string();
        let remote_addr = v
            .get("remote_addr")
            .and_then(|r| r.as_str())
            .unwrap_or("")
            .to_string();
        let body = v
            .get("body")
            .and_then(|b| b.as_str())
            .unwrap_or("")
            .to_string();
        let mut headers = Vec::new();
        if let Some(obj) = v.get("headers").and_then(|h| h.as_object()) {
            for (k, val) in obj {
                if let Some(s) = val.as_str() {
                    headers.push((k.clone(), s.to_string()));
                } else if let Some(arr) = val.as_array() {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            headers.push((k.clone(), s.to_string()));
                        }
                    }
                }
            }
        }
        requests.push(ParsedReq {
            method,
            uri,
            protocol,
            remote_addr,
            body,
            headers,
        });
    }

    // Warmup
    for req in requests.iter().take(50) {
        let raw = req.uri.as_bytes();
        let (path, query) = match target_path(raw).iter().position(|&c| c == b'?') {
            Some(q) => (&target_path(raw)[..q], &target_path(raw)[q + 1..]),
            None => (target_path(raw), &b""[..]),
        };
        let mut tx = Tx::new(Some(engine.clone()), b"bench", 0);
        tx.set_client_addr(req.remote_addr.as_bytes());
        tx.set_policy(b"t");
        tx.request_line(
            req.method.as_bytes(),
            raw,
            &normalize(path),
            query,
            req.protocol.as_bytes(),
        );
    }

    let mut dur_tx_new = 0u128;
    let mut dur_req_line = 0u128;
    let mut dur_req_headers = 0u128;
    let mut dur_req_body = 0u128;
    let mut dur_verdict = 0u128;

    let start_all = Instant::now();
    for _ in 0..10 {
        for req in &requests {
            let raw = req.uri.as_bytes();
            let (path, query) = match target_path(raw).iter().position(|&c| c == b'?') {
                Some(q) => (&target_path(raw)[..q], &target_path(raw)[q + 1..]),
                None => (target_path(raw), &b""[..]),
            };
            let norm_path = normalize(path);

            let s = Instant::now();
            let mut tx = Tx::new(Some(engine.clone()), b"bench", 0);
            tx.set_client_addr(req.remote_addr.as_bytes());
            tx.set_policy(b"t");
            dur_tx_new += s.elapsed().as_nanos();

            let s = Instant::now();
            tx.request_line(
                req.method.as_bytes(),
                raw,
                &norm_path,
                query,
                req.protocol.as_bytes(),
            );
            dur_req_line += s.elapsed().as_nanos();

            let headers_bytes: Vec<(&[u8], &[u8])> = req
                .headers
                .iter()
                .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
                .collect();
            let s = Instant::now();
            tx.request_headers(&headers_bytes);
            dur_req_headers += s.elapsed().as_nanos();

            let s = Instant::now();
            if tx.verdict().need_body {
                tx.request_body_chunk(req.body.as_bytes(), true);
            }
            dur_req_body += s.elapsed().as_nanos();

            let s = Instant::now();
            let _ = tx.verdict();
            dur_verdict += s.elapsed().as_nanos();
        }
    }
    let total_elapsed = start_all.elapsed();

    let n = (requests.len() * 10) as u128;
    eprintln!("=== BENCHMARK STAGE BREAKDOWN ({} requests) ===", n);
    eprintln!(
        "Total wall-clock:     {:>8.2} ms",
        total_elapsed.as_secs_f64() * 1000.0
    );
    eprintln!(
        "Tx::new + setup:      {:>8.2} ms ({:>6.2} µs/req)",
        (dur_tx_new as f64) / 1e6,
        (dur_tx_new as f64) / (n as f64) / 1e3
    );
    eprintln!(
        "request_line:         {:>8.2} ms ({:>6.2} µs/req)",
        (dur_req_line as f64) / 1e6,
        (dur_req_line as f64) / (n as f64) / 1e3
    );
    eprintln!(
        "request_headers:      {:>8.2} ms ({:>6.2} µs/req)",
        (dur_req_headers as f64) / 1e6,
        (dur_req_headers as f64) / (n as f64) / 1e3
    );
    eprintln!(
        "request_body:         {:>8.2} ms ({:>6.2} µs/req)",
        (dur_req_body as f64) / 1e6,
        (dur_req_body as f64) / (n as f64) / 1e3
    );
    eprintln!(
        "verdict:              {:>8.2} ms ({:>6.2} µs/req)",
        (dur_verdict as f64) / 1e6,
        (dur_verdict as f64) / (n as f64) / 1e3
    );
}
