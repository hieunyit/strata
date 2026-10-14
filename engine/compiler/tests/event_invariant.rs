//! P-01 §1 invariant: no event datagram holds a payment card number, a
//! CCCD or a JWT. The attack corpus runs through the whole signature
//! package with such values added to the query and to a header; every
//! event the engine encodes is scanned with the engine's own matchers,
//! which must find nothing. Slow (a full Hyperscan compile): run with
//! cargo test --release -p strata-compiler --test event_invariant -- --ignored

use std::path::{Path, PathBuf};
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::detectors::response::{cccd, jwt, pan};
use libstrata::engine::Engine;
use libstrata::guard::{Ctx, Matcher};
use libstrata::tx::Tx;
use serde_json::Value;
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [47; 32];
const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every rule file under `dir` (as `strata-rules release` gathers them).
fn rule_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if p.is_dir() {
            if name != "schema" && name != "tests" && name != "reviews" {
                rule_files(&p, out);
            }
        } else if name.ends_with(".yaml") {
            out.push(p);
        }
    }
}

/// As url.QueryEscape.
fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn found(datagram: &[u8]) -> Vec<u32> {
    let ctx = Ctx {
        held: 0,
        before: None,
        end: true,
    };
    let mut hits = vec![];
    cccd::Cccd.find(datagram, ctx, &mut hits);
    jwt::Jwt::new().find(datagram, ctx, &mut hits);
    pan::Pan.find(datagram, ctx, &mut hits);
    hits.iter().map(|h| h.rule).collect()
}

#[test]
#[ignore]
fn no_event_holds_a_card_number_cccd_or_jwt() {
    let mut files = vec![];
    rule_files(&repo().join("rules"), &mut files);
    let mut defs = vec![];
    for f in files {
        let doc = from_yaml(&std::fs::read_to_string(&f).unwrap()).unwrap();
        let doc = if doc.get("rule").is_some() {
            serde_json::json!({"ir_version": 1, "ruleset": {"name": "p", "version": "1"}, "rules": [doc["rule"].clone()]})
        } else if doc.get("ir_version").is_some() {
            doc
        } else {
            continue;
        };
        defs.extend(rules_from_ir(&doc).unwrap());
    }
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce, max_snippet_size: 4096 }]")
            .unwrap(),
        Path::new("."),
    )
    .unwrap();
    let b = compile(
        &defs,
        &pol,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )
    .unwrap();
    let e = Arc::new(
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap(),
    );

    let (mut events, mut leaks) = (0, vec![]);
    let extra = format!("&card=4111+1111+1111+1111&id=001203012345&t={JWT}&n=5500000000000004");
    let mut dirs: Vec<_> = std::fs::read_dir(repo().join("corpus/attack"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    dirs.sort();
    for f in dirs {
        for (n, line) in std::fs::read_to_string(&f).unwrap().lines().enumerate() {
            let Ok(p) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let q = format!(
                "q={}{extra}",
                query_escape(p["payload"].as_str().unwrap_or(""))
            );
            let uri = format!("/search?{q}");
            let mut t = Tx::new(Some(e.clone()), b"node", 0);
            t.set_policy(b"example-api");
            t.set_client_addr(b"192.0.2.10");
            t.request_line(
                b"GET",
                uri.as_bytes(),
                b"/search",
                q.as_bytes(),
                b"HTTP/1.1",
            );
            let jwt_header = format!("Bearer {JWT}");
            t.request_headers(&[
                (b"Host", b"api.example.test"),
                (b"User-Agent", b"tool 4111111111111111"),
                (
                    b"Referer",
                    format!("https://app.example.test/?x={JWT}&c=001203012345").as_bytes(),
                ),
                (b"Authorization", jwt_header.as_bytes()),
                (b"X-Order", b"card 5500-0000-0000-0004 id 001203012345"),
            ]);
            // CRS runs most rules at stage request_body
            t.request_body_chunk(b"", true);
            if let Some(ev) = t.encode_event() {
                events += 1;
                let f = found(&ev);
                if !f.is_empty() {
                    leaks.push(format!("{}:{}: {f:?}", f.len(), n + 1));
                }
            }
        }
    }
    eprintln!("{events} events, {} with a leak", leaks.len());
    assert!(events > 1000, "only {events} events");
    assert!(
        leaks.is_empty(),
        "{}",
        leaks[..leaks.len().min(20)].join("\n")
    );
}
