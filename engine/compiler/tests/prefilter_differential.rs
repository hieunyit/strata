//! W09-R-01: the speed-ups give the verdicts of before. Every rule of the
//! repository (the signature package) is compiled twice:
//!   reference  as compilers before W09 (no condition lowered out of the
//!              Hyperscan database), evaluated without the prefilter, every
//!              rule on every request;
//!   fast       as now (gates first, secondary conditions as lazily
//!              compiled regexes), evaluated with the prefilter.
//! The attack corpus (each payload in a query and in a form body, and in
//! the path for traversal) and the benign corpus run through both: action,
//! score and matched rules must be identical.
//!
//! #28: payloads also go in JSON bodies, in cookies and among many other
//! form fields, where the prefilter's per-value pass shares work.
//!
//! #27: a third bundle has the block-mode copy of the database
//! (HYPERSCAN_BLOCK), which scans values up to 2048 bytes; it must give
//! the same verdicts too. Payloads are also sent padded to just under,
//! at and just over that length, so both databases are used.
//!
//! Slow in debug builds (two full Hyperscan compiles); run with
//! `cargo test --release -p strata-compiler --test prefilter_differential
//! -- --ignored`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use libstrata::bundle::public_key;
use libstrata::engine::Engine;
use libstrata::tx::Tx;
use serde_json::Value;
use strata_compiler::{
    Build, Options, compile, compile_opts, compile_reference, from_yaml, policies_from,
    rules_from_ir,
};

const SEED: [u8; 32] = [9; 32];

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

fn engines() -> (Arc<Engine>, Arc<Engine>, Arc<Engine>, Arc<Engine>) {
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
        defs.extend(rules_from_ir(&doc).unwrap_or_else(|e| panic!("{}: {e}", f.display())));
    }
    assert!(defs.len() > 5000, "only {} rules", defs.len());
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        Path::new("."),
    )
    .unwrap();
    let build = Build {
        version: 1,
        created_at_ms: 0,
        rollback: false,
    };
    let map = |b: Vec<u8>| {
        Engine::map(
            Box::new(strata_hs::AlignedBuf::from_bytes(&b)),
            &public_key(&SEED),
        )
        .unwrap()
    };
    let mut reference = map(compile_reference(&defs, &pol, &build, &SEED).unwrap());
    reference.disable_prefilter();
    let fast = map(compile(&defs, &pol, &build, &SEED).unwrap());
    let block = map(compile_opts(
        &defs,
        &pol,
        &build,
        &SEED,
        Options {
            hs_block: true,
            ..Default::default()
        },
    )
    .unwrap());
    assert!(fast.hyperscan_block().is_none());
    assert!(
        block.hyperscan_block().is_some(),
        "no HYPERSCAN_BLOCK section"
    );
    // #27/#28: one block database per transformation chain
    let chains = map(compile_opts(
        &defs,
        &pol,
        &build,
        &SEED,
        Options {
            hs_block: true,
            hs_chains: true,
        },
    )
    .unwrap());
    assert!(
        chains.tables().n_hyperscan_chains() > 1,
        "no HYPERSCAN_CHAINS section"
    );
    assert!(
        chains.hyperscan_block().is_none(),
        "chains replace HYPERSCAN_BLOCK"
    );
    (
        Arc::new(reference),
        Arc::new(fast),
        Arc::new(block),
        Arc::new(chains),
    )
}

struct Req {
    id: String,
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    body: String,
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

fn requests() -> Vec<Req> {
    let host = || vec![("Host".to_string(), "api.example.test".to_string())];
    let mut out = vec![];
    let mut files: Vec<_> = std::fs::read_dir(repo().join("corpus/attack"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    for f in files {
        for (n, line) in std::fs::read_to_string(&f).unwrap().lines().enumerate() {
            let Ok(p) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let payload = p["payload"].as_str().unwrap_or("");
            let q = query_escape(payload);
            let id = format!("{}:{}", f.file_name().unwrap().to_string_lossy(), n + 1);
            out.push(Req {
                id: format!("{id}/query"),
                method: "GET".into(),
                uri: format!("/search?q={q}"),
                headers: host(),
                body: String::new(),
            });
            // around the block scan limit: the value (q, decoded) just
            // under, at and over 2048 bytes, the payload at its end
            if n % 4 == 0 {
                for len in [2047usize, 2048, 2049, 4200] {
                    let pad = len.saturating_sub(payload.len());
                    out.push(Req {
                        id: format!("{id}/long{len}"),
                        method: "GET".into(),
                        uri: format!("/search?q={}{q}", "a".repeat(pad)),
                        headers: host(),
                        body: String::new(),
                    });
                }
            }
            let mut h = host();
            h.push((
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ));
            out.push(Req {
                id: format!("{id}/form"),
                method: "POST".into(),
                uri: "/comments".into(),
                headers: h,
                body: format!("comment={q}"),
            });
            // #28: the prefilter scans each value once for every group that
            // reads it; the same payload in JSON, in a cookie, and among
            // many other fields (some with equal values) must give the
            // verdicts of before
            if n % 3 == 0 {
                let mut h = host();
                h.push(("Content-Type".into(), "application/json".into()));
                let j = serde_json::to_string(payload).unwrap();
                out.push(Req {
                    id: format!("{id}/json"),
                    method: "POST".into(),
                    uri: "/v1/items".into(),
                    headers: h,
                    body: format!(
                        r#"{{"items":[{{"id":1,"name":"a"}},{{"note":{j},"tags":["x",{j}]}}]}}"#
                    ),
                });
                let mut h = host();
                h.push(("Cookie".into(), format!("theme=dark; pref={q}")));
                out.push(Req {
                    id: format!("{id}/cookie"),
                    method: "GET".into(),
                    uri: "/".into(),
                    headers: h,
                    body: String::new(),
                });
                let mut h = host();
                h.push((
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                ));
                let mut body: Vec<String> = (0..60)
                    .map(|i| format!("field{i}=same+text+value&n{i}={i}"))
                    .collect();
                body.insert(37, format!("comment={q}"));
                out.push(Req {
                    id: format!("{id}/many"),
                    method: "POST".into(),
                    uri: format!("/comments?page=2&q={q}"),
                    headers: h,
                    body: body.join("&"),
                });
            }
            if p["attack_type"] == "path-traversal" {
                let path = payload.trim_start_matches('/');
                if !path.contains([' ', '\t', '#', '?']) {
                    out.push(Req {
                        id: format!("{id}/path"),
                        method: "GET".into(),
                        uri: format!("/static/{path}"),
                        headers: host(),
                        body: String::new(),
                    });
                }
            }
        }
    }
    for line in std::fs::read_to_string(repo().join("corpus/benign/synthetic.jsonl"))
        .unwrap()
        .lines()
    {
        let Ok(b) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let headers = b["headers"]
            .as_object()
            .map(|h| {
                h.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();
        out.push(Req {
            id: b["id"].as_str().unwrap_or("").into(),
            method: b["method"].as_str().unwrap_or("GET").into(),
            uri: b["uri"].as_str().unwrap_or("/").into(),
            headers,
            body: b["body"].as_str().unwrap_or("").into(),
        });
    }
    out
}

fn verdict(e: &Arc<Engine>, r: &Req) -> (u32, i32, Vec<u32>) {
    let (path, args) = r.uri.split_once('?').unwrap_or((&r.uri, ""));
    let mut t = Tx::new(Some(e.clone()), b"node", 0);
    t.set_policy(b"example-api");
    t.set_client_addr(b"192.0.2.10");
    t.request_line(
        r.method.as_bytes(),
        r.uri.as_bytes(),
        path.as_bytes(),
        args.as_bytes(),
        b"HTTP/1.1",
    );
    let mut headers = r.headers.clone();
    if !r.body.is_empty()
        && !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
    {
        headers.push(("Content-Length".into(), r.body.len().to_string()));
    }
    let hs: Vec<(&[u8], &[u8])> = headers
        .iter()
        .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
        .collect();
    t.request_headers(&hs);
    t.request_body_chunk(r.body.as_bytes(), true);
    let v = t.verdict();
    let mut rules = v.rules[..v.n_rules as usize].to_vec();
    rules.sort_unstable();
    (v.action, v.score, rules)
}

#[test]
#[ignore]
fn prefilter_gives_the_verdicts_of_before() {
    let (reference, fast, block, chains) = engines();
    let reqs = requests();
    assert!(reqs.len() > 7000, "only {} requests", reqs.len());
    let mut differ = vec![];
    let mut matched = 0;
    for r in &reqs {
        let (a, b, c) = (
            verdict(&reference, r),
            verdict(&fast, r),
            verdict(&block, r),
        );
        if !a.2.is_empty() {
            matched += 1;
        }
        if a != b {
            differ.push(format!("{}: reference {a:?}, fast {b:?}", r.id));
        }
        if a != c {
            differ.push(format!("{}: reference {a:?}, hs block {c:?}", r.id));
        }
        let d = verdict(&chains, r);
        if a != d {
            differ.push(format!("{}: reference {a:?}, hs chains {d:?}", r.id));
        }
    }
    eprintln!(
        "{} requests, {matched} with a matched rule, {} differ",
        reqs.len(),
        differ.len()
    );
    assert!(matched > 3000, "the corpus barely matches: {matched}");
    assert!(
        differ.is_empty(),
        "{} verdicts differ:\n{}",
        differ.len(),
        differ[..differ.len().min(20)].join("\n")
    );
}
