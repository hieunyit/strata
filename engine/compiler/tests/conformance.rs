//! Conformance corpus v1 (W08-Q-01, reworked by the W08 review): every
//! request of conformance/corpus/v1.jsonl runs through the engine with the
//! bundle the NGINX test suite uses (connectors/nginx/t/fixtures, compiled
//! from engine/compiler/examples/rules.yaml), policy example-api, as the
//! NGINX connector would call it; the action and the set of matched rules
//! must be the expectation. connectors/nginx/t/080-conformance.t (generated
//! from the same corpus) checks the same through NGINX. Run on every
//! engine/ and connectors/ PR (`make test-conformance`).

use std::path::PathBuf;
use std::sync::Arc;

use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK};
use serde_json::Value;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn engine() -> Arc<Engine> {
    let fx = repo().join("connectors/nginx/t/fixtures");
    let b = std::fs::read(fx.join("bundle/bundle-1.sbn")).unwrap();
    let key: [u8; 32] = std::fs::read(fx.join("bundle.pub"))
        .unwrap()
        .try_into()
        .unwrap();
    Arc::new(Engine::map(Box::new(strata_hs::AlignedBuf::from_bytes(&b)), &key).unwrap())
}

/// The request target as the corpus writes it, with @ARGS<n>@ expanded.
pub fn expand(uri: &str) -> String {
    match (uri.find("@ARGS"), uri.rfind('@')) {
        (Some(i), Some(j)) if j > i + 5 => {
            let n: usize = uri[i + 5..j].parse().unwrap();
            let args: Vec<String> = (0..n).map(|k| format!("a{k}=1")).collect();
            format!("{}{}{}", &uri[..i], args.join("&"), &uri[j + 1..])
        }
        _ => uri.to_string(),
    }
}

/// NGINX's normalized path (r->uri): percent-decoded, slashes merged, dot
/// segments resolved.
fn normalize(path: &str) -> Vec<u8> {
    let raw = path.as_bytes();
    let mut dec = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let hex = raw
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        if let (b'%', Some(Ok(b))) = (raw[i], hex.map(|h| u8::from_str_radix(h, 16))) {
            dec.push(b);
            i += 3;
            continue;
        }
        dec.push(raw[i]);
        i += 1;
    }
    let mut segs: Vec<&[u8]> = vec![];
    for s in dec.split(|&c| c == b'/') {
        match s {
            b"" | b"." => {}
            b".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let mut out = vec![b'/'];
    out.extend(segs.join(&b'/'));
    if dec.ends_with(b"/") && out.len() > 1 {
        out.push(b'/');
    }
    out
}

#[test]
fn corpus_v1() {
    let e = engine();
    let corpus = std::fs::read_to_string(repo().join("conformance/corpus/v1.jsonl")).unwrap();
    let mut checked = 0;
    for line in corpus.lines().filter(|l| !l.trim().is_empty()) {
        let c: Value = serde_json::from_str(line).unwrap();
        let name = c["name"].as_str().unwrap();
        let uri = expand(c["uri"].as_str().unwrap());
        let (path, args) = uri.split_once('?').unwrap_or((&uri, ""));
        let mut headers: Vec<(String, String)> = vec![("Host".into(), "api.example.test".into())];
        if let Some(h) = c["headers"].as_object() {
            for (k, v) in h {
                match v {
                    Value::Array(vs) => headers.extend(
                        vs.iter()
                            .map(|x| (k.clone(), x.as_str().unwrap().to_string())),
                    ),
                    v => headers.push((k.clone(), v.as_str().unwrap().to_string())),
                }
            }
        }
        // the body NGINX hands over: none for a request it frames itself
        // (framed), and a Content-Length when the corpus leaves it out
        let framed = c["framed"].as_bool().unwrap_or(false);
        let body = if framed {
            ""
        } else {
            c["body"].as_str().unwrap_or("")
        };
        let chunked = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Transfer-Encoding"));
        if !body.is_empty()
            && !chunked
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        {
            headers.push(("Content-Length".into(), body.len().to_string()));
        }

        let mut t = Tx::new(Some(e.clone()), b"node", 0);
        t.set_policy(b"example-api");
        t.set_client_addr(b"127.0.0.1");
        let method = c["method"].as_str().unwrap_or("GET");
        t.request_line(
            method.as_bytes(),
            uri.as_bytes(),
            &normalize(path),
            args.as_bytes(),
            b"HTTP/1.1",
        );
        let hs: Vec<(&[u8], &[u8])> = headers
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();
        t.request_headers(&hs);
        t.request_body_chunk(body.as_bytes(), true);
        let v = t.verdict();

        let mut got: Vec<u32> = v.rules[..v.n_rules as usize].to_vec();
        got.sort_unstable();
        got.dedup();
        let mut want: Vec<u32> = c["expect"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_u64().unwrap() as u32)
            .collect();
        want.sort_unstable();
        let action = match c["expect"]["action"].as_str().unwrap() {
            "allow" => ACTION_ALLOW,
            "block" => ACTION_BLOCK,
            a => panic!("{name}: unknown expected action {a}"),
        };
        assert_eq!(
            (v.action, &got),
            (action, &want),
            "{name}: action {} score {} rules {got:?}, want action {action} rules {want:?}",
            v.action,
            v.score
        );
        checked += 1;
    }
    assert!(checked >= 30, "corpus has {checked} cases");
}
