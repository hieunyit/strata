//! W12-N-01: libstrata's anonymizer gives the records the control plane's
//! writer gives (docs/spec/replay-sample.md › 4): the vectors of the
//! specification, and a corpus of 400 generated requests written by
//! control-plane/replay's TestDifferentialCorpus.

use std::path::PathBuf;

use libstrata::anon::{Anonymizer, Request};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn b64(s: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = vec![];
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|&c| c != b'=') {
        acc = (acc << 6) | T.iter().position(|&t| t == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn anonymizer(v: &serde_json::Value) -> Anonymizer {
    let key: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&v["key_hex"].as_str().unwrap()[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    Anonymizer::new(&key, v["key_id"].as_str().unwrap()).unwrap()
}

#[test]
fn spec_vectors() {
    let v: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repo().join("docs/spec/examples/replay-anon-v1.json")).unwrap(),
    )
    .unwrap();
    let a = anonymizer(&v);
    for (i, c) in v["cases"].as_array().unwrap().iter().enumerate() {
        let inp = &c["input"];
        let s = |k: &str| inp[k].as_str().unwrap_or_default().as_bytes().to_vec();
        let (node, policy, method, raw, uri, args, proto, client, action) = (
            s("NodeID"),
            s("Policy"),
            s("Method"),
            s("RawURI"),
            s("URI"),
            s("Args"),
            s("Proto"),
            s("Client"),
            s("Action"),
        );
        let headers: Vec<(Vec<u8>, Vec<u8>)> = inp["Headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                (
                    h[0].as_str().unwrap().as_bytes().to_vec(),
                    h[1].as_str().unwrap().as_bytes().to_vec(),
                )
            })
            .collect();
        let body = inp["Body"].as_str().map(b64).unwrap_or_default();
        let rules: Vec<u32> = inp["Rules"].as_array().map_or(vec![], |r| {
            r.iter().map(|x| x.as_u64().unwrap() as u32).collect()
        });
        let req = Request {
            ts_ms: inp["TsMs"].as_i64().unwrap(),
            node_id: &node,
            policy: &policy,
            method: &method,
            raw_uri: &raw,
            uri: &uri,
            args: &args,
            proto: &proto,
            client: &client,
            headers: headers
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect(),
            body: &body,
            body_len: None,
            action: &action,
            rules: &rules,
        };
        let r = a.anonymize(&req);
        let o = &c["output"];
        let str_of = |k: &str| o[k].as_str().unwrap_or_default().as_bytes().to_vec();
        assert_eq!(
            String::from_utf8_lossy(&r.raw_uri),
            String::from_utf8_lossy(&str_of("raw_uri")),
            "case {i}"
        );
        assert_eq!(r.uri, str_of("uri"), "case {i}");
        assert_eq!(r.args, str_of("args"), "case {i}");
        assert_eq!(r.client, str_of("client"), "case {i}");
        assert_eq!(
            String::from_utf8_lossy(&r.headers),
            String::from_utf8_lossy(&str_of("headers")),
            "case {i}"
        );
        assert_eq!(
            String::from_utf8_lossy(&r.body),
            String::from_utf8_lossy(&o["body"].as_str().map(b64).unwrap_or_default()),
            "case {i}"
        );
        assert_eq!(
            (r.body_len, r.body_truncated),
            (
                o["body_len"].as_i64().unwrap(),
                o["body_truncated"].as_bool().unwrap()
            )
        );
        assert_eq!(r.rules, str_of("rules"));
    }
}

#[test]
fn differential_corpus() {
    let v: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repo().join("engine/tests/fixtures/anon-corpus-v1.json")).unwrap(),
    )
    .unwrap();
    let mut a = anonymizer(&v);
    a.max_body = v["max_body"].as_u64().unwrap() as usize;
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 400);
    let mut failed = vec![];
    for (i, c) in cases.iter().enumerate() {
        let f: Vec<Vec<u8>> = c["in"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| b64(x.as_str().unwrap_or_default()))
            .collect();
        let headers: Vec<(Vec<u8>, Vec<u8>)> = c["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| (b64(h[0].as_str().unwrap()), b64(h[1].as_str().unwrap())))
            .collect();
        let rules: Vec<u32> = c["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u32)
            .collect();
        let req = Request {
            ts_ms: c["ts_ms"].as_i64().unwrap(),
            node_id: &f[0],
            policy: &f[1],
            method: &f[2],
            raw_uri: &f[3],
            uri: &f[4],
            args: &f[5],
            proto: &f[6],
            client: &f[7],
            headers: headers
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect(),
            body: &f[8],
            body_len: None,
            action: &f[9],
            rules: &rules,
        };
        let r = a.anonymize(&req);
        let want: Vec<Vec<u8>> = c["out"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| b64(x.as_str().unwrap_or_default()))
            .collect();
        let got = [
            &r.raw_uri, &r.uri, &r.args, &r.client, &r.headers, &r.body, &r.rules,
        ];
        let names = [
            "raw_uri", "uri", "args", "client", "headers", "body", "rules",
        ];
        for k in 0..7 {
            if *got[k] != want[k] {
                failed.push(format!(
                    "case {i} {}:\n  in   {:?}\n  got  {:?}\n  want {:?}",
                    names[k],
                    String::from_utf8_lossy(if k == 5 { &f[8] } else { &f[3] }),
                    String::from_utf8_lossy(got[k]),
                    String::from_utf8_lossy(&want[k])
                ));
            }
        }
        if (r.body_len, r.body_truncated)
            != (
                c["body_len"].as_i64().unwrap(),
                c["body_truncated"].as_bool().unwrap(),
            )
        {
            failed.push(format!("case {i}: body_len/truncated"));
        }
    }
    assert!(
        failed.is_empty(),
        "{} differences:\n{}",
        failed.len(),
        failed[..failed.len().min(8)].join("\n")
    );
}
