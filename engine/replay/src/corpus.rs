//! Labelled requests from the repository's corpus (corpus/README.md) and
//! synthetic traffic, as samples: for `strata-replay gen` (load tests) and
//! `strata-replay semantic` (W20-R-01).

use std::path::{Path, PathBuf};

use crate::Sample;

/// Benign requests as they are, and every attack payload in a query value.
pub fn corpus_samples(dir: &Path) -> Result<Vec<Sample>, String> {
    Ok(corpus_labelled(dir, &["synthetic"])?
        .into_iter()
        .map(|(_, s)| s)
        .collect())
}

pub const ATTACKS: [&str; 4] = [
    "sql-injection",
    "xss",
    "command-injection",
    "path-traversal",
];

/// The requests of the benign files named (`benign/<name>.jsonl`) labelled
/// `benign`, then every attack payload in a query value labelled with its
/// attack type.
pub fn corpus_labelled(dir: &Path, benign: &[&str]) -> Result<Vec<(String, Sample)>, String> {
    let mut out = vec![];
    let read =
        |p: PathBuf| std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()));
    for name in benign {
        for line in read(dir.join(format!("benign/{name}.jsonl")))?.lines() {
            let v: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
            let uri = v["uri"].as_str().unwrap_or("/").to_string();
            let (path, args) = uri.split_once('?').unwrap_or((&uri, ""));
            let headers: Vec<(String, String)> = v["headers"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let body = v["body"].as_str().unwrap_or("").as_bytes().to_vec();
            out.push((
                "benign".to_string(),
                sample(
                    v["method"].as_str().unwrap_or("GET"),
                    &uri,
                    path,
                    args,
                    &headers,
                    body,
                    "allow",
                ),
            ));
        }
    }
    for kind in ATTACKS {
        for line in read(dir.join(format!("attack/{kind}.jsonl")))?.lines() {
            let v: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
            out.push((
                kind.to_string(),
                query_sample(v["payload"].as_str().unwrap_or(""), "block"),
            ));
        }
    }
    if out.is_empty() {
        return Err(format!("{}: empty corpus", dir.display()));
    }
    Ok(out)
}

/// `GET /v1/search?q=<value>` from a browser.
pub fn query_sample(value: &str, action: &str) -> Sample {
    let q = encode(value);
    let uri = format!("/v1/search?q={q}");
    let headers = vec![
        ("Host".to_string(), "api.example.test".to_string()),
        ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
    ];
    sample(
        "GET",
        &uri,
        "/v1/search",
        &format!("q={q}"),
        &headers,
        vec![],
        action,
    )
}

/// Every line of `file` (blank lines and `#` comments aside) as a query
/// value, labelled `label`.
pub fn value_samples(label: &str, file: &Path) -> Result<Vec<(String, Sample)>, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let action = if crate::semantic::is_benign(label) {
        "allow"
    } else {
        "block"
    };
    Ok(text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| (label.to_string(), query_sample(l, action)))
        .collect())
}

/// `n` multipart uploads like the staging pilot's (deploy/staging/
/// pilot-traffic.sh): three form fields and a file of 2 to 32 KiB of
/// random bytes, from a fixed seed. Labelled `benign-upload`.
pub fn upload_samples(n: usize) -> Vec<(String, Sample)> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        // xorshift64*: reproducible, not cryptographic
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    };
    let names = ["an", "binh", "chi", "dung", "giang", "hoa", "khanh", "linh"];
    (0..n)
        .map(|i| {
            let boundary = format!("------exampleBoundary{:016x}", next());
            let mut body = vec![];
            for (k, v) in [
                ("customer_id", (next() % 229_369).to_string()),
                ("kind", "id-front".to_string()),
                (
                    "comment",
                    format!("photo of {} (front side)", names[(next() % 8) as usize]),
                ),
            ] {
                body.extend_from_slice(
                    format!(
                        "--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
                    )
                    .as_bytes(),
                );
            }
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"photo.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n"
                )
                .as_bytes(),
            );
            let len = 2048 + (next() % 30_000) as usize;
            while body.len() < len {
                body.extend_from_slice(&next().to_le_bytes());
            }
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let headers = vec![
                ("Host".to_string(), "api.example.test".to_string()),
                ("User-Agent".to_string(), "example-web/1.0".to_string()),
                (
                    "Content-Type".to_string(),
                    format!("multipart/form-data; boundary={boundary}"),
                ),
                ("Content-Length".to_string(), body.len().to_string()),
            ];
            let mut s = sample("POST", "/v1/upload", "/v1/upload", "", &headers, body, "allow");
            s.ts_ms = i as i64;
            ("benign-upload".to_string(), s)
        })
        .collect()
}

fn sample(
    method: &str,
    raw: &str,
    path: &str,
    args: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
    action: &str,
) -> Sample {
    Sample {
        node_id: "synthetic".into(),
        policy: "example-api".into(),
        method: method.into(),
        raw_uri: raw.into(),
        uri: path.into(),
        args: args.into(),
        proto: "HTTP/1.1".into(),
        client: "~h:0000000000000000:s9".into(),
        headers: serde_json::to_string(headers).unwrap_or_else(|_| "[]".into()),
        body_len: body.len() as i64,
        body,
        action: action.into(),
        ..Sample::default()
    }
}

fn encode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}
