//! strata-replay: runs traffic samples through a bundle (W11-R-01).
//!
//! ```text
//! strata-replay run --bundle b.sbn --pubkey k.pub [--policy name] [--threads N] samples.parquet...
//! strata-replay gen --out s.parquet --count N [--corpus <repo>/corpus]
//! ```
//!
//! `run` prints the report as JSON. `gen` writes synthetic samples (format
//! 1 files) from the benign and attack corpora, for load tests: no personal
//! data, nothing anonymized.

use std::path::{Path, PathBuf};
use std::process::exit;

use strata_replay::{Sample, load_engine, run, write_file};

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("strata-replay: {msg}");
    exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        die("usage: strata-replay run|gen ... (see the source header)")
    };
    let mut opts = std::collections::HashMap::new();
    let mut files = vec![];
    let mut i = 1;
    while i < args.len() {
        if let Some(k) = args[i].strip_prefix("--") {
            let v = args
                .get(i + 1)
                .cloned()
                .unwrap_or_else(|| die(format!("--{k} needs a value")));
            opts.insert(k.to_string(), v);
            i += 2;
        } else {
            files.push(PathBuf::from(&args[i]));
            i += 1;
        }
    }
    let opt = |k: &str| opts.get(k).cloned();
    match cmd.as_str() {
        "run" => {
            let engine = load_engine(
                Path::new(&opt("bundle").unwrap_or_else(|| die("--bundle is required"))),
                Path::new(&opt("pubkey").unwrap_or_else(|| die("--pubkey is required"))),
            )
            .unwrap_or_else(|e| die(e));
            if files.is_empty() {
                die("no sample file");
            }
            let threads = opt("threads")
                .map(|t| t.parse().unwrap_or_else(|_| die("--threads is a number")))
                .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
            let refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
            let policy = opt("policy");
            let r = run(engine, &refs, policy.as_deref(), threads).unwrap_or_else(|e| die(e));
            println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
        }
        "gen" => {
            let out = opt("out").unwrap_or_else(|| die("--out is required"));
            let count: usize = opt("count")
                .unwrap_or_else(|| die("--count is required"))
                .parse()
                .unwrap_or_else(|_| die("--count is a number"));
            let corpus = PathBuf::from(opt("corpus").unwrap_or_else(|| "corpus".into()));
            let base = corpus_samples(&corpus).unwrap_or_else(|e| die(e));
            let samples: Vec<Sample> = (0..count)
                .map(|n| {
                    let mut s = base[n % base.len()].clone();
                    s.ts_ms = 1_791_939_600_000 + n as i64;
                    s
                })
                .collect();
            write_file(Path::new(&out), "synthetic", &samples, 65_536).unwrap_or_else(|e| die(e));
            eprintln!(
                "strata-replay: {count} samples from {} corpus requests -> {out}",
                base.len()
            );
        }
        _ => die(format!("unknown command {cmd}")),
    }
}

/// Benign requests as they are, and every attack payload in a query value.
fn corpus_samples(dir: &Path) -> Result<Vec<Sample>, String> {
    let mut out = vec![];
    let read =
        |p: PathBuf| std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()));
    for line in read(dir.join("benign/synthetic.jsonl"))?.lines() {
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
        out.push(sample(
            v["method"].as_str().unwrap_or("GET"),
            &uri,
            path,
            args,
            &headers,
            body,
            "allow",
        ));
    }
    for kind in [
        "sql-injection",
        "xss",
        "command-injection",
        "path-traversal",
    ] {
        for line in read(dir.join(format!("attack/{kind}.jsonl")))?.lines() {
            let v: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
            let q = encode(v["payload"].as_str().unwrap_or(""));
            let uri = format!("/v1/search?q={q}");
            let headers = vec![
                ("Host".to_string(), "api.example.test".to_string()),
                ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
            ];
            out.push(sample(
                "GET",
                &uri,
                "/v1/search",
                &format!("q={q}"),
                &headers,
                vec![],
                "block",
            ));
        }
    }
    if out.is_empty() {
        return Err(format!("{}: empty corpus", dir.display()));
    }
    Ok(out)
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
