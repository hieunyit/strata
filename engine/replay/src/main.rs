//! strata-replay: runs traffic samples through a bundle (W11-R-01).
//!
//! ```text
//! strata-replay run --bundle b.sbn --pubkey k.pub [--policy name] [--threads N] samples.parquet...
//! strata-replay compare --bundle draft.sbn --baseline current.sbn --pubkey k.pub [--baseline-pubkey k2.pub]
//!     [--policy name] [--threads N] [--md report.md] [--title T] samples.parquet...
//! strata-replay gen --out s.parquet --count N [--corpus <repo>/corpus]
//! strata-replay semantic --bundle b.sbn --pubkey k.pub [--policy name] [--threads N]
//!     [--corpus <repo>/corpus] [--values label=file,...] [--uploads N]
//!     [--md report.md] [--title T] [samples.parquet...]
//! ```
//!
//! `run` prints the report as JSON. `semantic` (W20-R-01) counts the
//! matches of the semantic detectors' rules per detector and label: the
//! corpus (benign files pilot and synthetic, labelled `benign`; attacks by
//! type), value lists (one query value per line; a label starting with
//! `benign` counts false positives), `--uploads` multipart uploads of
//! random bytes like the staging pilot's (`benign-upload`) and traffic
//! samples (`replay`); JSON on stdout, Markdown with `--md`. `gen` writes synthetic samples (format
//! 1 files) from the benign and attack corpora, for load tests: no personal
//! data, nothing anonymized.

use std::path::{Path, PathBuf};
use std::process::exit;

use strata_replay::corpus::{corpus_labelled, corpus_samples, upload_samples, value_samples};
use strata_replay::{Sample, compare, load_engine, run, semantic, write_file};

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("strata-replay: {msg}");
    exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        die("usage: strata-replay run|compare|gen|semantic ... (see the source header)")
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
        "compare" => {
            let pubkey = opt("pubkey").unwrap_or_else(|| die("--pubkey is required"));
            let draft = load_engine(
                Path::new(
                    &opt("bundle").unwrap_or_else(|| die("--bundle (the draft) is required")),
                ),
                Path::new(&pubkey),
            )
            .unwrap_or_else(|e| die(e));
            let baseline = load_engine(
                Path::new(&opt("baseline").unwrap_or_else(|| die("--baseline is required"))),
                Path::new(&opt("baseline-pubkey").unwrap_or(pubkey)),
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
            let c = compare(draft, baseline, &refs, policy.as_deref(), threads)
                .unwrap_or_else(|e| die(e));
            if let Some(md) = opt("md") {
                std::fs::write(
                    &md,
                    c.markdown(
                        &opt("title").unwrap_or_else(|| "Replay: draft against baseline".into()),
                    ),
                )
                .unwrap_or_else(|e| die(format!("{md}: {e}")));
            }
            println!("{}", serde_json::to_string_pretty(&c).unwrap_or_default());
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
        "semantic" => {
            let engine = load_engine(
                Path::new(&opt("bundle").unwrap_or_else(|| die("--bundle is required"))),
                Path::new(&opt("pubkey").unwrap_or_else(|| die("--pubkey is required"))),
            )
            .unwrap_or_else(|e| die(e));
            let threads = opt("threads")
                .map(|t| t.parse().unwrap_or_else(|_| die("--threads is a number")))
                .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
            let mut labelled = vec![];
            if let Some(dir) = opt("corpus") {
                labelled.extend(
                    corpus_labelled(Path::new(&dir), &["pilot", "synthetic"])
                        .unwrap_or_else(|e| die(e)),
                );
            }
            for spec in opt("values").iter().flat_map(|v| v.split(',')) {
                let (label, file) = spec
                    .split_once('=')
                    .unwrap_or_else(|| die(format!("--values {spec}: label=file")));
                labelled.extend(value_samples(label, Path::new(file)).unwrap_or_else(|e| die(e)));
            }
            if let Some(n) = opt("uploads") {
                labelled.extend(upload_samples(
                    n.parse().unwrap_or_else(|_| die("--uploads is a number")),
                ));
            }
            if labelled.is_empty() && files.is_empty() {
                die("nothing to run: --corpus, --values, --uploads or sample files");
            }
            let refs: Vec<&Path> = files.iter().map(|p| p.as_path()).collect();
            let policy = opt("policy");
            let r = semantic::run(engine, &labelled, &refs, policy.as_deref(), threads)
                .unwrap_or_else(|e| die(e));
            if let Some(md) = opt("md") {
                std::fs::write(
                    &md,
                    r.markdown(
                        &opt("title")
                            .unwrap_or_else(|| "Semantic detectors: matches per label".into()),
                    ),
                )
                .unwrap_or_else(|e| die(format!("{md}: {e}")));
            }
            println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
        }
        _ => die(format!("unknown command {cmd}")),
    }
}
