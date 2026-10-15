//! strata-pattern-cost (#28): what each Hyperscan pattern of a bundle costs
//! on short values, and what leaving the most expensive ones out of the
//! database would save.
//!
//! The scans of a request are mostly short values (arguments, headers)
//! scanned one by one, and each scan of the full database costs a few
//! microseconds whatever its length. This tool tells which patterns make
//! that fixed cost. Compiling and timing are separate steps, so that the
//! compiles run on the build CPUs and the timings on a quiet one:
//!
//!   strata-pattern-cost prepare --rules <ir>... --corpus <jsonl>... --out <dir>
//!       the patterns as `compile` builds them (patterns.json), sample
//!       values of the corpus (values.json), the full database in block
//!       mode and one database per pattern (images.bin, images.json)
//!   strata-pattern-cost time --dir <dir> [--rounds N]
//!       ns per scan of the full database and of each pattern alone, over
//!       the values; ranking in rank.json, a summary on stdout
//!   strata-pattern-cost minus --dir <dir> [--k 10,50,200] [--drop 932340,...]
//!                             [--sources et-open,crs,...]
//!       the full database without the K patterns most expensive alone,
//!       without the patterns of some rules, or of a whole source;
//!       `--each-rule-of crs`: one database per rule of that source, without
//!       that rule (what each rule adds to the full database)
//!   strata-pattern-cost time-minus --dir <dir> [--rounds N]
//!       ns per scan of each of those databases
//!   strata-pattern-cost regex --dir <dir> --rule <id> [--rounds N]
//!       ns per value of the rule's patterns run as the engine's fallback
//!       (regex crate, lazy DFA) instead of Hyperscan, and of the same
//!       patterns alone in Hyperscan
//!
//! A pattern alone is not what it adds to the full database (Hyperscan
//! shares literal matching between patterns): the "minus" steps measure
//! that.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use serde_json::{Value, json};
use strata_compiler::{hyperscan_patterns, load, rules_from_ir};
use strata_hs::{AlignedBuf, HS_MODE_BLOCK, MappedDb, Pattern, compile_mode};

type Result<T> = std::result::Result<T, String>;

/// Values sampled from the corpus at most (distinct).
const MAX_VALUES: usize = 4000;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("prepare") => prepare(&args[1..]),
        Some("time") => time(&args[1..]),
        Some("minus") => minus(&args[1..]),
        Some("time-minus") => time_minus(&args[1..]),
        Some("regex") => regex_cost(&args[1..]),
        _ => Err(
            "usage: strata-pattern-cost prepare|time|minus|time-minus ... (see the source)".into(),
        ),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("strata-pattern-cost: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Values of `--name` (repeatable).
fn opts<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.windows(2)
        .filter(|w| w[0] == name)
        .map(|w| w[1].as_str())
        .collect()
}

fn opt<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    opts(args, name).into_iter().next()
}

fn dir_of(args: &[String]) -> Result<PathBuf> {
    opt(args, "--dir")
        .or_else(|| opt(args, "--out"))
        .map(PathBuf::from)
        .ok_or_else(|| "--dir is required".to_string())
}

/// `%XX` and `+` decoded (no validation: sample values only).
fn form_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                match (hex(b[i + 1]), hex(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    out
}

fn pairs(q: &str, out: &mut Vec<Vec<u8>>) {
    for p in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        out.push(form_decode(k));
        out.push(form_decode(v));
    }
}

/// The values a request gives the scans: path, query and form fields
/// (names and values), JSON leaves, header values and cookies.
fn request_values(r: &Value, out: &mut Vec<Vec<u8>>) {
    let uri = r["uri"].as_str().unwrap_or("/");
    let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
    out.push(path.as_bytes().to_vec());
    pairs(query, out);
    let mut ct = String::new();
    if let Some(h) = r["headers"].as_object() {
        for (k, v) in h {
            let v = v.as_str().unwrap_or("");
            out.push(v.as_bytes().to_vec());
            if k.eq_ignore_ascii_case("content-type") {
                ct = v.to_ascii_lowercase();
            }
            if k.eq_ignore_ascii_case("cookie") {
                for c in v.split(';') {
                    let (n, val) = c.trim().split_once('=').unwrap_or((c.trim(), ""));
                    out.push(n.as_bytes().to_vec());
                    out.push(val.as_bytes().to_vec());
                }
            }
        }
    }
    let body = r["body"].as_str().unwrap_or("");
    if body.is_empty() {
        return;
    }
    if ct.contains("json") {
        if let Ok(leaves) = libstrata::json::args_with_budget(body.as_bytes(), 1024, None) {
            for (k, v) in leaves {
                out.push(k);
                out.push(v);
            }
        }
    } else if ct.contains("x-www-form-urlencoded") {
        pairs(body, out);
    } else {
        out.push(body.as_bytes().to_vec());
    }
}

fn prepare(args: &[String]) -> Result<()> {
    let dir = dir_of(args)?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut rules = vec![];
    for f in opts(args, "--rules") {
        rules.extend(rules_from_ir(&load(Path::new(f))?).map_err(|e| format!("{f}: {e}"))?);
    }
    let hs = hyperscan_patterns(&rules)?.ok_or("no Hyperscan pattern")?;
    eprintln!("{} rules, {} patterns", rules.len(), hs.pats.len());

    // values: distinct, non-empty, in corpus order
    let mut seen = BTreeSet::new();
    let mut values = vec![];
    for f in opts(args, "--corpus") {
        let text = fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?;
        for line in text.lines() {
            let Ok(r) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let mut vs = vec![];
            request_values(&r, &mut vs);
            for v in vs {
                if !v.is_empty() && v.len() <= 2048 && seen.insert(v.clone()) {
                    values.push(v);
                }
            }
        }
    }
    values.truncate(MAX_VALUES);
    let lens: usize = values.iter().map(Vec::len).sum();
    eprintln!(
        "{} values, {} bytes on average",
        values.len(),
        lens / values.len().max(1)
    );
    let vals: Vec<String> = values
        .iter()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect();
    write_json(&dir.join("values.json"), &json!(vals))?;

    let pats: Vec<Value> = hs
        .pats
        .iter()
        .enumerate()
        .map(|(i, p)| {
            json!({
                "id": i,
                "rule": hs.rule_of[i],
                "cond": hs.conds[i],
                "flags": p.flags,
                "expression": String::from_utf8_lossy(&p.expression),
            })
        })
        .collect();
    write_json(&dir.join("patterns.json"), &json!(pats))?;

    // the full database, then one per pattern; a pattern block mode
    // refuses alone gets an empty image
    let mut images = vec![];
    let full = compile_mode(&hs.pats, HS_MODE_BLOCK).map_err(|(i, m)| format!("{i}: {m}"))?;
    images.push(("full".to_string(), full));
    for (i, p) in hs.pats.iter().enumerate() {
        let one = vec![Pattern {
            expression: p.expression.clone(),
            flags: p.flags,
            id: 0,
        }];
        images.push((
            i.to_string(),
            compile_mode(&one, HS_MODE_BLOCK).unwrap_or_default(),
        ));
        if i % 1000 == 999 {
            eprintln!("  {} compiled", i + 1);
        }
    }
    write_images(&dir, "images", &images)
}

fn write_json(path: &Path, v: &Value) -> Result<()> {
    fs::write(path, serde_json::to_vec(v).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn read_json(path: &Path) -> Result<Value> {
    let b = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&b).map_err(|e| e.to_string())
}

/// `<name>.bin` (the images one after the other) and `<name>.json`
/// ([label, offset, length] per image).
fn write_images(dir: &Path, name: &str, images: &[(String, Vec<u8>)]) -> Result<()> {
    let mut bin = vec![];
    let mut index = vec![];
    for (label, img) in images {
        index.push(json!([label, bin.len(), img.len()]));
        bin.extend_from_slice(img);
    }
    fs::write(dir.join(format!("{name}.bin")), bin).map_err(|e| e.to_string())?;
    write_json(&dir.join(format!("{name}.json")), &json!(index))
}

fn read_images(dir: &Path, name: &str) -> Result<Vec<(String, AlignedBuf)>> {
    let bin = fs::read(dir.join(format!("{name}.bin"))).map_err(|e| e.to_string())?;
    let index = read_json(&dir.join(format!("{name}.json")))?;
    let mut out = vec![];
    for e in index.as_array().into_iter().flatten() {
        let label = e[0].as_str().unwrap_or("").to_string();
        let (off, len) = (
            e[1].as_u64().unwrap_or(0) as usize,
            e[2].as_u64().unwrap_or(0) as usize,
        );
        out.push((label, AlignedBuf::from_bytes(&bin[off..off + len])));
    }
    Ok(out)
}

fn read_values(dir: &Path) -> Result<Vec<Vec<u8>>> {
    Ok(read_json(&dir.join("values.json"))?
        .as_array()
        .into_iter()
        .flatten()
        .map(|v| v.as_str().unwrap_or("").as_bytes().to_vec())
        .collect())
}

/// ns per scan of `db` over `values`: one pass to grow the scratch and
/// warm the caches, then the best of `rounds` timed passes.
fn ns_per_scan(db: &MappedDb<'_>, values: &[Vec<u8>], rounds: usize) -> f64 {
    let pass = || {
        let t = Instant::now();
        for v in values {
            let _ = db.scan(v, &mut |_| true);
        }
        t.elapsed().as_nanos() as f64 / values.len().max(1) as f64
    };
    pass();
    (0..rounds.max(1)).map(|_| pass()).fold(f64::MAX, f64::min)
}

fn rounds_of(args: &[String]) -> usize {
    opt(args, "--rounds")
        .and_then(|r| r.parse().ok())
        .unwrap_or(3)
}

/// Where a rule comes from, by its ID range (rules/README.md).
fn source(rule: u64) -> &'static str {
    match rule {
        100_000..=199_999 => "protocol",
        400_000..=449_999 => "sigma",
        450_000..=499_999 => "et-open",
        500_000..=509_999 => "bots",
        700_000..=799_999 => "virtual-patch",
        900_000..=999_999 => "crs",
        _ => "other",
    }
}

fn time(args: &[String]) -> Result<()> {
    let dir = dir_of(args)?;
    let rounds = rounds_of(args);
    let values = read_values(&dir)?;
    let pats = read_json(&dir.join("patterns.json"))?;
    let pats = pats.as_array().ok_or("patterns.json")?;
    let images = read_images(&dir, "images")?;
    let mut rank = vec![];
    let mut full_ns = 0.0;
    for (n, (label, img)) in images.iter().enumerate() {
        if img.as_ref().is_empty() {
            continue;
        }
        MappedDb::validate(img.as_ref()).map_err(|e| format!("{label}: {e:?}"))?;
        let db = MappedDb::assume_valid_with_id(img.as_ref(), 1_000_000 + n as u64);
        let ns = ns_per_scan(&db, &values, rounds);
        if label == "full" {
            full_ns = ns;
            continue;
        }
        let i: usize = label.parse().unwrap_or(0);
        let p = &pats[i];
        rank.push(json!({
            "id": i,
            "rule": p["rule"],
            "source": source(p["rule"].as_u64().unwrap_or(0)),
            "ns": ns,
            "expression": p["expression"],
        }));
    }
    rank.sort_by(|a, b| b["ns"].as_f64().partial_cmp(&a["ns"].as_f64()).unwrap());
    write_json(&dir.join("rank.json"), &json!(rank))?;

    let total: f64 = rank.iter().filter_map(|r| r["ns"].as_f64()).sum();
    println!(
        "{} values; full database {:.0} ns per scan; {} patterns alone {:.0} ns in sum",
        values.len(),
        full_ns,
        rank.len(),
        total
    );
    let mut by_source: Vec<(String, f64, usize)> = vec![];
    for r in &rank {
        let s = r["source"].as_str().unwrap_or("").to_string();
        let ns = r["ns"].as_f64().unwrap_or(0.0);
        match by_source.iter_mut().find(|e| e.0 == s) {
            Some(e) => {
                e.1 += ns;
                e.2 += 1;
            }
            None => by_source.push((s, ns, 1)),
        }
    }
    by_source.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    println!("\nby source: patterns, ns alone in sum");
    for (s, ns, n) in &by_source {
        println!("  {s:14} {n:6} {ns:12.0}");
    }
    let mut cum = 0.0;
    println!("\nmost expensive alone (ns per scan, cumulative share of the sum):");
    for (k, r) in rank.iter().enumerate().take(40) {
        let ns = r["ns"].as_f64().unwrap_or(0.0);
        cum += ns;
        let e = r["expression"].as_str().unwrap_or("");
        let e: String = e.chars().take(90).collect();
        println!(
            "  {:3} {:7.0} {:5.1}%  rule {} ({})  {e}",
            k + 1,
            ns,
            100.0 * cum / total.max(1.0),
            r["rule"],
            r["source"].as_str().unwrap_or("")
        );
    }
    for k in [10usize, 50, 100, 200, 500, 1000] {
        let s: f64 = rank.iter().take(k).filter_map(|r| r["ns"].as_f64()).sum();
        println!(
            "  top {k:5}: {:5.1}% of the sum",
            100.0 * s / total.max(1.0)
        );
    }
    Ok(())
}

fn minus(args: &[String]) -> Result<()> {
    let dir = dir_of(args)?;
    let ks: Vec<usize> = opt(args, "--k")
        .unwrap_or("")
        .split(',')
        .filter_map(|k| k.trim().parse().ok())
        .collect();
    let pats = read_json(&dir.join("patterns.json"))?;
    let pats = pats.as_array().ok_or("patterns.json")?;
    let rank = read_json(&dir.join("rank.json"))?;
    let order: Vec<usize> = rank
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["id"].as_u64().map(|i| i as usize))
        .collect();
    let all: Vec<Pattern> = pats
        .iter()
        .map(|p| Pattern {
            expression: p["expression"].as_str().unwrap_or("").as_bytes().to_vec(),
            flags: p["flags"].as_u64().unwrap_or(0) as u32,
            id: p["id"].as_u64().unwrap_or(0) as u32,
        })
        .collect();
    let rule_of = |i: usize| pats[i]["rule"].as_u64().unwrap_or(0);
    let mut sets: Vec<(String, BTreeSet<usize>)> = ks
        .iter()
        .map(|&k| (format!("minus{k}"), order.iter().take(k).copied().collect()))
        .collect();
    if let Some(d) = opt(args, "--drop") {
        let rules: BTreeSet<u64> = d.split(',').filter_map(|r| r.trim().parse().ok()).collect();
        let ids = (0..pats.len())
            .filter(|&i| rules.contains(&rule_of(i)))
            .collect();
        sets.push((format!("drop{}", d.replace(',', "+")), ids));
    }
    for src in opt(args, "--sources")
        .into_iter()
        .flat_map(|s| s.split(','))
    {
        let ids = (0..pats.len())
            .filter(|&i| source(rule_of(i)) == src)
            .collect();
        sets.push((format!("no-{src}"), ids));
    }
    if let Some(src) = opt(args, "--each-rule-of") {
        let rules: BTreeSet<u64> = (0..pats.len())
            .map(rule_of)
            .filter(|&r| source(r) == src)
            .collect();
        for r in rules {
            let ids = (0..pats.len()).filter(|&i| rule_of(i) == r).collect();
            sets.push((format!("rule{r}"), ids));
        }
    }
    let mut images = vec![];
    for (label, out) in sets {
        let kept: Vec<Pattern> = all
            .iter()
            .enumerate()
            .filter(|(i, _)| !out.contains(i))
            .map(|(_, p)| Pattern {
                expression: p.expression.clone(),
                flags: p.flags,
                id: p.id,
            })
            .collect();
        let img = compile_mode(&kept, HS_MODE_BLOCK).map_err(|(i, m)| format!("{i}: {m}"))?;
        eprintln!("{label}: {} patterns", kept.len());
        images.push((label, img));
    }
    write_images(&dir, "minus", &images)
}

fn time_minus(args: &[String]) -> Result<()> {
    let dir = dir_of(args)?;
    let rounds = rounds_of(args);
    let values = read_values(&dir)?;
    let full = read_images(&dir, "images")?
        .into_iter()
        .find(|(l, _)| l == "full")
        .ok_or("no full database")?;
    let minus = read_images(&dir, "minus")?;
    let measure = |label: &str, img: &AlignedBuf, id: u64| -> Result<f64> {
        MappedDb::validate(img.as_ref()).map_err(|e| format!("{label}: {e:?}"))?;
        let db = MappedDb::assume_valid_with_id(img.as_ref(), id);
        Ok(ns_per_scan(&db, &values, rounds))
    };
    // each one between two measures of the full database, compared with
    // their mean: the machine drifts (shared caches, other loads) more than
    // the differences measured
    let f0 = measure("full", &full.1, 1)?;
    println!("full database: {f0:.0} ns per scan");
    let mut prev = f0;
    for (n, (label, img)) in minus.iter().enumerate() {
        let ns = measure(label, img, 10 + n as u64)?;
        let next = measure("full", &full.1, 1)?;
        let base = (prev + next) / 2.0;
        println!(
            "{label:10} {ns:8.0} ns per scan, full {base:8.0} ({:+.1}%)",
            100.0 * (ns - base) / base
        );
        prev = next;
    }
    Ok(())
}

fn regex_cost(args: &[String]) -> Result<()> {
    let dir = dir_of(args)?;
    let rounds = rounds_of(args);
    let rule: u64 = opt(args, "--rule")
        .and_then(|r| r.parse().ok())
        .ok_or("--rule is required")?;
    let values = read_values(&dir)?;
    let pats = read_json(&dir.join("patterns.json"))?;
    let mine: Vec<&Value> = pats
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["rule"].as_u64() == Some(rule))
        .collect();
    if mine.is_empty() {
        return Err(format!("rule {rule} has no Hyperscan pattern"));
    }
    for p in mine {
        let expr = p["expression"].as_str().unwrap_or("");
        let flags = p["flags"].as_u64().unwrap_or(0) as u32;
        let src = if flags & strata_hs::compile::CASELESS != 0 {
            format!("(?i){expr}")
        } else {
            expr.to_string()
        };
        let re = libstrata::eval::fallback_regex(src.as_bytes())?;
        let pass = || {
            let t = Instant::now();
            let mut hits = 0usize;
            for v in &values {
                hits += re.is_match(v) as usize;
            }
            (
                t.elapsed().as_nanos() as f64 / values.len().max(1) as f64,
                hits,
            )
        };
        pass();
        let (ns, hits) = (0..rounds.max(1))
            .map(|_| pass())
            .fold((f64::MAX, 0), |a, b| if b.0 < a.0 { b } else { a });
        let one = vec![Pattern {
            expression: expr.as_bytes().to_vec(),
            flags: flags & !strata_hs::compile::SINGLEMATCH,
            id: 0,
        }];
        let img = AlignedBuf::from_bytes(
            &compile_mode(&one, HS_MODE_BLOCK).map_err(|(i, m)| format!("{i}: {m}"))?,
        );
        MappedDb::validate(img.as_ref()).map_err(|e| format!("{e:?}"))?;
        let db = MappedDb::assume_valid_with_id(img.as_ref(), 7);
        let hs_ns = ns_per_scan(&db, &values, rounds);
        println!(
            "rule {rule} pattern {}: regex (lazy DFA) {ns:.0} ns per value, Hyperscan alone {hs_ns:.0} ns per scan, {hits} of {} values match",
            p["id"],
            values.len()
        );
    }
    Ok(())
}
