//! strata-compile — rule IR + policies -> signed bundle.
//!
//! ```text
//! strata-compile --policies <file> (--key <seed file> | --unsigned)
//!                --version <n> --out <file>
//!                [--rules <file>]... [--created-at <ms>] [--rollback]
//!                [--cost-report <file>] [--identity-key <file>] [--no-hs-block]
//!                [--good-bots <file>] [--geo <file>]
//! ```
//! Files are JSON or YAML by extension. Without --created-at the current
//! time is used (fixtures pass it to stay reproducible).
//!
//! `--unsigned` writes the bytes to sign instead of a bundle: an external
//! signer (KMS) appends its 64-byte Ed25519 signature over them. No key is
//! read. `--cost-report` writes the cost units of each rule as JSON:
//! `{"total": n, "rules": [{"id", "name", "cost"}...]}`, costliest first.
//! `--identity-key` is the installation's key for policies with
//! `privacy: { identity: hmac }` (32 bytes, or 64 hex digits).
//! The block-mode copy of the Hyperscan database (section HYPERSCAN_BLOCK,
//! #27), which engines scan short values with, is written by default (PO
//! 14/10/2026); `--no-hs-block` leaves it out (smaller bundle, slower
//! scans). `--hs-block` is accepted and changes nothing.

use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use strata_compiler::{
    Build, Options, compile_unsigned_opts, geo_from_json, good_bots_from_json, load, policies_from,
    read_identity_key, rules_from_ir,
};

fn run(args: &[String]) -> Result<(), String> {
    let (mut rules_files, mut policies, mut key, mut version, mut out) =
        (vec![], None, None, None, None);
    let (mut created, mut rollback, mut unsigned, mut cost_report) = (None, false, false, None);
    let mut identity_key: Option<String> = None;
    let mut good_bots: Option<String> = None;
    let mut geo: Option<String> = None;
    // HYPERSCAN_BLOCK by default (PO 14/10/2026)
    let mut opts = Options { hs_block: true };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--rules" => rules_files.push(val()?),
            "--policies" => policies = Some(val()?),
            "--key" => key = Some(val()?),
            "--version" => {
                version = Some(
                    val()?
                        .parse::<u64>()
                        .map_err(|_| "--version: not a number")?,
                )
            }
            "--created-at" => {
                created = Some(
                    val()?
                        .parse::<u64>()
                        .map_err(|_| "--created-at: not a number")?,
                )
            }
            "--out" => out = Some(val()?),
            "--rollback" => rollback = true,
            "--identity-key" => identity_key = Some(val()?),
            "--good-bots" => good_bots = Some(val()?),
            "--geo" => geo = Some(val()?),
            "--hs-block" => opts.hs_block = true,
            "--no-hs-block" => opts.hs_block = false,
            "--unsigned" => unsigned = true,
            "--cost-report" => cost_report = Some(val()?),
            _ => return Err(format!("unexpected argument {a}")),
        }
    }
    let policies = policies.ok_or("--policies is required")?;
    let version = version.ok_or("--version is required")?;
    let out = out.ok_or("--out is required")?;
    let seed: Option<[u8; 32]> = match (key, unsigned) {
        (Some(_), true) => return Err("--key and --unsigned exclude each other".into()),
        (None, false) => return Err("--key or --unsigned is required".into()),
        (None, true) => None,
        (Some(key), false) => Some(
            std::fs::read(&key)
                .map_err(|e| format!("{key}: {e}"))?
                .try_into()
                .map_err(|_| format!("{key}: must hold a 32-byte seed"))?,
        ),
    };
    let mut rules = vec![];
    let mut rule_meta = vec![];
    for f in &rules_files {
        let doc = load(Path::new(f))?;
        rules.extend(rules_from_ir(&doc).map_err(|e| format!("{f}: {e}"))?);
        // what rule sets filter on (RS-2)
        rule_meta.extend(strata_compiler::rule_sets::meta_from_ir(&doc));
    }
    let ppath = Path::new(&policies);
    let mut pol = policies_from(&load(ppath)?, ppath.parent().unwrap_or(Path::new(".")))
        .map_err(|e| format!("{policies}: {e}"))?;
    pol.rule_meta = rule_meta;
    if let Some(f) = &identity_key {
        let b = std::fs::read(f).map_err(|e| format!("{f}: {e}"))?;
        pol.identity_key = Some(read_identity_key(&b).map_err(|e| format!("{f}: {e}"))?);
    }
    // published crawler ranges (W18-R-02): section GOOD_BOTS
    if let Some(f) = &good_bots {
        let b = std::fs::read(f).map_err(|e| format!("{f}: {e}"))?;
        pol.good_bots = good_bots_from_json(&b).map_err(|e| format!("{f}: {e}"))?;
    }
    // networks of countries and ASNs (W19-R-01): section GEO, those the
    // rules name
    if let Some(f) = &geo {
        let b = std::fs::read(f).map_err(|e| format!("{f}: {e}"))?;
        pol.geo = geo_from_json(&b).map_err(|e| format!("{f}: {e}"))?;
    }
    let created_at_ms = created.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    });

    let (mut bundle, mut costs) = compile_unsigned_opts(
        &rules,
        &pol,
        &Build {
            version,
            created_at_ms,
            rollback,
        },
        opts,
    )?;
    if let Some(seed) = &seed {
        bundle = libstrata::bundle::sign(bundle, seed);
    }
    std::fs::write(&out, &bundle).map_err(|e| format!("{out}: {e}"))?;
    let total: u64 = costs.iter().map(|c| c.cost).sum();
    if let Some(f) = &cost_report {
        costs.sort_by(|a, b| b.cost.cmp(&a.cost).then(a.id.cmp(&b.id)));
        let rules: Vec<_> = costs
            .iter()
            .map(|c| serde_json::json!({"id": c.id, "name": c.name, "cost": c.cost}))
            .collect();
        let doc = serde_json::json!({"total": total, "rules": rules});
        std::fs::write(f, doc.to_string()).map_err(|e| format!("{f}: {e}"))?;
    }
    eprintln!(
        "strata-compile: {out}: version {version}, {} rules, {} policies, block page: {}, {} bytes, {total} cost units{}",
        rules.len(),
        pol.policies.len(),
        if pol.block_page.is_some() {
            "yes"
        } else {
            "no"
        },
        bundle.len(),
        if seed.is_none() { ", unsigned" } else { "" }
    );
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("strata-compile: {e}");
            ExitCode::FAILURE
        }
    }
}
