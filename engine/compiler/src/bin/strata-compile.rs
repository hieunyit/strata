//! strata-compile — rule IR + policies -> signed bundle.
//!
//! ```text
//! strata-compile --policies <file> --key <seed file> --version <n> --out <file>
//!                [--rules <file>]... [--created-at <ms>] [--rollback]
//! ```
//! Files are JSON or YAML by extension. Without --created-at the current
//! time is used (fixtures pass it to stay reproducible).

use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use strata_compiler::{Build, compile, load, policies_from, rules_from_ir};

fn run(args: &[String]) -> Result<(), String> {
    let (mut rules_files, mut policies, mut key, mut version, mut out) =
        (vec![], None, None, None, None);
    let (mut created, mut rollback) = (None, false);
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
            _ => return Err(format!("unexpected argument {a}")),
        }
    }
    let policies = policies.ok_or("--policies is required")?;
    let key = key.ok_or("--key is required")?;
    let version = version.ok_or("--version is required")?;
    let out = out.ok_or("--out is required")?;

    let seed: [u8; 32] = std::fs::read(&key)
        .map_err(|e| format!("{key}: {e}"))?
        .try_into()
        .map_err(|_| format!("{key}: must hold a 32-byte seed"))?;
    let mut rules = vec![];
    for f in &rules_files {
        rules.extend(rules_from_ir(&load(Path::new(f))?).map_err(|e| format!("{f}: {e}"))?);
    }
    let ppath = Path::new(&policies);
    let pol = policies_from(&load(ppath)?, ppath.parent().unwrap_or(Path::new(".")))
        .map_err(|e| format!("{policies}: {e}"))?;
    let created_at_ms = created.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    });

    let bundle = compile(
        &rules,
        &pol,
        &Build {
            version,
            created_at_ms,
            rollback,
        },
        &seed,
    )?;
    std::fs::write(&out, &bundle).map_err(|e| format!("{out}: {e}"))?;
    eprintln!(
        "strata-compile: {out}: version {version}, {} rules, {} policies, block page: {}, {} bytes",
        rules.len(),
        pol.policies.len(),
        if pol.block_page.is_some() {
            "yes"
        } else {
            "no"
        },
        bundle.len()
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
