//! mkbundle — development and test tool for Strata bundles.
//!
//! ```text
//! mkbundle keygen  --seed <64 hex> --key-out <file> --pub-out <file>
//! mkbundle build   --key <seed file> --version <n> --out <file>
//!                  [--rollback] [--created-at <ms>] [--policy <name>]...
//!                  [--sections-size <bytes>]
//! mkbundle control --out <file> --generation <n> --version <n> --name <file>
//!                  [--bundle <path>] [--in-place] [--writing]
//! ```
//!
//! `control --in-place` updates an existing control file with the seqlock
//! protocol of docs/design/control-file.md; `--writing` leaves the
//! generation odd, like a writer that died mid-update.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::process::ExitCode;

use sha2::{Digest, Sha256};
use strata::bundle::{self, FLAG_ROLLBACK, Spec};

const CTL_SIZE: usize = 4096;
const CTL_MAGIC: &[u8; 8] = b"STRCTL1\0";
const CTL_LAYOUT: u32 = 1;
const CTL_GEN_OFF: u64 = 16;
const CTL_NAME_MAX: usize = 255;

type Args = HashMap<String, Vec<String>>;

fn parse(args: &[String]) -> Result<Args, String> {
    let mut out: Args = HashMap::new();
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        let key = a
            .strip_prefix("--")
            .ok_or(format!("unexpected argument {a}"))?;
        let flag = matches!(key, "rollback" | "in-place" | "writing");
        let val = if flag {
            String::new()
        } else {
            it.next().ok_or(format!("--{key} needs a value"))?.clone()
        };
        out.entry(key.to_string()).or_default().push(val);
    }
    Ok(out)
}

fn one<'a>(a: &'a Args, k: &str) -> Result<&'a str, String> {
    a.get(k)
        .and_then(|v| v.last())
        .map(String::as_str)
        .ok_or(format!("--{k} is required"))
}

fn num(a: &Args, k: &str, default: Option<u64>) -> Result<u64, String> {
    match (a.get(k).and_then(|v| v.last()), default) {
        (Some(v), _) => v.parse().map_err(|_| format!("--{k}: not a number")),
        (None, Some(d)) => Ok(d),
        (None, None) => Err(format!("--{k} is required")),
    }
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err("seed must be 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| "bad hex")?;
    }
    Ok(out)
}

fn keygen(a: &Args) -> Result<(), String> {
    let seed = hex32(one(a, "seed")?)?;
    fs::write(one(a, "key-out")?, seed).map_err(|e| e.to_string())?;
    fs::write(one(a, "pub-out")?, bundle::public_key(&seed)).map_err(|e| e.to_string())
}

fn build(a: &Args) -> Result<(), String> {
    let seed: [u8; 32] = fs::read(one(a, "key")?)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "key file must hold a 32-byte seed")?;
    let policies: Vec<&str> = a
        .get("policy")
        .map(|v| v.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let sections = vec![0x5a; num(a, "sections-size", Some(64))? as usize];
    let spec = Spec {
        version: num(a, "version", None)?,
        created_at_ms: num(a, "created-at", Some(0))?,
        flags: if a.contains_key("rollback") {
            FLAG_ROLLBACK
        } else {
            0
        },
        policies: &policies,
        sections: &sections,
    };
    let out = bundle::build(&spec, &seed).map_err(|e| e.message().to_string())?;
    fs::write(one(a, "out")?, out).map_err(|e| e.to_string())
}

fn control(a: &Args) -> Result<(), String> {
    let path = one(a, "out")?;
    let name = one(a, "name")?;
    if name.is_empty()
        || name.len() > CTL_NAME_MAX
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return Err("--name must be a plain file name".into());
    }
    let mut generation = num(a, "generation", None)?;
    if generation % 2 == 1 {
        return Err("--generation must be even (odd means 'being written')".into());
    }
    let sha: [u8; 32] = match a.get("bundle").and_then(|v| v.last()) {
        Some(b) => Sha256::digest(fs::read(b).map_err(|e| e.to_string())?).into(),
        None => [0; 32],
    };

    let mut body = vec![0u8; CTL_SIZE];
    body[..8].copy_from_slice(CTL_MAGIC);
    body[8..12].copy_from_slice(&CTL_LAYOUT.to_le_bytes());
    body[24..32].copy_from_slice(&num(a, "version", None)?.to_le_bytes());
    body[32..64].copy_from_slice(&sha);
    body[64..66].copy_from_slice(&(name.len() as u16).to_le_bytes());
    body[66..66 + name.len()].copy_from_slice(name.as_bytes());

    if !a.contains_key("in-place") {
        body[16..24].copy_from_slice(&generation.to_le_bytes());
        return fs::write(path, body).map_err(|e| e.to_string());
    }

    // seqlock writer: odd generation, fields, then the next even generation
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    if f.metadata().map_err(|e| e.to_string())?.len() != CTL_SIZE as u64 {
        return Err("control file must be 4096 bytes".into());
    }
    let writing = generation - 1;
    if a.contains_key("writing") {
        generation = writing;
    }
    let mut put = |off: u64, b: &[u8]| -> Result<(), String> {
        f.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
        f.write_all(b).map_err(|e| e.to_string())
    };
    put(CTL_GEN_OFF, &writing.to_le_bytes())?;
    put(24, &body[24..CTL_SIZE])?;
    put(0, &body[..16])?;
    put(CTL_GEN_OFF, &generation.to_le_bytes())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let result = match argv.split_first() {
        Some((cmd, rest)) => parse(rest).and_then(|a| match cmd.as_str() {
            "keygen" => keygen(&a),
            "build" => build(&a),
            "control" => control(&a),
            _ => Err(format!("unknown command {cmd}")),
        }),
        None => Err("usage: mkbundle keygen|build|control ...".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mkbundle: {e}");
            ExitCode::FAILURE
        }
    }
}
