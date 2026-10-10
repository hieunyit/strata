//! Bundle compiler v0 (W04-R-01).
//!
//! Inputs: rule IR documents (docs/spec/ir.schema.json) in JSON or YAML —
//! the same data model, two syntaxes — and a policies document
//! (docs/spec/policies.schema.json). Output: a signed bundle whose rule
//! sections follow `libstrata::rules`. Same inputs, same bytes.
//!
//! v0 encodes what the engine will evaluate (ids, layers, stages, scores,
//! conditions) and compiles every pattern condition (rx, pm, contains,
//! begins_with, ends_with, streq) into one Hyperscan database for a generic
//! x86-64 target, stored as an in-memory image (docs/poc/hyperscan-mmap.md). Rule metadata (source, license, author...) is checked by the
//! schema but not shipped yet: it belongs in events, not in the hot path.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use libstrata::bundle::{self, Mode, Oversize, PolicySpec, Response, Spec};
use libstrata::rules::{
    self, BlockPage, CondDef, LAYERS, OPERATORS, RuleDef, SEVERITIES, STAGES, TRANSFORMS,
    TargetDef, VARS, Value as RValue,
};
use serde_json::{Map, Number, Value};
use yaml_rust2::{Yaml, YamlLoader};

const IR_SCHEMA: &str = include_str!("../../../docs/spec/ir.schema.json");
const POLICIES_SCHEMA: &str = include_str!("../../../docs/spec/policies.schema.json");

pub type Result<T> = std::result::Result<T, String>;

/// Reads a JSON (`.json`) or YAML (`.yaml`, `.yml`) document.
pub fn load(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let yaml = matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml" | "yml")
    );
    if yaml {
        from_yaml(&text)
    } else {
        serde_json::from_str(&text).map_err(|e| e.to_string())
    }
    .map_err(|e| format!("{}: {e}", path.display()))
}

/// YAML text -> JSON value (single document, string keys only).
pub fn from_yaml(text: &str) -> Result<Value> {
    let docs = YamlLoader::load_from_str(text).map_err(|e| e.to_string())?;
    match docs.as_slice() {
        [doc] => yaml_to_json(doc),
        _ => Err("expected exactly one YAML document".into()),
    }
}

fn yaml_to_json(y: &Yaml) -> Result<Value> {
    Ok(match y {
        Yaml::Null => Value::Null,
        Yaml::Boolean(b) => Value::Bool(*b),
        Yaml::Integer(i) => Value::Number((*i).into()),
        Yaml::Real(r) => {
            let f: f64 = r.parse().map_err(|_| format!("bad number {r}"))?;
            Value::Number(Number::from_f64(f).ok_or(format!("bad number {r}"))?)
        }
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Array(a) => Value::Array(a.iter().map(yaml_to_json).collect::<Result<_>>()?),
        Yaml::Hash(h) => {
            let mut m = Map::new();
            for (k, v) in h {
                let Yaml::String(k) = k else {
                    return Err("YAML keys must be strings".into());
                };
                m.insert(k.clone(), yaml_to_json(v)?);
            }
            Value::Object(m)
        }
        Yaml::Alias(_) | Yaml::BadValue => return Err("unsupported YAML value".into()),
    })
}

fn check(schema: &str, doc: &Value, what: &str) -> Result<()> {
    let schema: Value = serde_json::from_str(schema).map_err(|e| e.to_string())?;
    let validator = jsonschema::validator_for(&schema).map_err(|e| e.to_string())?;
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .take(10)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{what} does not follow its schema:\n  {}",
            errors.join("\n  ")
        ))
    }
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn coded(table: &[&str], name: &str) -> Result<u8> {
    rules::code(table, name).ok_or(format!("unknown code {name:?}"))
}

fn value_bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::String(s) => s.as_bytes().to_vec(),
        other => other.to_string().into_bytes(),
    }
}

fn condition(c: &Value) -> Result<CondDef> {
    let targets = c["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|t| {
            Ok(TargetDef {
                var: coded(VARS, s(t, "var"))?,
                key: t
                    .get("key")
                    .and_then(Value::as_str)
                    .map(|k| k.as_bytes().to_vec()),
                exclude: t["exclude"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(value_bytes)
                    .collect(),
                count: t["count"].as_bool().unwrap_or(false),
            })
        })
        .collect::<Result<_>>()?;
    let transforms = c["transforms"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|t| coded(TRANSFORMS, t.as_str().unwrap_or_default()))
        .collect::<Result<_>>()?;
    let op = &c["operator"];
    let value = match op.get("value") {
        None => RValue::None,
        Some(Value::String(v)) => RValue::Str(v.as_bytes().to_vec()),
        Some(Value::Number(n)) => RValue::Int(n.as_i64().ok_or("integer value out of range")?),
        Some(Value::Array(a)) => RValue::List(a.iter().map(value_bytes).collect()),
        Some(other) => return Err(format!("unsupported operator value {other}")),
    };
    Ok(CondDef {
        targets,
        transforms,
        op: coded(OPERATORS, s(op, "type"))?,
        negate: op["negate"].as_bool().unwrap_or(false),
        value,
    })
}

/// Rules of one IR document, after schema validation.
pub fn rules_from_ir(doc: &Value) -> Result<Vec<RuleDef>> {
    check(IR_SCHEMA, doc, "rule IR")?;
    doc["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            let id = r["id"].as_u64().ok_or("rule id")? as u32;
            let (any, conds) = match (&r["match"]["all"], &r["match"]["any"]) {
                (Value::Array(c), _) => (false, c),
                (_, Value::Array(c)) => (true, c),
                _ => return Err(format!("rule {id}: no conditions")),
            };
            Ok(RuleDef {
                id,
                name: s(r, "name").to_string(),
                layer: coded(LAYERS, s(r, "layer"))?,
                stage: coded(STAGES, s(r, "stage"))?,
                severity: coded(SEVERITIES, s(r, "severity"))?,
                score: r["score"].as_i64().unwrap_or(0) as i32,
                paranoia: r["paranoia_level"].as_u64().unwrap_or(0) as u8,
                any,
                conditions: conds
                    .iter()
                    .map(condition)
                    .collect::<Result<_>>()
                    .map_err(|e| format!("rule {id}: {e}"))?,
            })
        })
        .collect()
}

#[derive(Debug)]
pub struct Policies {
    /// (name, mode, oversize, response flags)
    pub policies: Vec<(String, Mode, Oversize, Response)>,
    pub block_page: Option<BlockPage>,
}

/// Policies document, after schema validation; `base` resolves html_file.
pub fn policies_from(doc: &Value, base: &Path) -> Result<Policies> {
    check(POLICIES_SCHEMA, doc, "policies")?;
    let mut seen = BTreeSet::new();
    let mut policies = vec![];
    for p in doc["policies"].as_array().into_iter().flatten() {
        let name = s(p, "name").to_string();
        if !seen.insert(name.clone()) {
            return Err(format!("duplicate policy {name:?}"));
        }
        let mode = if s(p, "mode") == "enforce" {
            Mode::Enforce
        } else {
            Mode::Shadow
        };
        let oversize = if s(p, "oversize") == "block" {
            Oversize::Block
        } else {
            Oversize::Pass
        };
        let r = &p["response"];
        let mut response = 0;
        if r["allowed_codes_check"].as_bool() == Some(true) {
            response |= Response::STATUS;
        }
        if r["db_errors"].as_bool() == Some(true) {
            response |= Response::DB_ERRORS;
        }
        for d in r["data_guard"].as_array().into_iter().flatten() {
            response |= match d.as_str() {
                Some("cccd") => Response::GUARD_CCCD,
                _ => Response::GUARD_JWT,
            };
        }
        policies.push((name, mode, oversize, Response(response)));
    }
    let block_page = match doc.get("block_page") {
        None => None,
        Some(bp) => {
            let html = match (bp.get("html"), bp.get("html_file")) {
                (Some(h), _) => h.as_str().unwrap_or_default().as_bytes().to_vec(),
                (None, Some(f)) => {
                    let path = base.join(f.as_str().unwrap_or_default());
                    fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?
                }
                (None, None) => return Err("block_page needs html or html_file".into()),
            };
            if html.is_empty() || html.len() > 65536 {
                return Err("block page must be 1..65536 bytes".into());
            }
            Some(BlockPage {
                html,
                support_contact: s(bp, "support_contact").as_bytes().to_vec(),
            })
        }
    };
    Ok(Policies {
        policies,
        block_page,
    })
}

pub struct Build {
    pub version: u64,
    pub created_at_ms: u64,
    pub rollback: bool,
}

/// `\xHH` for every byte that is not alphanumeric: a literal as a regex.
fn escape(lit: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(lit.len() * 2);
    for &c in lit {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else {
            out.extend_from_slice(format!("\\x{c:02x}").as_bytes());
        }
    }
    out
}

/// One Hyperscan pattern per pattern-condition (one per item for pm); the
/// pattern id indexes the returned condition table. Conditions in `apart`
/// (rx patterns Hyperscan refuses) are left out: the engine runs them with
/// the `regex` crate.
fn patterns(
    rules: &[RuleDef],
    apart: &BTreeSet<u32>,
) -> (Vec<strata_hs::Pattern>, Vec<u32>, Vec<u32>) {
    use strata_hs::compile::{ALLOWEMPTY, CASELESS, SINGLEMATCH};
    let (mut pats, mut conds, mut rule_of) = (vec![], vec![], vec![]);
    let op = |name| rules::code(OPERATORS, name).unwrap_or(u8::MAX);
    let mut ci = 0u32;
    for r in rules {
        for c in &r.conditions {
            let mut push = |expr: Vec<u8>, flags: u32| {
                if apart.contains(&ci) {
                    return;
                }
                pats.push(strata_hs::Pattern {
                    expression: expr,
                    flags: flags | SINGLEMATCH | ALLOWEMPTY,
                    id: pats.len() as u32,
                });
                conds.push(ci);
                rule_of.push(r.id);
            };
            match &c.value {
                RValue::Str(v) if c.op == op("rx") => push(v.clone(), 0),
                RValue::Str(v) if c.op == op("contains") => push(escape(v), 0),
                RValue::Str(v) if c.op == op("begins_with") => {
                    push([b"^".as_slice(), &escape(v)].concat(), 0)
                }
                RValue::Str(v) if c.op == op("ends_with") => {
                    push([escape(v).as_slice(), b"$"].concat(), 0)
                }
                RValue::Str(v) if c.op == op("streq") => {
                    push([b"^".as_slice(), &escape(v), b"$"].concat(), 0)
                }
                RValue::List(items) if c.op == op("pm") => {
                    for it in items {
                        push(escape(it), CASELESS);
                    }
                }
                _ => {}
            }
            ci += 1;
        }
    }
    (pats, conds, rule_of)
}

/// Signs a bundle from rules (in input order) and policies.
pub fn compile(
    rules: &[RuleDef],
    policies: &Policies,
    build: &Build,
    seed: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut ids = BTreeSet::new();
    for r in rules {
        if !ids.insert(r.id) {
            return Err(format!("duplicate rule id {}", r.id));
        }
    }
    let mut sections = rules::encode(rules, policies.block_page.as_ref());
    let rx = rules::code(OPERATORS, "rx").unwrap_or(u8::MAX);
    let rx_conds: Vec<Option<&[u8]>> = rules
        .iter()
        .flat_map(|r| &r.conditions)
        .map(|c| match &c.value {
            RValue::Str(v) if c.op == rx => Some(&v[..]),
            _ => None,
        })
        .collect();
    let mut apart = BTreeSet::new();
    loop {
        let (pats, conds, rule_of) = patterns(rules, &apart);
        if pats.is_empty() {
            break;
        }
        let image = match strata_hs::compile(&pats) {
            Ok(image) => image,
            Err((i, msg)) => {
                // an rx pattern Hyperscan refuses (too large) runs with the
                // regex crate if that takes it; anything else is an error
                let ci = conds.get(i).copied().unwrap_or(u32::MAX);
                let rx = rx_conds.get(ci as usize).copied().flatten();
                if rx.is_some_and(|p| libstrata::eval::fallback_regex(p).is_ok()) {
                    apart.insert(ci);
                    continue;
                }
                return Err(format!(
                    "rule {}: pattern not supported by Hyperscan: {msg}",
                    rule_of.get(i).copied().unwrap_or(0)
                ));
            }
        };
        sections.push((
            libstrata::bundle::kind::HYPERSCAN,
            rules::encode_hyperscan(strata_hs::version(), &conds, &image),
        ));
        break;
    }
    let refs: Vec<(u32, &[u8])> = sections.iter().map(|(k, b)| (*k, &b[..])).collect();
    let names: Vec<PolicySpec> = policies
        .policies
        .iter()
        .map(|(n, m, o, r)| PolicySpec {
            response: *r,
            ..PolicySpec::new(n, *m, *o)
        })
        .collect();
    let spec = Spec {
        version: build.version,
        created_at_ms: build.created_at_ms,
        flags: if build.rollback {
            bundle::FLAG_ROLLBACK
        } else {
            0
        },
        policies: &names,
        sections: &refs,
    };
    bundle::build(&spec, seed).map_err(|e| e.message().to_string())
}
