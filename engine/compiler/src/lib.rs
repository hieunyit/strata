//! Bundle compiler v0 (W04-R-01).
//!
//! Inputs: rule IR documents (docs/spec/ir.schema.json) in JSON or YAML —
//! the same data model, two syntaxes — and a policies document
//! (docs/spec/policies.schema.json). Output: a signed bundle whose rule
//! sections follow `libstrata::rules`. Same inputs, same bytes.
//!
//! v0 encodes what the engine will evaluate (ids, layers, stages, scores,
//! conditions). Rule metadata (source, license, author...) is checked by the
//! schema but not shipped yet: it belongs in events, not in the hot path.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use libstrata::bundle::{self, Mode, Spec};
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
    pub policies: Vec<(String, Mode)>,
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
        policies.push((name, mode));
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
    let sections = rules::encode(rules, policies.block_page.as_ref());
    let refs: Vec<(u32, &[u8])> = sections.iter().map(|(k, b)| (*k, &b[..])).collect();
    let names: Vec<(&str, Mode)> = policies
        .policies
        .iter()
        .map(|(n, m)| (n.as_str(), *m))
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
