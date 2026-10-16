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

pub mod resolution;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use libstrata::bundle::{
    self, Mode, Oversize, PolicySpec, Response, Signatures, SnippetSize, Spec,
};
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
    let op_type_str = s(op, "type");
    let op_code = coded(OPERATORS, op_type_str)?;
    let value = match op.get("value") {
        None => RValue::None,
        Some(Value::String(v)) => RValue::Str(v.as_bytes().to_vec()),
        Some(Value::Number(n)) => RValue::Int(n.as_i64().ok_or("integer value out of range")?),
        Some(Value::Array(a)) => RValue::List(a.iter().map(value_bytes).collect()),
        Some(other) => return Err(format!("unsupported operator value {other}")),
    };
    if op_type_str == "validate_byte_range" {
        match &value {
            RValue::Str(s) => {
                let spec = std::str::from_utf8(s)
                    .map_err(|_| "validate_byte_range: value is not valid utf-8")?;
                libstrata::operators::validate_byte_range_syntax(spec)
                    .map_err(|e| format!("validate_byte_range: {e}"))?;
            }
            _ => return Err("validate_byte_range requires a string value".into()),
        }
    } else if op_type_str == "ip_match" {
        match &value {
            RValue::List(items) => {
                let mut strs = Vec::with_capacity(items.len());
                for b in items {
                    strs.push(
                        std::str::from_utf8(b)
                            .map_err(|_| "ip_match: entry is not valid utf-8".to_string())?,
                    );
                }
                libstrata::operators::validate_ip_match_syntax(&strs)
                    .map_err(|e| format!("ip_match: {e}"))?;
            }
            _ => return Err("ip_match requires a list value".into()),
        }
    }
    Ok(CondDef {
        targets,
        transforms,
        op: op_code,
        negate: op["negate"].as_bool().unwrap_or(false),
        multi_match: c["multi_match"].as_bool().unwrap_or(false),
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
            // matched_vars reads the previous condition of an all match
            for (i, c) in conds.iter().enumerate() {
                let reads = c["targets"]
                    .as_array()
                    .is_some_and(|ts| ts.iter().any(|t| t["var"] == "matched_vars"));
                if reads && (any || i == 0) {
                    return Err(format!(
                        "rule {id}: matched_vars only follows a condition of an all match"
                    ));
                }
            }
            Ok(RuleDef {
                id,
                name: s(r, "name").to_string(),
                layer: coded(LAYERS, s(r, "layer"))?,
                stage: coded(STAGES, s(r, "stage"))?,
                severity: coded(SEVERITIES, s(r, "severity"))?,
                score: r["score"].as_i64().unwrap_or(0) as i32,
                paranoia: r["paranoia_level"].as_u64().unwrap_or(0) as u8,
                any,
                // absent means score (see ir.schema.json action_mode)
                block_alone: r["action_mode"].as_str() == Some("block_alone"),
                signature: libstrata::rules::signature_source(s(&r["metadata"], "source")),
                conditions: conds
                    .iter()
                    .map(condition)
                    .collect::<Result<_>>()
                    .map_err(|e| format!("rule {id}: {e}"))?,
            })
        })
        .collect()
}

/// A policy as the compiler reads it: (name, mode, oversize, response
/// flags, canary share in basis points, signature pack, snippet size,
/// max_args (0 = the engine's 1024), fail_on_findings (#98)).
pub type PolicyFields = (
    String,
    Mode,
    Oversize,
    Response,
    u16,
    Signatures,
    SnippetSize,
    usize,
    bool,
);

#[derive(Debug)]
pub struct Policies {
    pub policies: Vec<PolicyFields>,
    pub block_page: Option<BlockPage>,
    /// privacy settings, by index in `policies` (P-01 §1)
    pub privacy: Vec<libstrata::privacy::PrivacySpec>,
    /// the installation's identity key, for policies with `identity: hmac`
    /// (strata-compile --identity-key; the control plane keeps it)
    pub identity_key: Option<[u8; libstrata::privacy::KEY_LEN]>,
}

/// Reads an identity key file: 32 raw bytes, or 64 hex digits (a final
/// newline allowed).
pub fn read_identity_key(bytes: &[u8]) -> Result<[u8; libstrata::privacy::KEY_LEN]> {
    let k: Vec<u8> = if bytes.len() == libstrata::privacy::KEY_LEN {
        bytes.to_vec()
    } else {
        let t = std::str::from_utf8(bytes)
            .map_err(|_| "identity key: 32 bytes or 64 hex digits")?
            .trim();
        if t.len() != 64 {
            return Err("identity key: 32 bytes or 64 hex digits".into());
        }
        (0..32)
            .map(|i| u8::from_str_radix(&t[2 * i..2 * i + 2], 16))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| "identity key: 32 bytes or 64 hex digits")?
    };
    let k: [u8; libstrata::privacy::KEY_LEN] =
        k.try_into().map_err(|_| "identity key: 32 bytes")?;
    if k.iter().all(|&b| b == 0) {
        return Err("identity key: all zeros".into());
    }
    Ok(k)
}

/// Policies document, after schema validation; `base` resolves html_file.
pub fn policies_from(doc: &Value, base: &Path) -> Result<Policies> {
    check(POLICIES_SCHEMA, doc, "policies")?;
    let mut seen = BTreeSet::new();
    let mut policies = vec![];
    let mut privacy = vec![];
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
                Some("pan") => Response::GUARD_PAN,
                _ => Response::GUARD_JWT,
            };
        }
        let canary = match p.get("canary_percent").and_then(Value::as_f64) {
            None => 0,
            Some(_) if mode != Mode::Enforce => {
                return Err(format!(
                    "policy {name:?}: canary_percent needs mode enforce"
                ));
            }
            Some(pct) => {
                let bp = (pct * 100.0).round();
                if (pct * 100.0 - bp).abs() > 1e-6 || !(1.0..=9999.0).contains(&bp) {
                    return Err(format!(
                        "policy {name:?}: canary_percent {pct} is not 0.01..99.99 with two decimals"
                    ));
                }
                bp as u16
            }
        };
        let signatures = match s(p, "signatures") {
            "off" => Signatures::Off,
            "enforce" => Signatures::Enforce,
            _ => Signatures::Shadow,
        };
        let snippet = match p["max_snippet_size"].as_u64() {
            Some(2048) => SnippetSize::Kb2,
            Some(4096) => SnippetSize::Kb4,
            _ => SnippetSize::Small,
        };
        // #28: arguments inspected; more go by `oversize` (rule 100021)
        let max_args = match &p["max_args"] {
            serde_json::Value::Null => 0,
            v => match v.as_u64() {
                Some(n) if (1..=libstrata::bundle::MAX_ARGS_POLICY as u64).contains(&n) => {
                    n as usize
                }
                _ => {
                    return Err(format!(
                        "policy {name:?}: max_args must be 1..{}, got {v}",
                        libstrata::bundle::MAX_ARGS_POLICY
                    ));
                }
            },
        };
        // #98: the budget runs out on a request with findings: fail closed
        let fail_on_findings = match p["fail_on_findings"].as_str() {
            None | Some("pass") => false,
            Some("block") => true,
            Some(v) => {
                return Err(format!(
                    "policy {name:?}: fail_on_findings must be pass or block, got {v:?}"
                ));
            }
        };
        let pv = &p["privacy"];
        let strings = |k: &str| -> Vec<String> {
            pv[k]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        };
        let (fields, patterns) = (strings("sensitive_fields"), strings("mask_patterns"));
        for f in &fields {
            libstrata::privacy::check_field(f).map_err(|e| format!("policy {name:?}: {e}"))?;
        }
        for pat in &patterns {
            libstrata::privacy::compile_pattern(pat)
                .map_err(|e| format!("policy {name:?}: {e}"))?;
        }
        let identity_hmac = pv["identity"].as_str() == Some("hmac");
        if !fields.is_empty() || !patterns.is_empty() || identity_hmac {
            privacy.push(libstrata::privacy::PrivacySpec {
                policy_index: policies.len() as u32,
                sensitive_fields: fields,
                mask_patterns: patterns,
                identity_hmac,
            });
        }
        policies.push((
            name,
            mode,
            oversize,
            Response(response),
            canary,
            signatures,
            snippet,
            max_args,
            fail_on_findings,
        ));
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
        privacy,
        identity_key: None,
    })
}

pub struct Build {
    pub version: u64,
    pub created_at_ms: u64,
    pub rollback: bool,
}

/// Optional parts of a bundle.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Also store the patterns compiled in block mode (section
    /// HYPERSCAN_BLOCK, #27): engines that read it scan short values with
    /// it, older ones skip it. About doubles the Hyperscan part of the
    /// bundle and its compile time.
    pub hs_block: bool,
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
    use strata_hs::compile::{ALLOWEMPTY, SINGLEMATCH};
    let (mut pats, mut conds, mut rule_of) = (vec![], vec![], vec![]);
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
            for (e, flags) in expressions(c) {
                push(e, flags);
            }
            ci += 1;
        }
    }
    (pats, conds, rule_of)
}

/// The Hyperscan database of a bundle: its patterns, the condition and
/// rule of each, and the stream-mode image.
pub struct HsImage {
    pub pats: Vec<strata_hs::Pattern>,
    pub conds: Vec<u32>,
    pub rule_of: Vec<u32>,
    pub image: Vec<u8>,
}

/// Compiles the patterns of `rules` (lowered already) in stream mode. An rx
/// pattern Hyperscan refuses (too large) runs with the regex crate if that
/// takes it: its condition joins `apart` and the rest compiles again;
/// anything else is an error. None when no condition has a pattern.
fn hs_image(rules: &[RuleDef], apart: &mut BTreeSet<u32>) -> Result<Option<HsImage>> {
    let rx = rules::code(OPERATORS, "rx").unwrap_or(u8::MAX);
    let rx_conds: Vec<Option<&[u8]>> = rules
        .iter()
        .flat_map(|r| &r.conditions)
        .map(|c| match &c.value {
            RValue::Str(v) if c.op == rx => Some(&v[..]),
            _ => None,
        })
        .collect();
    loop {
        let (pats, conds, rule_of) = patterns(rules, apart);
        if pats.is_empty() {
            return Ok(None);
        }
        match strata_hs::compile(&pats) {
            Ok(image) => {
                return Ok(Some(HsImage {
                    pats,
                    conds,
                    rule_of,
                    image,
                }));
            }
            Err((i, msg)) => {
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
        }
    }
}

/// The Hyperscan patterns a bundle of `rules` holds, as `compile` builds
/// them (conditions lowered, refused ones apart): for tools that measure
/// them (#28, strata-pattern-cost).
pub fn hyperscan_patterns(rules: &[RuleDef]) -> Result<Option<HsImage>> {
    let (lowered, mut apart) = lower_loose(rules);
    hs_image(&lowered, &mut apart)
}

/// Signs a bundle from rules (in input order) and policies.
pub fn compile(
    rules: &[RuleDef],
    policies: &Policies,
    build: &Build,
    seed: &[u8; 32],
) -> Result<Vec<u8>> {
    let (out, _) = compile_unsigned(rules, policies, build)?;
    Ok(bundle::sign(out, seed))
}

/// As `compile`, without lowering secondary conditions out of the
/// Hyperscan database (`lower_loose`): the bundle compilers made before
/// W09, which the prefilter differential test compares with.
pub fn compile_reference(
    rules: &[RuleDef],
    policies: &Policies,
    build: &Build,
    seed: &[u8; 32],
) -> Result<Vec<u8>> {
    let (out, _) = compile_unsigned_with(rules, policies, build, false, Options::default())?;
    Ok(bundle::sign(out, seed))
}

/// Cost of one rule in cost units (see `rule_cost`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleCost {
    pub id: u32,
    pub name: String,
    pub cost: u64,
}

/// Weight of a target: how many values it usually yields.
fn target_weight(t: &rules::TargetDef) -> u64 {
    let var = rules::VARS.get(t.var as usize).copied().unwrap_or("");
    if t.count || t.key.is_some() {
        return 1;
    }
    match var {
        "request_body" | "response_body" => 8,
        "args"
        | "args_names"
        | "args_get"
        | "args_post"
        | "request_headers"
        | "request_headers_names"
        | "request_cookies"
        | "request_cookies_names"
        | "files"
        | "files_names"
        | "xml"
        | "xml_attributes"
        | "response_headers"
        | "matched_vars" => 4,
        _ => 1,
    }
}

/// Weight of an operator. Patterns of the Hyperscan operators share one
/// scan per value; a regex Hyperscan refused runs alone (`fallback`).
fn op_weight(op: u8, fallback: bool) -> u64 {
    match OPERATORS.get(op as usize).copied().unwrap_or("") {
        "rx" if fallback => 25,
        "detect_sqli" | "detect_xss" => 10,
        "validate_byte_range" | "validate_url_encoding" | "validate_utf8_encoding" | "ip_match" => {
            2
        }
        _ => 1,
    }
}

/// Cost units of a rule: 1, plus for each condition, for each target,
/// target weight × (1 + transformations) × operator weight, doubled with
/// multi_match. `fallback` holds the condition indexes (over all rules, in
/// order) whose regex runs outside Hyperscan.
pub fn rule_costs(rules: &[RuleDef], fallback: &BTreeSet<u32>) -> Vec<RuleCost> {
    let mut ci = 0u32;
    rules
        .iter()
        .map(|r| {
            let mut cost = 1u64;
            for c in &r.conditions {
                let per = (1 + c.transforms.len() as u64)
                    * op_weight(c.op, fallback.contains(&ci))
                    * if c.multi_match { 2 } else { 1 };
                cost += c
                    .targets
                    .iter()
                    .map(|t| target_weight(t) * per)
                    .sum::<u64>();
                ci += 1;
            }
            RuleCost {
                id: r.id,
                name: r.name.clone(),
                cost,
            }
        })
        .collect()
}

/// The expression Hyperscan is given for a pattern condition (one per pm
/// item), and its flags.
fn expressions(c: &CondDef) -> Vec<(Vec<u8>, u32)> {
    use strata_hs::compile::CASELESS;
    let op = |name| rules::code(OPERATORS, name).unwrap_or(u8::MAX);
    match &c.value {
        RValue::Str(v) if c.op == op("rx") => vec![(v.clone(), 0)],
        RValue::Str(v) if c.op == op("contains") => vec![(escape(v), 0)],
        RValue::Str(v) if c.op == op("begins_with") => {
            vec![([b"^".as_slice(), &escape(v)].concat(), 0)]
        }
        RValue::Str(v) if c.op == op("ends_with") => {
            vec![([escape(v).as_slice(), b"$"].concat(), 0)]
        }
        RValue::Str(v) if c.op == op("streq") => {
            vec![([b"^".as_slice(), &escape(v), b"$"].concat(), 0)]
        }
        RValue::List(items) if c.op == op("pm") => {
            items.iter().map(|it| (escape(it), CASELESS)).collect()
        }
        _ => vec![],
    }
}

/// How much a condition narrows the values it matches: the fewest literal
/// bytes a match must contain (as a prefix or a suffix), from the
/// `regex-syntax` literal extractor; 0 when a match needs none (`^\w`).
fn selectivity(c: &CondDef) -> usize {
    use regex_syntax::hir::literal::{ExtractKind, Extractor};
    let exprs = expressions(c);
    if exprs.is_empty() {
        return 0;
    }
    exprs
        .iter()
        .map(|(e, flags)| {
            let Ok(p) = std::str::from_utf8(e) else {
                return 0;
            };
            let Ok(hir) = regex_syntax::ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .case_insensitive(flags & strata_hs::compile::CASELESS != 0)
                .build()
                .parse(&libstrata::eval::byte_escapes(p))
            else {
                return 0;
            };
            [ExtractKind::Prefix, ExtractKind::Suffix]
                .into_iter()
                .map(|k| {
                    Extractor::new()
                        .kind(k)
                        .extract(&hir)
                        .min_literal_len()
                        .unwrap_or(0)
                })
                .max()
                .unwrap_or(0)
        })
        .min()
        .unwrap_or(0)
}

/// Lowers secondary conditions out of the Hyperscan database (W09-R-01). In
/// a rule whose conditions must all hold, the most selective condition is
/// enough to tell when the rule may match (the engine's prefilter); it is
/// moved first and stays in the database. Its companions (often loose:
/// `^\w`, `^[^&]+`, contains "/") would otherwise be reported on many values
/// of every request, from the one database every value is scanned with, and
/// make every scan slower. They become the `rx` Hyperscan was given for them
/// (same expression, same flags) and run with the `regex` crate, compiled on
/// first use, only for requests where the rule's gate held. Returns the
/// rules and the conditions left out. Bundles stay readable by every engine:
/// rx conditions outside the database have always run with the `regex`
/// crate (engines before W09 compile them all when the bundle is mapped).
pub fn lower_loose(rules: &[RuleDef]) -> (Vec<RuleDef>, BTreeSet<u32>) {
    let (lowered, mut apart) = lower_loose_conditions(rules);
    apart.extend(costly_outside_hs(&lowered));
    (lowered, apart)
}

/// Rules whose `rx` conditions run with the `regex` crate rather than in
/// the Hyperscan database (#28, measured with strata-pattern-cost,
/// docs/reports/issue-28-pattern-cost.md). One pattern can make every scan
/// of the shared database slower: 932340 (Unix commands with evasion
/// characters between the letters, no literal Hyperscan can start from)
/// keeps a large NFA running on every value, about a third of the cost of
/// each scan of the full pack, while the regex crate's lazy DFA runs it in
/// about a twentieth of the time on the same values. Its rule is then
/// evaluated on every request (no gate), as rules with only fallback
/// regexes always were.
pub const REGEX_OUTSIDE_HS: &[u32] = &[932_340];

/// The `rx` conditions of the rules in REGEX_OUTSIDE_HS.
fn costly_outside_hs(rules: &[RuleDef]) -> BTreeSet<u32> {
    let rx = rules::code(OPERATORS, "rx").unwrap_or(u8::MAX);
    let mut out = BTreeSet::new();
    let mut ci = 0u32;
    for r in rules {
        for c in &r.conditions {
            if REGEX_OUTSIDE_HS.contains(&r.id) && c.op == rx {
                out.insert(ci);
            }
            ci += 1;
        }
    }
    out
}

fn lower_loose_conditions(rules: &[RuleDef]) -> (Vec<RuleDef>, BTreeSet<u32>) {
    let rx = rules::code(OPERATORS, "rx").unwrap_or(u8::MAX);
    let matched_vars = rules::code(rules::VARS, "matched_vars").unwrap_or(u8::MAX);
    let mut out = rules.to_vec();
    let mut apart = BTreeSet::new();
    let mut first = 0u32;
    for r in &mut out {
        let n = r.conditions.len() as u32;
        let gate = |c: &CondDef| {
            !c.negate
                && !c.targets.is_empty()
                && c.targets.iter().all(|t| !t.count && t.var != matched_vars)
                && !expressions(c).is_empty()
        };
        if !r.any && n > 1 {
            let mut sel: Vec<usize> = r.conditions.iter().map(selectivity).collect();
            let mut best = (0..r.conditions.len())
                .filter(|&i| gate(&r.conditions[i]))
                .max_by_key(|&i| (sel[i], usize::MAX - i));
            // the gate goes first: the engine's prefilter gates a rule on
            // its first gate, and evaluation stops at the first condition
            // that fails. Only when no condition reads matched_vars, where
            // the order is the chain's.
            let chained = r
                .conditions
                .iter()
                .any(|c| c.targets.iter().any(|t| t.var == matched_vars));
            if let Some(b) = best
                && !chained
                && b > 0
            {
                let c = r.conditions.remove(b);
                r.conditions.insert(0, c);
                let s = sel.remove(b);
                sel.insert(0, s);
                best = Some(0);
            }
            if let Some(best) = best {
                for (i, c) in r.conditions.iter_mut().enumerate() {
                    if i == best {
                        continue;
                    }
                    let mut exprs = expressions(c);
                    let expr = match exprs.len() {
                        0 => continue,
                        1 => {
                            let (e, flags) = exprs.remove(0);
                            if flags & strata_hs::compile::CASELESS != 0 {
                                [b"(?i)".as_slice(), &e].concat()
                            } else {
                                e
                            }
                        }
                        _ => {
                            let alts: Vec<Vec<u8>> = exprs.into_iter().map(|(e, _)| e).collect();
                            [b"(?i)(?:".as_slice(), &alts.join(&b'|'), b")"].concat()
                        }
                    };
                    if libstrata::eval::fallback_regex(&expr).is_err()
                        || libstrata::eval::fallback_dfa(&expr).is_err()
                    {
                        continue;
                    }
                    c.op = rx;
                    c.value = RValue::Str(expr);
                    apart.insert(first + i as u32);
                }
            }
        }
        first += n;
    }
    (out, apart)
}

/// The bundle bytes an external signer signs (append its 64-byte Ed25519
/// signature to get the bundle), and the cost of each rule.
pub fn compile_unsigned(
    rules: &[RuleDef],
    policies: &Policies,
    build: &Build,
) -> Result<(Vec<u8>, Vec<RuleCost>)> {
    compile_unsigned_with(rules, policies, build, true, Options::default())
}

/// As `compile_unsigned`, with optional parts.
pub fn compile_unsigned_opts(
    rules: &[RuleDef],
    policies: &Policies,
    build: &Build,
    opts: Options,
) -> Result<(Vec<u8>, Vec<RuleCost>)> {
    compile_unsigned_with(rules, policies, build, true, opts)
}

/// As `compile`, with optional parts.
pub fn compile_opts(
    rules: &[RuleDef],
    policies: &Policies,
    build: &Build,
    seed: &[u8; 32],
    opts: Options,
) -> Result<Vec<u8>> {
    let (out, _) = compile_unsigned_opts(rules, policies, build, opts)?;
    Ok(bundle::sign(out, seed))
}

fn compile_unsigned_with(
    rules: &[RuleDef],
    policies: &Policies,
    build: &Build,
    lower: bool,
    opts: Options,
) -> Result<(Vec<u8>, Vec<RuleCost>)> {
    let mut ids = BTreeSet::new();
    for r in rules {
        if !ids.insert(r.id) {
            return Err(format!("duplicate rule id {}", r.id));
        }
    }
    let (lowered, mut apart) = if lower {
        lower_loose(rules)
    } else {
        (rules.to_vec(), BTreeSet::new())
    };
    let rules = &lowered[..];
    let mut sections = rules::encode(rules, policies.block_page.as_ref());
    if let Some(HsImage {
        pats, conds, image, ..
    }) = hs_image(rules, &mut apart)?
    {
        sections.push((
            libstrata::bundle::kind::HYPERSCAN,
            rules::encode_hyperscan(strata_hs::version(), &conds, &image),
        ));
        if opts.hs_block {
            // the same patterns, ids and index as the stream database, which
            // the engine checks; a pattern only stream mode takes (none
            // known) leaves the section out rather than failing the build
            if let Ok(block) = strata_hs::compile_mode(&pats, strata_hs::HS_MODE_BLOCK) {
                sections.push((
                    libstrata::bundle::kind::HYPERSCAN_BLOCK,
                    rules::encode_hyperscan_mode(
                        rules::HS_MAGIC,
                        strata_hs::version(),
                        &conds,
                        &block,
                    ),
                ));
            }
        }
    }
    let privacy = libstrata::privacy::encode(&policies.privacy, policies.identity_key.as_ref())
        .map_err(|e| format!("{e} (strata-compile --identity-key)"))?;
    if !privacy.is_empty() {
        sections.push((libstrata::bundle::kind::PRIVACY, privacy));
    }
    let refs: Vec<(u32, &[u8])> = sections.iter().map(|(k, b)| (*k, &b[..])).collect();
    let names: Vec<PolicySpec> = policies
        .policies
        .iter()
        .enumerate()
        .map(|(i, (n, m, o, r, c, g, sn, a, f))| PolicySpec {
            response: *r,
            canary: *c,
            signatures: *g,
            snippet: *sn,
            max_args: *a,
            fail_on_findings: *f,
            privacy: policies.privacy.iter().any(|p| p.policy_index == i as u32),
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
    let out = bundle::build_unsigned(&spec).map_err(|e| e.message().to_string())?;
    Ok((out, rule_costs(rules, &apart)))
}
