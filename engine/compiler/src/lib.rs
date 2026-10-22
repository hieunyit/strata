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

/// IR target `user_input`: every place of a request the client fills in
/// that injection rules read, as the targets the compiler expands it to
/// (var, key). Adding a place here covers every rule that names
/// `user_input`, without touching the rules (22/10/2026).
pub const USER_INPUT: &[(&str, Option<&str>)] = &[
    ("args", None),
    ("args_names", None),
    ("request_cookies", None),
    ("request_cookies_names", None),
    ("path", None),
    ("xml", None),
    ("xml_attributes", None),
    ("files", None),
    ("files_names", None),
    ("request_headers", Some("User-Agent")),
    ("request_headers", Some("Referer")),
];

fn condition(c: &Value) -> Result<CondDef> {
    let mut targets = vec![];
    for t in c["targets"].as_array().into_iter().flatten() {
        let exclude: Vec<Vec<u8>> = t["exclude"]
            .as_array()
            .into_iter()
            .flatten()
            .map(value_bytes)
            .collect();
        let count = t["count"].as_bool().unwrap_or(false);
        if s(t, "var") == "user_input" {
            if t.get("key").is_some() || count {
                return Err("user_input takes no key and no count".into());
            }
            for &(var, key) in USER_INPUT {
                targets.push(TargetDef {
                    var: coded(VARS, var)?,
                    key: key.map(|k| k.as_bytes().to_vec()),
                    // a name excluded is excluded where names apply
                    exclude: if key.is_some() {
                        vec![]
                    } else {
                        exclude.clone()
                    },
                    count: false,
                });
            }
            continue;
        }
        targets.push(TargetDef {
            var: coded(VARS, s(t, "var"))?,
            key: t
                .get("key")
                .and_then(Value::as_str)
                .map(|k| k.as_bytes().to_vec()),
            exclude,
            count,
        });
    }
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

/// The removals of an exclusion rule (W17-S-01, IR `exclude`); None for a
/// detection rule. A key of request_headers or request_headers_names is
/// compared ignoring ASCII case, others exactly.
fn exclusion(r: &Value) -> Result<Option<libstrata::rule_exclusions::RuleExclusion>> {
    use libstrata::rule_exclusions::{KeyMode, Removal, RuleExclusion, WHOLE_RULE};
    let Some(list) = r["exclude"].as_array() else {
        return Ok(None);
    };
    let mut removals = vec![];
    for e in list {
        let (var, key_mode, key) = match e.get("target") {
            None => (WHOLE_RULE, KeyMode::Any, vec![]),
            Some(t) => {
                let var = coded(VARS, s(t, "var"))?;
                match t["key"].as_str() {
                    None => (var, KeyMode::Any, vec![]),
                    Some(k)
                        if matches!(s(t, "var"), "request_headers" | "request_headers_names") =>
                    {
                        (var, KeyMode::Caseless, k.as_bytes().to_vec())
                    }
                    Some(k) => (var, KeyMode::Exact, k.as_bytes().to_vec()),
                }
            }
        };
        let ids = e["rules"].as_array().into_iter().flatten().map(|v| {
            let id = v.as_u64().unwrap_or(0) as u32;
            (id, id)
        });
        let ranges = e["rule_ranges"].as_array().into_iter().flatten().map(|v| {
            (
                v[0].as_u64().unwrap_or(0) as u32,
                v[1].as_u64().unwrap_or(0) as u32,
            )
        });
        for (lo, hi) in ids.chain(ranges) {
            if lo > hi {
                return Err(format!("exclude: range {lo}-{hi}"));
            }
            removals.push(Removal {
                lo,
                hi,
                var,
                key_mode,
                key: key.clone(),
            });
        }
    }
    removals.sort();
    removals.dedup();
    Ok(Some(RuleExclusion {
        plugin: s(&r["metadata"], "plugin").to_string(),
        removals,
    }))
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
                exclusion: exclusion(r).map_err(|e| format!("rule {id}: {e}"))?,
                scoped: false,
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
/// max_args (0 = the engine's 1024), fail_on_findings (#98),
/// parse_error: pass (audit 22/10/2026)).
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
    bool,
);

#[derive(Debug)]
pub struct Policies {
    pub policies: Vec<PolicyFields>,
    pub block_page: Option<BlockPage>,
    /// privacy settings, by index in `policies` (P-01 §1)
    pub privacy: Vec<libstrata::privacy::PrivacySpec>,
    pub exceptions: Vec<libstrata::exceptions::Exception>,
    pub staging: Vec<libstrata::staging::Entry>,
    /// CRS paranoia levels other than (1, 1) (W17-S-01: `crs_paranoia`,
    /// `crs_paranoia_shadow`)
    pub paranoia: Vec<libstrata::paranoia::Entry>,
    /// CRS plugins each policy runs (W17-S-01, `crs_plugins`): (policy
    /// index, plugin name)
    pub plugins: Vec<(u32, String)>,
    /// the installation's identity key, for policies with `identity: hmac`
    /// (strata-compile --identity-key; the control plane keeps it)
    pub identity_key: Option<[u8; libstrata::privacy::KEY_LEN]>,
    /// published crawler ranges for section GOOD_BOTS (W18-R-02;
    /// strata-compile --good-bots, the control plane's latest list)
    pub good_bots: Vec<libstrata::goodbots::Crawler>,
    /// networks per country and ASN (W19-R-01; strata-compile --geo, from
    /// the control plane's GeoIP databases); only those rules name go into
    /// section GEO
    pub geo: Vec<libstrata::geo::Entry>,
    /// rules of the policies themselves (W19-G2-01, `geo_rules`), each
    /// scoped to its policy (section SCOPE)
    pub scoped_rules: Vec<RuleDef>,
    pub scope: Vec<libstrata::scope::Entry>,
}

/// IDs of the rules policies define (W19-G2-01, `geo_rules`).
pub const POLICY_RULE_IDS: std::ops::RangeInclusive<u32> = 190_000..=199_999;
/// Most geo rules one policy has.
pub const MAX_GEO_RULES: usize = 16;

/// The rule a policy's geo rule (W19-G2-01) compiles to: countries and
/// ASNs of the client address (W19-R-01); with `not`, the addresses
/// outside them, local addresses excepted. Block: blocks on its own.
fn geo_rule(policy: &str, g: &Value) -> Result<(RuleDef, libstrata::scope::Mode)> {
    let id = g["id"].as_u64().unwrap_or(0);
    if !POLICY_RULE_IDS.contains(&(id as u32)) || id > u32::MAX as u64 {
        return Err(format!(
            "policy {policy:?}: geo rule id {id} is not {}..{}",
            POLICY_RULE_IDS.start(),
            POLICY_RULE_IDS.end()
        ));
    }
    let id = id as u32;
    let list = |k: &str| -> Result<Vec<Vec<u8>>> {
        let mut out: Vec<Vec<u8>> = vec![];
        for v in g[k].as_array().into_iter().flatten() {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => return Err(format!("policy {policy:?}: geo rule {id}: {k}: {v}")),
            };
            let kind = if k == "countries" {
                libstrata::geo::Kind::Country
            } else {
                libstrata::geo::Kind::Asn
            };
            if !libstrata::geo::valid_key(kind, &s) || out.iter().any(|o| o == s.as_bytes()) {
                return Err(format!(
                    "policy {policy:?}: geo rule {id}: {k}: {s:?} is invalid or repeated"
                ));
            }
            out.push(s.into_bytes());
        }
        Ok(out)
    };
    let (countries, asns) = (list("countries")?, list("asns")?);
    if countries.is_empty() && asns.is_empty() {
        return Err(format!(
            "policy {policy:?}: geo rule {id}: no country and no ASN"
        ));
    }
    let not = g["not"].as_bool().unwrap_or(false);
    let mode = match g["action"].as_str() {
        Some("block") => libstrata::scope::Mode::Enforce,
        Some("log") => libstrata::scope::Mode::Log,
        a => {
            return Err(format!(
                "policy {policy:?}: geo rule {id}: action {a:?} is not block or log"
            ));
        }
    };
    let cond = |var: &str, mut values: Vec<Vec<u8>>| -> Result<CondDef> {
        if not {
            values.push(b"private".to_vec());
        }
        Ok(CondDef {
            targets: vec![rules::TargetDef {
                var: coded(rules::VARS, var)?,
                key: None,
                exclude: vec![],
                count: false,
            }],
            transforms: vec![],
            op: coded(rules::OPERATORS, "pm")?,
            negate: not,
            multi_match: false,
            value: rules::Value::List(values),
        })
    };
    let mut conditions = vec![];
    if !countries.is_empty() {
        conditions.push(cond("geo_country", countries)?);
    }
    if !asns.is_empty() {
        conditions.push(cond("geo_asn", asns)?);
    }
    Ok((
        RuleDef {
            id,
            name: format!("geo rule {id} of policy {policy}"),
            layer: coded(LAYERS, "pre")?,
            stage: coded(STAGES, "request_headers")?,
            severity: coded(SEVERITIES, "critical")?,
            score: 100,
            paranoia: 0,
            // in: one list is enough; not: outside every list
            any: !not,
            block_alone: true,
            signature: false,
            exclusion: None,
            scoped: true,
            conditions,
        },
        mode,
    ))
}

/// Reads the networks the control plane extracts from its GeoIP databases
/// (W19-R-01): `{"version": "...", "countries": {"VN": ["14.160.0.0/11",
/// ...]}, "asns": {"7552": [...]}}`.
pub fn geo_from_json(bytes: &[u8]) -> Result<Vec<libstrata::geo::Entry>> {
    use libstrata::geo::{Kind, entry};
    let doc: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| format!("geo: {e}"))?;
    let mut out = vec![];
    for (field, kind) in [("countries", Kind::Country), ("asns", Kind::Asn)] {
        let Some(map) = doc.get(field) else { continue };
        let map = map
            .as_object()
            .ok_or_else(|| format!("geo: {field:?} is not an object"))?;
        for (key, prefixes) in map {
            let list: Vec<&str> = prefixes
                .as_array()
                .ok_or_else(|| format!("geo: {key}: not a list"))?
                .iter()
                .map(|p| {
                    p.as_str()
                        .ok_or_else(|| format!("geo: {key}: not a string"))
                })
                .collect::<Result<_>>()?;
            out.push(entry(kind, key, &list).map_err(|e| format!("geo: {e}"))?);
        }
    }
    Ok(out)
}

/// The countries and ASNs the rules name, from their conditions on
/// geo_country / geo_asn (streq or pm only, so the names are known;
/// `other` and `private` name none).
fn geo_keys(rules: &[RuleDef]) -> Result<BTreeSet<(libstrata::geo::Kind, String)>> {
    use libstrata::geo::Kind;
    let var = |n| rules::code(rules::VARS, n).unwrap_or(u8::MAX);
    let op = |n| rules::code(rules::OPERATORS, n).unwrap_or(u8::MAX);
    let mut out = BTreeSet::new();
    for r in rules {
        for c in &r.conditions {
            for t in &c.targets {
                let kind = if t.var == var("geo_country") {
                    Kind::Country
                } else if t.var == var("geo_asn") {
                    Kind::Asn
                } else {
                    continue;
                };
                let values: Vec<&[u8]> = match &c.value {
                    rules::Value::Str(v) if c.op == op("streq") => vec![v],
                    rules::Value::List(l) if c.op == op("pm") => l.iter().map(|v| &v[..]).collect(),
                    _ => {
                        return Err(format!(
                            "rule {}: geo_country and geo_asn take streq or pm only",
                            r.id
                        ));
                    }
                };
                if t.count || t.key.is_some() || !c.transforms.is_empty() || c.multi_match {
                    return Err(format!(
                        "rule {}: geo_country and geo_asn take no key, count or transformation",
                        r.id
                    ));
                }
                for v in values {
                    let v =
                        std::str::from_utf8(v).map_err(|_| format!("rule {}: geo value", r.id))?;
                    if v == "other" || v == "private" {
                        continue;
                    }
                    if !libstrata::geo::valid_key(kind, v) {
                        return Err(format!("rule {}: {v:?} is not a {kind:?} (VN, 7552)", r.id));
                    }
                    out.insert((kind, v.to_string()));
                }
            }
        }
    }
    Ok(out)
}

/// Reads the crawler ranges the control plane stores (W18-G2-02):
/// `{"version": "...", "crawlers": {"googlebot": ["66.249.64.0/27", ...]}}`.
pub fn good_bots_from_json(bytes: &[u8]) -> Result<Vec<libstrata::goodbots::Crawler>> {
    let doc: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("good bots: {e}"))?;
    let crawlers = doc["crawlers"]
        .as_object()
        .ok_or("good bots: no \"crawlers\" object")?;
    let mut out = vec![];
    for (name, prefixes) in crawlers {
        let list: Vec<&str> = prefixes
            .as_array()
            .ok_or_else(|| format!("good bots: {name}: not a list"))?
            .iter()
            .map(|p| {
                p.as_str()
                    .ok_or_else(|| format!("good bots: {name}: not a string"))
            })
            .collect::<Result<_>>()?;
        out.push(libstrata::goodbots::crawler(name, &list).map_err(|e| format!("good bots: {e}"))?);
    }
    libstrata::goodbots::encode(&out).map_err(|e| format!("good bots: {e}"))?;
    Ok(out)
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
    let mut paranoia = vec![];
    let mut plugins = vec![];
    let mut scoped_rules = vec![];
    let mut scope = vec![];
    let mut exceptions = vec![];
    let mut staging = vec![];
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
        // audit 22/10/2026: a body the engine cannot read (100022/100023)
        // blocks alone in enforce; pass only records it
        let parse_error_pass = match p["parse_error"].as_str() {
            None | Some("block") => false,
            Some("pass") => true,
            Some(v) => {
                return Err(format!(
                    "policy {name:?}: parse_error must be pass or block, got {v:?}"
                ));
            }
        };
        // W17-S-01: CRS paranoia level enforced, and the level run in
        // shadow above it (default: the enforced level)
        let level = |k: &str, default: u8| -> Result<u8> {
            match &p[k] {
                serde_json::Value::Null => Ok(default),
                v => match v.as_u64() {
                    Some(n) if (1..=libstrata::paranoia::MAX_LEVEL as u64).contains(&n) => {
                        Ok(n as u8)
                    }
                    _ => Err(format!("policy {name:?}: {k} must be 1..4, got {v}")),
                },
            }
        };
        let enforce = level("crs_paranoia", 1)?;
        let levels = libstrata::paranoia::Levels {
            enforce,
            shadow: level("crs_paranoia_shadow", enforce)?,
        };
        if levels.shadow < levels.enforce {
            return Err(format!(
                "policy {name:?}: crs_paranoia_shadow ({}) is below crs_paranoia ({})",
                levels.shadow, levels.enforce
            ));
        }
        if levels != libstrata::paranoia::Levels::default() {
            paranoia.push(libstrata::paranoia::Entry {
                policy_index: policies.len() as u32,
                levels,
            });
        }
        // W19-G2-01: the policy's own geo rules, scoped to it
        let geo_rules = p["geo_rules"].as_array().map_or(&[][..], |v| &v[..]);
        if geo_rules.len() > MAX_GEO_RULES {
            return Err(format!(
                "policy {name:?}: more than {MAX_GEO_RULES} geo rules"
            ));
        }
        for g in geo_rules {
            let (rule, mode) = geo_rule(&name, g)?;
            scope.push(libstrata::scope::Entry {
                policy_index: policies.len() as u32,
                rule_id: rule.id,
                mode,
            });
            scoped_rules.push(rule);
        }
        // W17-S-01: the CRS plugins (rule exclusions) the policy runs
        let mut seen = BTreeSet::new();
        for v in p["crs_plugins"].as_array().into_iter().flatten() {
            let plugin = v.as_str().unwrap_or_default();
            if plugin.is_empty()
                || plugin.len() > 32
                || !plugin
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || !seen.insert(plugin)
            {
                return Err(format!(
                    "policy {name:?}: invalid or duplicate crs_plugins entry {v}"
                ));
            }
            plugins.push((policies.len() as u32, plugin.to_string()));
        }
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
        let mut exception_ids = BTreeSet::new();
        for e in p["exceptions"].as_array().into_iter().flatten() {
            if !exception_ids.insert(s(e, "id"))
                || s(e, "reason").trim().is_empty()
                || s(e, "reason").len() > 500
            {
                return Err(format!(
                    "policy {name:?}: invalid or duplicate exception metadata"
                ));
            }
            exceptions.push(libstrata::exceptions::Exception {
                policy_index: policies.len() as u32,
                rule_id: e["rule_id"].as_u64().ok_or("exception rule_id")? as u32,
                expires_unix_ms: e["expires_unix_ms"].as_u64().ok_or("exception expiry")?,
                method: s(e, "method").into(),
                host: s(e, "host").into(),
                path: s(e, "path").into(),
                field: s(e, "field").into(),
            });
        }
        for id in p["staged_rules"].as_array().into_iter().flatten() {
            staging.push(libstrata::staging::Entry {
                policy_index: policies.len() as u32,
                rule_id: u32::try_from(id.as_u64().ok_or("staging rule_id")?)
                    .map_err(|_| "staging rule_id")?,
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
            parse_error_pass,
        ));
    }
    libstrata::exceptions::encode(&exceptions, policies.len() as u32)
        .map_err(|e| format!("policy exceptions: {}", e.message()))?;
    libstrata::staging::encode(&staging, policies.len() as u32)
        .map_err(|e| format!("policy staging: {}", e.message()))?;
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
        exceptions,
        staging,
        paranoia,
        plugins,
        scoped_rules,
        scope,
        identity_key: None,
        good_bots: vec![],
        geo: vec![],
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
        "detect_sqli" | "detect_xss" | "detect_ssti" | "detect_cmdi" => 10,
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
    // W19-G2-01: the policies' own rules join the rule set
    let with_scoped: Vec<RuleDef>;
    let rules = if policies.scoped_rules.is_empty() {
        rules
    } else {
        with_scoped = rules
            .iter()
            .chain(&policies.scoped_rules)
            .cloned()
            .collect();
        &with_scoped[..]
    };
    if rules
        .iter()
        .any(|r| r.scoped && !POLICY_RULE_IDS.contains(&r.id))
    {
        return Err("a scoped rule outside the policy rule ids".into());
    }
    let mut ids = BTreeSet::new();
    for r in rules {
        if !ids.insert(r.id) {
            return Err(format!("duplicate rule id {}", r.id));
        }
    }
    // W17-S-01: rules above every policy's paranoia levels never run: they
    // are left out, so a bundle without a paranoid policy keeps its size
    // and cost (PL2 adds about half to the CRS Hyperscan databases)
    let highest = policies
        .paranoia
        .iter()
        .map(|e| e.levels.shadow)
        .max()
        .unwrap_or(1);
    // W17-S-01: exclusion rules of a plugin no policy runs are left out
    // too; a plugin a policy names must exist
    let wanted: BTreeSet<&str> = policies.plugins.iter().map(|(_, p)| p.as_str()).collect();
    let present: BTreeSet<&str> = rules
        .iter()
        .filter_map(|r| r.exclusion.as_ref().map(|x| x.plugin.as_str()))
        .collect();
    if let Some(missing) = wanted.difference(&present).next() {
        return Err(format!("crs_plugins: no rules of plugin {missing:?}"));
    }
    let keep = |r: &RuleDef| {
        r.paranoia <= highest
            && r.exclusion
                .as_ref()
                .is_none_or(|x| wanted.contains(x.plugin.as_str()))
    };
    let kept: Vec<RuleDef>;
    let rules = if rules.iter().any(|r| !keep(r)) {
        kept = rules.iter().filter(|r| keep(r)).cloned().collect();
        &kept[..]
    } else {
        rules
    };
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
    let exception_bytes =
        libstrata::exceptions::encode(&policies.exceptions, policies.policies.len() as u32)
            .map_err(|e| format!("policy exceptions: {}", e.message()))?;
    if !exception_bytes.is_empty() {
        let managed_ids: BTreeSet<_> = rules
            .iter()
            .filter(|r| Some(r.layer) == rules::code(rules::LAYERS, "managed"))
            .map(|r| r.id)
            .collect();
        for e in &policies.exceptions {
            if !managed_ids.contains(&e.rule_id) {
                return Err(format!(
                    "exception must name an existing managed rule: {}",
                    e.rule_id
                ));
            }
        }
        sections.push((libstrata::bundle::kind::EXCEPTIONS, exception_bytes));
    }
    let paranoia = libstrata::paranoia::encode(&policies.paranoia, policies.policies.len() as u32)
        .map_err(|e| format!("policy paranoia: {}", e.message()))?;
    if !paranoia.is_empty() {
        sections.push((libstrata::bundle::kind::PARANOIA, paranoia));
    }
    let defs: Vec<libstrata::rule_exclusions::Def> = rules
        .iter()
        .filter_map(|r| {
            let x = r.exclusion.as_ref()?;
            Some(libstrata::rule_exclusions::Def {
                rule_id: r.id,
                removals: x.removals.clone(),
                policies: policies
                    .plugins
                    .iter()
                    .filter(|(_, p)| *p == x.plugin)
                    .map(|(i, _)| *i)
                    .collect(),
            })
        })
        .collect();
    let exclusions = libstrata::rule_exclusions::encode(
        &defs,
        policies.policies.len() as u32,
        rules::VARS.len(),
    )
    .map_err(|e| format!("rule exclusions: {}", e.message()))?;
    if !exclusions.is_empty() {
        sections.push((libstrata::bundle::kind::EXCLUSIONS, exclusions));
    }
    // W19-R-01: the networks of the countries and ASNs the rules name
    let wanted = geo_keys(rules)?;
    let mut geo = vec![];
    for (kind, key) in &wanted {
        let e = policies
            .geo
            .iter()
            .find(|e| e.kind == *kind && &e.key == key)
            .ok_or_else(|| format!("{kind:?} {key}: no networks (strata-compile --geo)"))?;
        geo.push(e.clone());
    }
    let geo = libstrata::geo::encode(&geo).map_err(|e| format!("geo: {e}"))?;
    if !geo.is_empty() {
        sections.push((libstrata::bundle::kind::GEO, geo));
    }
    let scope = libstrata::scope::encode(&policies.scope, policies.policies.len() as u32)
        .map_err(|e| format!("rule scope: {}", e.message()))?;
    if !scope.is_empty() {
        sections.push((libstrata::bundle::kind::SCOPE, scope));
    }
    let good_bots = libstrata::goodbots::encode(&policies.good_bots)?;
    if !good_bots.is_empty() {
        sections.push((libstrata::bundle::kind::GOOD_BOTS, good_bots));
    }
    let stage_bytes = libstrata::staging::encode(&policies.staging, policies.policies.len() as u32)
        .map_err(|e| format!("policy staging: {}", e.message()))?;
    if !stage_bytes.is_empty() {
        let managed = rules::code(rules::LAYERS, "managed");
        let headers = rules::code(rules::STAGES, "request_headers");
        let body = rules::code(rules::STAGES, "request_body");
        // Rule IDs have already passed the compiler's uniqueness check.
        let eligible: BTreeSet<_> = rules
            .iter()
            .filter(|r| {
                Some(r.layer) == managed
                    && (Some(r.stage) == headers || Some(r.stage) == body)
                    && (0..=1000).contains(&r.score)
            })
            .map(|r| r.id)
            .collect();
        for e in &policies.staging {
            if !eligible.contains(&e.rule_id) {
                return Err(format!(
                    "staging requires one managed request rule with score 0..1000: {}",
                    e.rule_id
                ));
            }
        }
        sections.push((libstrata::bundle::kind::STAGING, stage_bytes));
    }
    let refs: Vec<(u32, &[u8])> = sections.iter().map(|(k, b)| (*k, &b[..])).collect();
    let names: Vec<PolicySpec> = policies
        .policies
        .iter()
        .enumerate()
        .map(|(i, (n, m, o, r, c, g, sn, a, f, pe))| PolicySpec {
            response: *r,
            canary: *c,
            signatures: *g,
            snippet: *sn,
            max_args: *a,
            fail_on_findings: *f,
            parse_error_pass: *pe,
            privacy: policies.privacy.iter().any(|p| p.policy_index == i as u32),
            staging: policies.staging.iter().any(|p| p.policy_index == i as u32),
            paranoia: policies.paranoia.iter().any(|p| p.policy_index == i as u32),
            exceptions: policies
                .exceptions
                .iter()
                .any(|p| p.policy_index == i as u32),
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
