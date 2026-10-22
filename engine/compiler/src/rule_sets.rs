//! Rule sets and rule overrides of a policy (RS-2, docs/plan/rule-sets.md):
//! the policy document names, for each policy, rule sets as filters on the
//! rules' metadata with an action, then single rule overrides. The compiler
//! resolves them against the rules of this bundle into section OVERRIDE
//! (libstrata::overrides), keeping only the rules whose action differs from
//! what the rule does on its own.
//!
//! Order of precedence: overrides, then rule sets (a later set wins over an
//! earlier one for a rule in both), then the rule itself. `default` puts a
//! rule back to its own behaviour.

use libstrata::bundle::Signatures;
use libstrata::overrides::{Action, Entry};
use libstrata::rules::RuleDef;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, String>;

/// Most rule sets and overrides one policy has (docs/plan/rule-sets.md §3.2).
pub const MAX_SETS: usize = 32;
pub const MAX_OVERRIDES: usize = 2048;

/// What a rule set filter reads of a rule (its IR metadata).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleMeta {
    pub id: u32,
    pub source: String,
    pub attack_type: String,
    pub tags: BTreeSet<String>,
}

/// The metadata of the rules of a rule IR document (already checked
/// against the IR schema by `rules_from_ir`).
pub fn meta_from_ir(doc: &Value) -> Vec<RuleMeta> {
    doc["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let m = &r["metadata"];
            Some(RuleMeta {
                id: u32::try_from(r["id"].as_u64()?).ok()?,
                source: m["source"].as_str().unwrap_or_default().to_string(),
                attack_type: m["attack_type"].as_str().unwrap_or_default().to_string(),
                tags: m["tags"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|t| t.as_str().map(str::to_string))
                    .collect(),
            })
        })
        .collect()
}

/// An action of a set or an override; `None` is `default`.
fn action(v: &Value, what: &str) -> Result<Option<Action>> {
    match v.as_str() {
        Some("off") => Ok(Some(Action::Off)),
        Some("log") => Ok(Some(Action::Log)),
        Some("block") => Ok(Some(Action::Block)),
        Some("default") => Ok(None),
        _ => Err(format!("{what}: action must be off, log, block or default")),
    }
}

/// A rule set as the policy document gives it: rules whose metadata
/// matches every non-empty list (a tag: any of them), plus `ids`.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub sources: BTreeSet<String>,
    pub attack_types: BTreeSet<String>,
    pub tags: BTreeSet<String>,
    pub ids: BTreeSet<u32>,
}

impl Filter {
    pub fn from_json(m: &Value, what: &str) -> Result<Filter> {
        let strings = |k: &str| -> BTreeSet<String> {
            m[k].as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        };
        let f = Filter {
            sources: strings("sources"),
            attack_types: strings("attack_types"),
            tags: strings("tags"),
            ids: m["ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()))
                .collect(),
        };
        if f.sources.is_empty()
            && f.attack_types.is_empty()
            && f.tags.is_empty()
            && f.ids.is_empty()
        {
            // a set of every rule is the policy's mode, not a set
            return Err(format!(
                "{what}: a rule set needs sources, attack_types, tags or ids"
            ));
        }
        Ok(f)
    }

    pub fn matches(&self, m: &RuleMeta) -> bool {
        if self.ids.contains(&m.id) {
            return true;
        }
        let by_meta =
            !(self.sources.is_empty() && self.attack_types.is_empty() && self.tags.is_empty());
        by_meta
            && (self.sources.is_empty() || self.sources.contains(&m.source))
            && (self.attack_types.is_empty() || self.attack_types.contains(&m.attack_type))
            && (self.tags.is_empty() || m.tags.iter().any(|t| self.tags.contains(t)))
    }
}

/// The rule sets and overrides of one policy.
#[derive(Clone, Debug, Default)]
pub struct PolicyActions {
    pub policy_index: u32,
    /// (name, filter, action) in the policy's order
    pub sets: Vec<(String, Filter, Option<Action>)>,
    pub overrides: Vec<(u32, Option<Action>)>,
}

/// Reads `rule_sets` and `rule_overrides` of a policy of the document;
/// `None` when it has neither.
pub fn from_policy(p: &Value, index: u32, name: &str) -> Result<Option<PolicyActions>> {
    let sets = p["rule_sets"].as_array().map_or(&[][..], |v| &v[..]);
    let overrides = p["rule_overrides"].as_array().map_or(&[][..], |v| &v[..]);
    if sets.is_empty() && overrides.is_empty() {
        return Ok(None);
    }
    if sets.len() > MAX_SETS || overrides.len() > MAX_OVERRIDES {
        return Err(format!(
            "policy {name:?}: at most {MAX_SETS} rule sets and {MAX_OVERRIDES} rule overrides"
        ));
    }
    let mut out = PolicyActions {
        policy_index: index,
        ..Default::default()
    };
    for (i, s) in sets.iter().enumerate() {
        let set = s["name"].as_str().unwrap_or_default().to_string();
        let what = format!(
            "policy {name:?} rule set {}",
            if set.is_empty() {
                format!("#{i}")
            } else {
                set.clone()
            }
        );
        out.sets.push((
            set,
            Filter::from_json(&s["match"], &what)?,
            action(&s["action"], &what)?,
        ));
    }
    let mut seen = BTreeSet::new();
    for o in overrides {
        let rule = o["rule"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| format!("policy {name:?}: rule override without a rule id"))?;
        if !seen.insert(rule) {
            return Err(format!("policy {name:?}: rule {rule} overridden twice"));
        }
        out.overrides.push((
            rule,
            action(&o["action"], &format!("policy {name:?} rule {rule}"))?,
        ));
    }
    Ok(Some(out))
}

/// What a rule does on its own in a policy whose signature pack is `sig`,
/// as an action: so that a set saying the same writes nothing.
fn own(r: &RuleDef, sig: Signatures) -> Option<Action> {
    match (r.signature, sig) {
        (true, Signatures::Off) => Some(Action::Off),
        (true, Signatures::Shadow) => Some(Action::Log),
        _ if r.block_alone => Some(Action::Block),
        _ => None,
    }
}

/// Section OVERRIDE entries of the policies. `rules`: the bundle's rules;
/// `meta`: their IR metadata; `signatures`: each policy's signature pack.
pub fn resolve(
    policies: &[PolicyActions],
    rules: &[RuleDef],
    meta: &[RuleMeta],
    signatures: &[Signatures],
) -> Result<Vec<Entry>> {
    if policies.is_empty() {
        return Ok(vec![]);
    }
    // the rules sets and overrides may name: detection rules of the packs,
    // not CRS exclusion rules nor a policy's own (geo) rules
    let by_id: BTreeMap<u32, &RuleDef> = rules
        .iter()
        .filter(|r| r.exclusion.is_none() && !r.scoped)
        .map(|r| (r.id, r))
        .collect();
    let meta: BTreeMap<u32, &RuleMeta> = meta.iter().map(|m| (m.id, m)).collect();
    let mut out = vec![];
    for p in policies {
        let sig = signatures
            .get(p.policy_index as usize)
            .copied()
            .unwrap_or_default();
        // rule -> action (None: default), sets in order, then overrides
        let mut chosen: BTreeMap<u32, Option<Action>> = BTreeMap::new();
        for (_, filter, act) in &p.sets {
            for (&id, _) in by_id.iter().filter(|(id, _)| {
                meta.get(id).is_some_and(|m| filter.matches(m)) || filter.ids.contains(id)
            }) {
                chosen.insert(id, *act);
            }
            if let Some(id) = filter.ids.iter().find(|id| !by_id.contains_key(id)) {
                return Err(format!(
                    "rule set names rule {id}, which is not in the bundle"
                ));
            }
        }
        for (id, act) in &p.overrides {
            if !by_id.contains_key(id) {
                return Err(format!(
                    "rule override names rule {id}, which is not in the bundle"
                ));
            }
            chosen.insert(*id, *act);
        }
        for (id, act) in chosen {
            let Some(act) = act else { continue };
            if own(by_id[&id], sig) == Some(act) {
                continue;
            }
            out.push(Entry {
                policy_index: p.policy_index,
                rule_id: id,
                action: act,
            });
        }
    }
    if out.len() > libstrata::overrides::MAX_ENTRIES {
        return Err(format!(
            "rule sets and overrides change {} rule actions, at most {}",
            out.len(),
            libstrata::overrides::MAX_ENTRIES
        ));
    }
    Ok(out)
}
