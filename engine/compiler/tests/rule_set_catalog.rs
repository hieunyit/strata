//! RS-2: the built-in rule sets (rules/sets/catalog.yaml): unique names, a
//! filter the compiler takes, a group, a title in both languages, and every
//! set holds at least one rule of the repository's packs (a misspelt tag
//! or source would make an empty set that silently does nothing).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;
use strata_compiler::from_yaml;
use strata_compiler::rule_sets::{Filter, RuleMeta};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Metadata of every rule of the packs: rule IR documents (`rules:`) and
/// one-rule files (`rule:`).
fn pack_rules() -> Vec<RuleMeta> {
    let mut out = vec![];
    for dir in [
        "crs",
        "protocol",
        "virtual-patches",
        "gaps",
        "bots",
        "sigma",
        "et-open",
        "good-bots",
        "samples",
    ] {
        let mut files: Vec<_> = std::fs::read_dir(repo().join("rules").join(dir))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
            .collect();
        files.sort();
        for f in files {
            let doc = from_yaml(&std::fs::read_to_string(&f).unwrap()).unwrap();
            let rules: Vec<&Value> = match (&doc["rules"], &doc["rule"]) {
                (Value::Array(r), _) => r.iter().collect(),
                (_, r @ Value::Object(_)) => vec![r],
                _ => vec![],
            };
            for r in rules {
                let m = &r["metadata"];
                out.push(RuleMeta {
                    id: r["id"].as_u64().unwrap() as u32,
                    source: m["source"].as_str().unwrap_or_default().into(),
                    attack_type: m["attack_type"].as_str().unwrap_or_default().into(),
                    tags: m["tags"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|t| t.as_str().map(Into::into))
                        .collect(),
                });
            }
        }
    }
    out
}

#[test]
fn every_built_in_set_is_valid_and_holds_rules() {
    let catalog =
        from_yaml(&std::fs::read_to_string(repo().join("rules/sets/catalog.yaml")).unwrap())
            .unwrap();
    assert_eq!(catalog["version"], 1);
    let rules = pack_rules();
    assert!(rules.len() > 1000, "{} rules read", rules.len());
    let mut names = BTreeSet::new();
    let sets = catalog["sets"].as_array().unwrap();
    assert!(sets.len() >= 10);
    for s in sets {
        let name = s["name"].as_str().unwrap();
        assert!(names.insert(name.to_string()), "{name} twice");
        assert!(
            name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "{name}: [a-z0-9-], at most 64"
        );
        assert!(
            ["attack", "signature", "technology", "bot"].contains(&s["group"].as_str().unwrap()),
            "{name}: group"
        );
        if s["group"] == "bot" {
            assert!(
                ["malicious", "automation", "untrusted", "trusted"]
                    .contains(&s["class"].as_str().unwrap_or("")),
                "{name}: class"
            );
        }
        for lang in ["vi", "en"] {
            assert!(
                !s["title"][lang].as_str().unwrap_or("").is_empty(),
                "{name}: title {lang}"
            );
        }
        let f = Filter::from_json(&s["match"], name).unwrap();
        let n = rules.iter().filter(|m| f.matches(m)).count();
        assert!(n > 0, "{name}: no rule of the packs");
    }
    // the bot classes cover every tag of the crawler list
    let bot_tags: BTreeSet<String> = sets
        .iter()
        .filter(|s| s["group"] == "bot")
        .flat_map(|s| {
            s["match"]["tags"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| t.as_str().unwrap().to_string())
        })
        .collect();
    let list_tags: BTreeSet<String> = rules
        .iter()
        .filter(|m| m.source == "crawler-user-agents")
        .flat_map(|m| m.tags.iter().cloned())
        .collect();
    let missing: Vec<_> = list_tags.difference(&bot_tags).collect();
    assert!(
        missing.is_empty(),
        "crawler list tags in no bot set: {missing:?}"
    );
}
