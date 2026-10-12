//! Differential test: dfa_is_match_with_budget (infinite budget) == Regex::is_match
//! on all go-ftw requests for 932230/932235/932250/932260 and on 10,000 random inputs.

use libstrata::eval::{dfa_is_match_with_budget, fallback_dfa, fallback_regex};
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

struct RuleMatcher {
    id: u32,
    dfa: libstrata::regex_automata::hybrid::dfa::DFA,
    re: libstrata::regex::bytes::Regex,
}

fn load_rule_matcher(id: u32, yaml_path: &str) -> RuleMatcher {
    let content = std::fs::read_to_string(yaml_path).expect("read yaml");
    let doc: Value = strata_compiler::from_yaml(&content).expect("parse yaml");
    let rules = doc["rules"].as_array().expect("rules array");
    let rule = rules
        .iter()
        .find(|r| r["id"].as_u64().unwrap_or(0) == id as u64)
        .expect("rule not found in yaml");
    let pattern = rule["match"]["all"][0]["operator"]["value"]
        .as_str()
        .expect("operator value");
    let dfa = fallback_dfa(pattern.as_bytes()).expect("fallback_dfa build");
    let re = fallback_regex(pattern.as_bytes()).expect("fallback_regex build");
    RuleMatcher { id, dfa, re }
}

/// Simple deterministic 64-bit LCG PRNG for reproducibility
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn next_byte(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }
}

#[test]
fn dfa_differential_against_ftw_and_random() {
    let rce_yaml = format!(
        "{}/../../rules/crs/932-rce.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let matchers = vec![
        load_rule_matcher(932230, &rce_yaml),
        load_rule_matcher(932235, &rce_yaml),
        load_rule_matcher(932250, &rce_yaml),
        load_rule_matcher(932260, &rce_yaml),
    ];

    // 1. FTW requests
    let ftw_path = format!(
        "{}/../../corpus/crs-ftw/REQUEST-932-APPLICATION-ATTACK-RCE.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    if Path::new(&ftw_path).exists() {
        let file = File::open(&ftw_path).expect("open ftw jsonl");
        let reader = BufReader::new(file);
        let mut tested_cases = 0;

        for line in reader.lines() {
            let line = line.expect("read line");
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(&line).expect("parse json line");
            let rule_id = v["rule"].as_u64().unwrap_or(0) as u32;

            if let Some(m) = matchers.iter().find(|m| m.id == rule_id) {
                let req = &v["request"];
                let mut candidates = Vec::new();

                if let Some(uri) = req["uri"].as_str() {
                    candidates.push(uri.as_bytes().to_vec());
                    if let Some(pos) = uri.find('?') {
                        candidates.push(uri.as_bytes()[pos + 1..].to_vec());
                        for param in uri[pos + 1..].split('&') {
                            if let Some(eq) = param.find('=') {
                                candidates.push(param.as_bytes()[eq + 1..].to_vec());
                            } else {
                                candidates.push(param.as_bytes().to_vec());
                            }
                        }
                    }
                }
                if let Some(body) = req["body"].as_str() {
                    candidates.push(body.as_bytes().to_vec());
                    for param in body.split('&') {
                        if let Some(eq) = param.find('=') {
                            candidates.push(param.as_bytes()[eq + 1..].to_vec());
                        } else {
                            candidates.push(param.as_bytes().to_vec());
                        }
                    }
                }

                for candidate in candidates {
                    let dfa_res =
                        dfa_is_match_with_budget(1, &m.dfa, &m.re, &candidate, &mut None).unwrap();
                    let re_res = m.re.is_match(&candidate);
                    assert_eq!(
                        dfa_res,
                        re_res,
                        "Mismatch for rule {} on candidate: {:?}",
                        m.id,
                        String::from_utf8_lossy(&candidate)
                    );
                    tested_cases += 1;
                }
            }
        }
        assert!(tested_cases > 0, "must test at least some FTW cases");
        eprintln!("DFA differential passed on {tested_cases} FTW candidate values");
    }

    // 2. 10,000 random inputs with fixed seed
    let mut rng = Rng::new(0xdeadbeef12345678);
    let common_chars = b"abcdefghijklmnopqrstuvwxyz0123456789|;&$()<>/\\'\" -_";

    for _ in 0..10_000 {
        let len = (rng.next_u64() % 120) as usize;
        let mut sample = Vec::with_capacity(len);
        let mode = rng.next_u64() % 3;
        for _ in 0..len {
            match mode {
                0 => sample.push(rng.next_byte()),
                1 => {
                    sample.push(common_chars[(rng.next_u64() % common_chars.len() as u64) as usize])
                }
                _ => {
                    let b = rng.next_byte();
                    sample.push(if b.is_multiple_of(4) {
                        b';'
                    } else if b % 4 == 1 {
                        b'|'
                    } else {
                        b
                    });
                }
            }
        }

        for m in &matchers {
            let dfa_res = dfa_is_match_with_budget(1, &m.dfa, &m.re, &sample, &mut None).unwrap();
            let re_res = m.re.is_match(&sample);
            assert_eq!(
                dfa_res, re_res,
                "Mismatch for rule {} on random input: {:?}",
                m.id, sample
            );
        }
    }
    eprintln!("DFA differential passed on 10,000 random inputs across all 4 rules");
}
