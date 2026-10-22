//! Section OVERRIDE (RS-1): any bytes parse or are refused, never panic;
//! what parses encodes back to the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libstrata::overrides::{self, Entry};

fuzz_target!(|data: &[u8]| {
    let policies = 4;
    let known = |r: u32| r % 3 != 0;
    if let Ok(parsed) = overrides::parse(data, policies, known) {
        let entries: Vec<Entry> = parsed
            .iter()
            .enumerate()
            .flat_map(|(p, rules)| {
                rules.iter().map(move |&(rule_id, action)| Entry {
                    policy_index: p as u32,
                    rule_id,
                    action,
                })
            })
            .collect();
        assert_eq!(overrides::encode(&entries, policies).unwrap(), data);
    }
});
