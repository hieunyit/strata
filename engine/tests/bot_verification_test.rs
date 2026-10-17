//! Integration tests for W18-R-02: Good bot verification and search crawler validation.

use std::sync::Arc;

use libstrata::bot::{BotVerifier, KnownBot};
use libstrata::bundle::{self, Mode, Oversize, PolicySpec, Spec};
use libstrata::engine::Engine;
use libstrata::rules::{self, CondDef, RuleDef, TargetDef, Value as RValue};
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, OK};

const SEED: [u8; 32] = [42; 32];

#[test]
fn test_bot_verifier_direct_resolution() {
    let verifier = BotVerifier::default();

    // 1. Authentic Googlebot IPv4
    let res = verifier.verify(
        b"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "66.249.66.1",
    );
    assert_eq!(res.bot, Some(KnownBot::Googlebot));
    assert_eq!(res.verified, Some(true));
    assert_eq!(res.verified_bytes(), b"true");
    assert_eq!(res.bot_name_bytes(), b"googlebot");

    // 2. Spoofed Googlebot IPv4 (from public non-Google IP)
    let res = verifier.verify(
        b"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "198.51.100.22",
    );
    assert_eq!(res.bot, Some(KnownBot::Googlebot));
    assert_eq!(res.verified, Some(false));
    assert_eq!(res.verified_bytes(), b"false");

    // 3. Authentic Googlebot IPv6
    let res = verifier.verify(
        b"Googlebot-Image/1.0",
        "2001:4860:4801:1234::1",
    );
    assert_eq!(res.bot, Some(KnownBot::Googlebot));
    assert_eq!(res.verified, Some(true));

    // 4. Spoofed Googlebot IPv6
    let res = verifier.verify(
        b"Googlebot-Image/1.0",
        "2001:db8::1",
    );
    assert_eq!(res.bot, Some(KnownBot::Googlebot));
    assert_eq!(res.verified, Some(false));

    // 5. Authentic Bingbot IPv4
    let res = verifier.verify(
        b"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "157.55.39.10",
    );
    assert_eq!(res.bot, Some(KnownBot::Bingbot));
    assert_eq!(res.verified, Some(true));
    assert_eq!(res.bot_name_bytes(), b"bingbot");

    // 6. Spoofed Bingbot IPv4
    let res = verifier.verify(
        b"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "203.0.113.88",
    );
    assert_eq!(res.bot, Some(KnownBot::Bingbot));
    assert_eq!(res.verified, Some(false));

    // 7. Authentic Applebot
    let res = verifier.verify(
        b"Mozilla/5.0 (Applebot/0.1; +http://www.apple.com/bot.html)",
        "17.58.100.1",
    );
    assert_eq!(res.bot, Some(KnownBot::Applebot));
    assert_eq!(res.verified, Some(true));

    // 8. Normal user browser (not a crawler)
    let res = verifier.verify(
        b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "198.51.100.5",
    );
    assert_eq!(res.bot, None);
    assert_eq!(res.verified, None);
    assert_eq!(res.verified_bytes(), b"");
    assert_eq!(res.bot_name_bytes(), b"");
}

#[test]
fn test_bot_verification_rule_500001_in_engine() {
    let req_headers_var = rules::code(rules::VARS, "request_headers").expect("request_headers var");
    let rx_op = rules::code(rules::OPERATORS, "rx").expect("rx op");
    let streq_op = rules::code(rules::OPERATORS, "streq").expect("streq op");

    // Rule 500001: Spoofed or unverified search engine crawler
    // matches if User-Agent has googlebot|bingbot|msnbot AND X-Strata-Verified-Bot is "false"
    let rule_500001 = RuleDef {
        id: 500001,
        name: "Spoofed or unverified search engine crawler".into(),
        layer: rules::code(rules::LAYERS, "managed").unwrap(),
        stage: rules::code(rules::STAGES, "request_headers").unwrap(),
        severity: 3, // error
        score: 75,
        paranoia: 1,
        any: false,
        block_alone: true, // block alone in test so verdict becomes ACTION_BLOCK
        signature: false,
        conditions: vec![
            // Condition 1: User-Agent matches crawler regex
            CondDef {
                targets: vec![TargetDef {
                    var: req_headers_var,
                    key: Some(b"User-Agent".to_vec()),
                    exclude: vec![],
                    count: false,
                }],
                transforms: vec![],
                op: rx_op,
                negate: false,
                multi_match: false,
                value: RValue::Str(b"(?i)\\b(?:googlebot|bingbot|msnbot)\\b".to_vec()),
            },
            // Condition 2: X-Strata-Verified-Bot streq "false"
            CondDef {
                targets: vec![TargetDef {
                    var: req_headers_var,
                    key: Some(b"X-Strata-Verified-Bot".to_vec()),
                    exclude: vec![],
                    count: false,
                }],
                transforms: vec![],
                op: streq_op,
                negate: false,
                multi_match: false,
                value: RValue::Str(b"false".to_vec()),
            },
        ],
    };

    let rules_list = vec![rule_500001];
    let rule_sections = rules::encode(&rules_list, None);
    let refs: Vec<(u32, &[u8])> = rule_sections.iter().map(|(k, b)| (*k, &b[..])).collect();

    let spec = Spec {
        version: 1802,
        created_at_ms: 1000,
        flags: 0,
        policies: &[PolicySpec::new("bot-policy", Mode::Enforce, Oversize::Pass)],
        sections: &refs,
    };

    let bundle_bytes = bundle::build(&spec, &SEED).unwrap();
    let engine = Arc::new(Engine::map(Box::new(bundle_bytes), &bundle::public_key(&SEED)).unwrap());

    // 1. Authentic Googlebot from official IP 66.249.66.1 -> MUST PASS!
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-bot", 0);
        tx.set_policy(b"bot-policy");
        tx.set_client_addr(b"66.249.66.1");
        assert_eq!(tx.request_line(b"GET", b"/products", b"/products", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[
                (b"Host", b"api.example.test"),
                (b"User-Agent", b"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
            ]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_ALLOW, "Authentic Googlebot must be allowed");
        assert!(!v.rules[..v.n_rules as usize].contains(&500001));
    }

    // 2. Spoofed Googlebot from rogue IP 198.51.100.22 -> MUST BE BLOCKED!
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-bot", 0);
        tx.set_policy(b"bot-policy");
        tx.set_client_addr(b"198.51.100.22");
        assert_eq!(tx.request_line(b"GET", b"/products", b"/products", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[
                (b"Host", b"api.example.test"),
                (b"User-Agent", b"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
            ]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_BLOCK, "Spoofed Googlebot must be blocked");
        assert!(v.rules[..v.n_rules as usize].contains(&500001));
    }

    // 3. Spoofed Googlebot attempting to forge header `X-Strata-Verified-Bot: true` -> MUST STILL BE BLOCKED!
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-bot", 0);
        tx.set_policy(b"bot-policy");
        tx.set_client_addr(b"198.51.100.22");
        assert_eq!(tx.request_line(b"GET", b"/products", b"/products", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[
                (b"Host", b"api.example.test"),
                (b"User-Agent", b"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
                (b"X-Strata-Verified-Bot", b"true"), // Malicious header injection attempt
            ]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_BLOCK, "Spoofed Googlebot with forged header must be blocked");
        assert!(v.rules[..v.n_rules as usize].contains(&500001));
    }

    // 4. Authentic Bingbot from official IP 40.77.167.10 -> MUST PASS!
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-bot", 0);
        tx.set_policy(b"bot-policy");
        tx.set_client_addr(b"40.77.167.10");
        assert_eq!(tx.request_line(b"GET", b"/products", b"/products", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[
                (b"Host", b"api.example.test"),
                (b"User-Agent", b"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
            ]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_ALLOW, "Authentic Bingbot must be allowed");
        assert!(!v.rules[..v.n_rules as usize].contains(&500001));
    }

    // 5. Spoofed Bingbot from rogue IP 203.0.113.88 -> MUST BE BLOCKED!
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-bot", 0);
        tx.set_policy(b"bot-policy");
        tx.set_client_addr(b"203.0.113.88");
        assert_eq!(tx.request_line(b"GET", b"/products", b"/products", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[
                (b"Host", b"api.example.test"),
                (b"User-Agent", b"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
            ]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_BLOCK, "Spoofed Bingbot must be blocked");
        assert!(v.rules[..v.n_rules as usize].contains(&500001));
    }

    // 6. Regular browser request -> MUST PASS!
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-bot", 0);
        tx.set_policy(b"bot-policy");
        tx.set_client_addr(b"198.51.100.5");
        assert_eq!(tx.request_line(b"GET", b"/products", b"/products", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[
                (b"Host", b"api.example.test"),
                (b"User-Agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
            ]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_ALLOW, "Normal user must be allowed");
        assert!(!v.rules[..v.n_rules as usize].contains(&500001));
    }
}

#[test]
fn test_bot_target_variables_matching() {
    let bot_verified_var = rules::code(rules::VARS, "bot_verified").expect("bot_verified var");
    let bot_name_var = rules::code(rules::VARS, "bot_name").expect("bot_name var");
    let streq_op = rules::code(rules::OPERATORS, "streq").expect("streq op");

    // Rule 810001: matches if bot_name == "googlebot" AND bot_verified == "false"
    let rule_fake_google = RuleDef {
        id: 810001,
        name: "DetectFakeGooglebot".into(),
        layer: rules::code(rules::LAYERS, "managed").unwrap(),
        stage: rules::code(rules::STAGES, "request_headers").unwrap(),
        severity: 3,
        score: 10,
        paranoia: 1,
        any: false,
        block_alone: true,
        signature: false,
        conditions: vec![
            CondDef {
                targets: vec![TargetDef {
                    var: bot_name_var,
                    key: None,
                    exclude: vec![],
                    count: false,
                }],
                transforms: vec![],
                op: streq_op,
                negate: false,
                multi_match: false,
                value: RValue::Str(b"googlebot".to_vec()),
            },
            CondDef {
                targets: vec![TargetDef {
                    var: bot_verified_var,
                    key: None,
                    exclude: vec![],
                    count: false,
                }],
                transforms: vec![],
                op: streq_op,
                negate: false,
                multi_match: false,
                value: RValue::Str(b"false".to_vec()),
            },
        ],
    };

    let rules_list = vec![rule_fake_google];
    let rule_sections = rules::encode(&rules_list, None);
    let refs: Vec<(u32, &[u8])> = rule_sections.iter().map(|(k, b)| (*k, &b[..])).collect();

    let spec = Spec {
        version: 1803,
        created_at_ms: 1000,
        flags: 0,
        policies: &[PolicySpec::new("var-policy", Mode::Enforce, Oversize::Pass)],
        sections: &refs,
    };

    let bundle_bytes = bundle::build(&spec, &SEED).unwrap();
    let engine = Arc::new(Engine::map(Box::new(bundle_bytes), &bundle::public_key(&SEED)).unwrap());

    // Fake Googlebot matches rule 810001
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-bot", 0);
        tx.set_policy(b"var-policy");
        tx.set_client_addr(b"1.2.3.4");
        assert_eq!(tx.request_line(b"GET", b"/test", b"/test", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[
                (b"User-Agent", b"Googlebot/2.1"),
            ]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_BLOCK);
        assert!(v.rules[..v.n_rules as usize].contains(&810001));
    }

    // Real Googlebot does not match rule 810001
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-bot", 0);
        tx.set_policy(b"var-policy");
        tx.set_client_addr(b"66.249.64.10");
        assert_eq!(tx.request_line(b"GET", b"/test", b"/test", b"", b"HTTP/1.1"), OK);
        assert_eq!(
            tx.request_headers(&[
                (b"User-Agent", b"Googlebot/2.1"),
            ]),
            OK
        );
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_ALLOW);
    }
}
