//! RS-1 (docs/plan/rule-sets.md): per-policy rule actions from section
//! OVERRIDE, through a real transaction.
use libstrata::{
    bundle::{self, Mode, Oversize, PolicySpec, Signatures, Spec},
    engine::Engine,
    overrides::{self, Action, Entry},
    rules::{self, CondDef, RuleDef, TargetDef, Value, code},
    tx::Tx,
    verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_LOG, OK},
};
use std::sync::Arc;

const SEED: [u8; 32] = [7; 32];
const FIRST: u32 = 700011; // scores 60
const SECOND: u32 = 700012; // scores 60
const ALONE: u32 = 700013; // blocks alone
const BOT: u32 = 500200; // signature pack, scores 0 (a bot list rule)

fn rule(id: u32, header: &[u8], score: i32, block_alone: bool, signature: bool) -> RuleDef {
    RuleDef {
        id,
        name: format!("example {id}"),
        layer: code(rules::LAYERS, "managed").unwrap(),
        stage: code(rules::STAGES, "request_headers").unwrap(),
        severity: 0,
        score,
        paranoia: 1,
        any: false,
        block_alone,
        signature,
        exclusion: None,
        scoped: false,
        conditions: vec![CondDef {
            targets: vec![TargetDef {
                var: code(rules::VARS, "request_headers").unwrap(),
                key: Some([b"X-Example-".as_slice(), header].concat()),
                exclude: vec![],
                count: false,
            }],
            transforms: vec![],
            op: code(rules::OPERATORS, "eq").unwrap(),
            negate: false,
            multi_match: false,
            value: Value::Int(1),
        }],
    }
}

/// Policies: 0 example-api (overrides), 1 example-web (none), 2
/// example-sig-off (signature pack off, the bot rule blocked).
fn sections(entries: &[Entry]) -> Vec<(u32, Vec<u8>)> {
    let rules = [
        rule(FIRST, b"first", 60, false, false),
        rule(SECOND, b"second", 60, false, false),
        rule(ALONE, b"alone", 0, true, false),
        rule(BOT, b"bot", 0, false, true),
    ];
    let mut sections = rules::encode(&rules, None);
    let o = overrides::encode(entries, 3).unwrap();
    if !o.is_empty() {
        sections.push((bundle::kind::OVERRIDE, o));
    }
    sections
}

fn image(entries: &[Entry]) -> Vec<u8> {
    let sections = sections(entries);
    let refs: Vec<_> = sections.iter().map(|(k, b)| (*k, b.as_slice())).collect();
    let policies = [
        PolicySpec::new("example-api", Mode::Enforce, Oversize::Block),
        PolicySpec::new("example-web", Mode::Enforce, Oversize::Block),
        PolicySpec {
            signatures: Signatures::Off,
            ..PolicySpec::new("example-sig-off", Mode::Enforce, Oversize::Block)
        },
    ];
    bundle::build(
        &Spec {
            version: 1,
            created_at_ms: 0,
            flags: 0,
            policies: &policies,
            sections: &refs,
        },
        &SEED,
    )
    .unwrap()
}

fn e(p: u32, r: u32, action: Action) -> Entry {
    Entry {
        policy_index: p,
        rule_id: r,
        action,
    }
}

fn entries() -> Vec<Entry> {
    vec![
        e(0, FIRST, Action::Off),
        e(0, SECOND, Action::Log),
        e(0, ALONE, Action::Log),
        e(0, BOT, Action::Block),
        e(2, BOT, Action::Block),
    ]
}

fn load(bytes: Vec<u8>) -> Result<Arc<Engine>, libstrata::verdict::Rc> {
    Engine::map(Box::new(bytes), &bundle::public_key(&SEED))
        .map(Arc::new)
        .map_err(|(rc, _)| rc)
}

fn headers(flags: &str) -> Vec<(Vec<u8>, &'static [u8])> {
    let mut out = vec![(b"Host".to_vec(), b"api.example.test".as_slice())];
    for f in flags.split(' ').filter(|f| !f.is_empty()) {
        out.push((
            [b"X-Example-".as_slice(), f.as_bytes()].concat(),
            b"1".as_slice(),
        ));
    }
    out
}

fn run(engine: &Arc<Engine>, policy: &str, flags: &str) -> libstrata::verdict::Verdict {
    let mut tx = Tx::new(Some(engine.clone()), b"example-node", 0);
    tx.set_policy(policy.as_bytes());
    assert_eq!(tx.request_line(b"GET", b"/", b"/", b"", b"HTTP/1.1"), OK);
    let h = headers(flags);
    let refs: Vec<(&[u8], &[u8])> = h.iter().map(|(k, v)| (k.as_slice(), *v)).collect();
    assert_eq!(tx.request_headers(&refs), OK);
    tx.verdict()
}

fn matched(v: &libstrata::verdict::Verdict) -> Vec<u32> {
    v.rules[..v.n_rules as usize].to_vec()
}

#[test]
fn rule_actions_per_policy() {
    let engine = load(image(&entries())).unwrap();
    for (policy, flags, action, rules_seen) in [
        // off: the rule does not run at all
        ("example-api", "first", ACTION_ALLOW, vec![]),
        // without overrides: 60 + 60 blocks
        (
            "example-web",
            "first second",
            ACTION_BLOCK,
            vec![FIRST, SECOND],
        ),
        // off + log: nothing counts towards blocking, the log rule is reported
        ("example-api", "first second", ACTION_ALLOW, vec![SECOND]),
        // a rule that blocks alone, set to log: logged, never blocks
        ("example-web", "alone", ACTION_BLOCK, vec![ALONE]),
        ("example-api", "alone", ACTION_LOG, vec![ALONE]),
        // a bot rule scoring 0 in the signature pack (shadow by default):
        // only reported without an override, blocked with block
        ("example-web", "bot", ACTION_ALLOW, vec![BOT]),
        ("example-api", "bot", ACTION_BLOCK, vec![BOT]),
        // block runs a rule of the signature pack even with the pack off
        ("example-sig-off", "bot", ACTION_BLOCK, vec![BOT]),
        // the pack off, no override: the other rules are unaffected
        (
            "example-sig-off",
            "first second",
            ACTION_BLOCK,
            vec![FIRST, SECOND],
        ),
        ("example-api", "", ACTION_ALLOW, vec![]),
    ] {
        let v = run(&engine, policy, flags);
        assert_eq!(v.action, action, "{policy} {flags:?}: action");
        assert_eq!(matched(&v), rules_seen, "{policy} {flags:?}: rules");
    }
}

#[test]
fn a_bundle_without_overrides_is_unchanged() {
    let engine = load(image(&[])).unwrap();
    assert_eq!(engine.info().requires, 0);
    assert_eq!(
        run(&engine, "example-api", "first second").action,
        ACTION_BLOCK
    );
    assert_eq!(run(&engine, "example-api", "bot").action, ACTION_ALLOW);
    assert!(engine.overrides(0).is_empty());
}

/// Re-signs `bytes` after `edit`, so the loader's own checks are tested.
fn patched(bytes: Vec<u8>, edit: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
    let mut b = bytes;
    b.truncate(b.len() - bundle::SIG_LEN);
    edit(&mut b);
    bundle::sign(b, &SEED)
}

#[test]
fn the_header_requirement_and_the_section_go_together() {
    let with = image(&entries());
    let info = bundle::verify(&with, &bundle::public_key(&SEED)).unwrap();
    assert_eq!(
        info.requires,
        bundle::REQUIRES_OVERRIDE,
        "set by the builder"
    );
    // section without the requirement: an engine must not run it as if
    // nothing were overridden
    assert!(load(patched(with.clone(), |b| b[48] = 0)).is_err());
    // requirement without the section
    assert!(load(patched(image(&[]), |b| b[48] = bundle::REQUIRES_OVERRIDE)).is_err());
    // an unknown requirement: refused, as engines before this byte do
    assert!(
        bundle::verify(
            &patched(with.clone(), |b| b[48] |= 1 << 1),
            &bundle::public_key(&SEED)
        )
        .is_err()
    );
    assert!(bundle::verify(&patched(with, |b| b[49] = 1), &bundle::public_key(&SEED)).is_err());
}

#[test]
fn an_override_must_name_a_rule_of_the_bundle() {
    let sections = sections(&[]);
    let mut refs: Vec<_> = sections.iter().map(|(k, b)| (*k, b.as_slice())).collect();
    let bogus = overrides::encode(&[e(0, 942999, Action::Off)], 3).unwrap();
    refs.push((bundle::kind::OVERRIDE, bogus.as_slice()));
    let policies = [
        PolicySpec::new("example-api", Mode::Enforce, Oversize::Block),
        PolicySpec::new("example-web", Mode::Enforce, Oversize::Block),
        PolicySpec::new("example-sig-off", Mode::Enforce, Oversize::Block),
    ];
    let b = bundle::build(
        &Spec {
            version: 1,
            created_at_ms: 0,
            flags: 0,
            policies: &policies,
            sections: &refs,
        },
        &SEED,
    )
    .unwrap();
    assert!(load(b).is_err());
}
