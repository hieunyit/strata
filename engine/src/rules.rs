//! Rule sections of a bundle: layouts, encoder (compiler) and validated
//! in-place views (engine). All integers little-endian; every table starts
//! with `count u32 | reserved u32`, followed by fixed-size records.
//!
//! ```text
//! RULES       32 B: id u32 | layer u8 | stage u8 | severity u8 | flags u8
//!                   (bit 0: conditions are OR-ed) | score i32 | cond_first u32
//!                   | cond_count u32 | name_off u32 | name_len u32
//!                   | paranoia u8 | reserved [u8; 3]
//! CONDITIONS  48 B: op u8 | negate u8 | n_transforms u8 | value_kind u8
//!                   | transforms [u8; 16] | target_first u32 | target_count u32
//!                   | value_a u32 | value_b u32 | reserved u32 | value_int i64
//!                   value_kind 0 none, 1 string (a = off, b = len in STRINGS),
//!                   2 integer (value_int), 3 list (a = first, b = count in LISTS)
//! TARGETS     24 B: var u8 | flags u8 (bit 0: count, bit 1: key) | reserved u16
//!                   | key_off u32 | key_len u32 | exclude_first u32
//!                   | exclude_count u32 | reserved u32
//! LISTS        8 B: off u32 | len u32 (a string in STRINGS)
//! STRINGS          raw bytes, no header
//! BLOCK_PAGE       html_len u32 | contact_len u32 | html | contact
//! ```
//!
//! Codes follow the order of the enums in docs/spec/ir.schema.json.
#![forbid(unsafe_code)]

use crate::bundle::{Error, Info, kind};

pub const LAYERS: &[&str] = &[
    "pre",
    "protocol",
    "rate",
    "managed",
    "custom-post",
    "response",
];
pub const STAGES: &[&str] = &[
    "request_headers",
    "request_body",
    "response_headers",
    "response_body",
    "log",
];
pub const SEVERITIES: &[&str] = &["critical", "error", "warning", "notice"];
pub const VARS: &[&str] = &[
    "method",
    "uri_raw",
    "uri",
    "path",
    "args",
    "args_names",
    "args_get",
    "args_post",
    "request_headers",
    "request_headers_names",
    "request_cookies",
    "request_cookies_names",
    "request_body",
    "files",
    "files_names",
    "remote_addr",
    "protocol",
    "response_status",
    "response_headers",
    "response_body",
];
pub const TRANSFORMS: &[&str] = &[
    "url_decode_uni",
    "html_entity_decode",
    "js_decode",
    "css_decode",
    "lowercase",
    "remove_nulls",
    "remove_whitespace",
    "compress_whitespace",
    "cmd_line",
    "normalize_path",
    "utf8_to_unicode",
    "base64_decode",
];
pub const OPERATORS: &[&str] = &[
    "rx",
    "pm",
    "contains",
    "begins_with",
    "ends_with",
    "streq",
    "eq",
    "ne",
    "gt",
    "ge",
    "lt",
    "le",
    "detect_sqli",
    "detect_xss",
    "validate_byte_range",
    "validate_url_encoding",
    "validate_utf8_encoding",
    "ip_match",
];

pub const MAX_TRANSFORMS: usize = 16;
const RULE_LEN: usize = 32;
const COND_LEN: usize = 48;
const TARGET_LEN: usize = 24;
const LIST_LEN: usize = 8;

/// Position of `name` in a code table.
pub fn code(table: &[&str], name: &str) -> Option<u8> {
    table.iter().position(|&n| n == name).map(|i| i as u8)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    None,
    Str(Vec<u8>),
    Int(i64),
    List(Vec<Vec<u8>>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetDef {
    pub var: u8,
    pub key: Option<Vec<u8>>,
    pub exclude: Vec<Vec<u8>>,
    pub count: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CondDef {
    pub targets: Vec<TargetDef>,
    pub transforms: Vec<u8>,
    pub op: u8,
    pub negate: bool,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleDef {
    pub id: u32,
    pub name: String,
    pub layer: u8,
    pub stage: u8,
    pub severity: u8,
    pub score: i32,
    pub paranoia: u8,
    pub any: bool,
    pub conditions: Vec<CondDef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPage {
    pub html: Vec<u8>,
    pub support_contact: Vec<u8>,
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn table(count: usize, record: usize) -> Vec<u8> {
    let mut t = Vec::with_capacity(8 + count * record);
    put_u32(&mut t, count as u32);
    put_u32(&mut t, 0);
    t
}

/// Interns nothing: strings are appended once per use, which keeps the
/// encoder trivial; the compiler may deduplicate later.
struct Pool(Vec<u8>);

impl Pool {
    fn add(&mut self, s: &[u8]) -> (u32, u32) {
        let off = self.0.len() as u32;
        self.0.extend_from_slice(s);
        (off, s.len() as u32)
    }
}

/// Encodes rules (and the default block page) into (kind, bytes) sections
/// for `bundle::Spec`.
pub fn encode(rules: &[RuleDef], page: Option<&BlockPage>) -> Vec<(u32, Vec<u8>)> {
    let n_conds: usize = rules.iter().map(|r| r.conditions.len()).sum();
    let n_targets: usize = rules
        .iter()
        .flat_map(|r| &r.conditions)
        .map(|c| c.targets.len())
        .sum();
    let mut rt = table(rules.len(), RULE_LEN);
    let mut ct = table(n_conds, COND_LEN);
    let mut tt = table(n_targets, TARGET_LEN);
    let mut lists: Vec<(u32, u32)> = vec![];
    let mut pool = Pool(vec![]);
    let (mut cond_i, mut target_i) = (0u32, 0u32);

    for r in rules {
        let (name_off, name_len) = pool.add(r.name.as_bytes());
        put_u32(&mut rt, r.id);
        rt.extend_from_slice(&[r.layer, r.stage, r.severity, u8::from(r.any)]);
        rt.extend_from_slice(&r.score.to_le_bytes());
        put_u32(&mut rt, cond_i);
        put_u32(&mut rt, r.conditions.len() as u32);
        put_u32(&mut rt, name_off);
        put_u32(&mut rt, name_len);
        rt.extend_from_slice(&[r.paranoia, 0, 0, 0]);

        for c in &r.conditions {
            let (kind_, a, b, int) = match &c.value {
                Value::None => (0u8, 0, 0, 0i64),
                Value::Str(s) => {
                    let (o, l) = pool.add(s);
                    (1, o, l, 0)
                }
                Value::Int(i) => (2, 0, 0, *i),
                Value::List(items) => {
                    let first = lists.len() as u32;
                    for it in items {
                        lists.push(pool.add(it));
                    }
                    (3, first, items.len() as u32, 0)
                }
            };
            let n_tr = c.transforms.len().min(MAX_TRANSFORMS);
            ct.extend_from_slice(&[c.op, u8::from(c.negate), n_tr as u8, kind_]);
            let mut tr = [0u8; MAX_TRANSFORMS];
            tr[..n_tr].copy_from_slice(&c.transforms[..n_tr]);
            ct.extend_from_slice(&tr);
            put_u32(&mut ct, target_i);
            put_u32(&mut ct, c.targets.len() as u32);
            put_u32(&mut ct, a);
            put_u32(&mut ct, b);
            put_u32(&mut ct, 0);
            ct.extend_from_slice(&int.to_le_bytes());

            for t in &c.targets {
                let (k_off, k_len) = t.key.as_deref().map_or((0, 0), |k| pool.add(k));
                let ex_first = lists.len() as u32;
                for e in &t.exclude {
                    lists.push(pool.add(e));
                }
                let flags = u8::from(t.count) | (u8::from(t.key.is_some()) << 1);
                tt.extend_from_slice(&[t.var, flags, 0, 0]);
                put_u32(&mut tt, k_off);
                put_u32(&mut tt, k_len);
                put_u32(&mut tt, ex_first);
                put_u32(&mut tt, t.exclude.len() as u32);
                put_u32(&mut tt, 0);
            }
            target_i += c.targets.len() as u32;
        }
        cond_i += r.conditions.len() as u32;
    }

    let mut lt = table(lists.len(), LIST_LEN);
    for (o, l) in &lists {
        put_u32(&mut lt, *o);
        put_u32(&mut lt, *l);
    }

    let mut out = vec![
        (kind::RULES, rt),
        (kind::CONDITIONS, ct),
        (kind::TARGETS, tt),
        (kind::LISTS, lt),
        (kind::STRINGS, pool.0),
    ];
    if let Some(p) = page {
        let mut b = vec![];
        put_u32(&mut b, p.html.len() as u32);
        put_u32(&mut b, p.support_contact.len() as u32);
        b.extend_from_slice(&p.html);
        b.extend_from_slice(&p.support_contact);
        out.push((kind::BLOCK_PAGE, b));
    }
    out
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn i32_at(b: &[u8], off: usize) -> i32 {
    u32_at(b, off) as i32
}

/// Record area of a table section, after checking its count fits.
fn records<'a>(
    sec: &'a [u8],
    record: usize,
    what: &'static str,
) -> Result<(&'a [u8], usize), Error> {
    if sec.is_empty() {
        return Ok((&[], 0));
    }
    if sec.len() < 8 || u32_at(sec, 4) != 0 {
        return Err(Error::BadLayout(what));
    }
    let n = u32_at(sec, 0) as usize;
    let need = n.checked_mul(record).and_then(|x| x.checked_add(8));
    match need {
        Some(need) if need <= sec.len() => Ok((&sec[8..need], n)),
        _ => Err(Error::BadLayout(what)),
    }
}

fn in_range(first: u32, count: u32, n: usize) -> bool {
    (first as usize)
        .checked_add(count as usize)
        .is_some_and(|end| end <= n)
}

fn str_ok(off: u32, len: u32, strings: &[u8]) -> bool {
    in_range(off, len, strings.len())
}

/// Validated, in-place view of the rule sections of a mapped bundle.
#[derive(Clone, Copy, Debug)]
pub struct Tables<'a> {
    rules: &'a [u8],
    n_rules: usize,
    strings: &'a [u8],
    page: Option<(&'a [u8], &'a [u8])>,
}

/// One rule, decoded from its record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleView<'a> {
    pub id: u32,
    pub name: &'a [u8],
    pub layer: u8,
    pub stage: u8,
    pub severity: u8,
    pub score: i32,
    pub paranoia: u8,
    pub any: bool,
    pub cond_first: u32,
    pub cond_count: u32,
}

impl<'a> Tables<'a> {
    /// Checks every record of the rule sections: codes in range, every
    /// reference (conditions, targets, lists, strings) inside its table.
    /// Cost is linear in the bundle size; runs once per load.
    pub fn validate(bundle: &'a [u8], info: &Info) -> Result<Tables<'a>, Error> {
        let strings = info.section(bundle, kind::STRINGS);
        let (lists, n_lists) = records(
            info.section(bundle, kind::LISTS),
            LIST_LEN,
            "bad lists section",
        )?;
        let (targets, n_targets) = records(
            info.section(bundle, kind::TARGETS),
            TARGET_LEN,
            "bad targets section",
        )?;
        let (conds, n_conds) = records(
            info.section(bundle, kind::CONDITIONS),
            COND_LEN,
            "bad conditions section",
        )?;
        let (rules, n_rules) = records(
            info.section(bundle, kind::RULES),
            RULE_LEN,
            "bad rules section",
        )?;

        for l in lists.as_chunks::<LIST_LEN>().0 {
            if !str_ok(u32_at(l, 0), u32_at(l, 4), strings) {
                return Err(Error::BadLayout("list entry out of bounds"));
            }
        }
        for t in targets.as_chunks::<TARGET_LEN>().0 {
            if t[0] as usize >= VARS.len()
                || t[1] & !0b11 != 0
                || !str_ok(u32_at(t, 4), u32_at(t, 8), strings)
                || !in_range(u32_at(t, 12), u32_at(t, 16), n_lists)
            {
                return Err(Error::BadLayout("bad target record"));
            }
        }
        for c in conds.as_chunks::<COND_LEN>().0 {
            let n_tr = c[2] as usize;
            let value_ok = match c[3] {
                0 | 2 => true,
                1 => str_ok(u32_at(c, 28), u32_at(c, 32), strings),
                3 => in_range(u32_at(c, 28), u32_at(c, 32), n_lists),
                _ => false,
            };
            if c[0] as usize >= OPERATORS.len()
                || c[1] > 1
                || n_tr > MAX_TRANSFORMS
                || c[4..4 + n_tr]
                    .iter()
                    .any(|&t| t as usize >= TRANSFORMS.len())
                || !in_range(u32_at(c, 20), u32_at(c, 24), n_targets)
                || !value_ok
            {
                return Err(Error::BadLayout("bad condition record"));
            }
        }
        for r in rules.as_chunks::<RULE_LEN>().0 {
            if !(100_000..=999_999).contains(&u32_at(r, 0))
                || r[4] as usize >= LAYERS.len()
                || r[5] as usize >= STAGES.len()
                || r[6] as usize >= SEVERITIES.len()
                || r[7] > 1
                || !in_range(u32_at(r, 12), u32_at(r, 16), n_conds)
                || !str_ok(u32_at(r, 20), u32_at(r, 24), strings)
                || r[28] > 4
            {
                return Err(Error::BadLayout("bad rule record"));
            }
        }

        let page_sec = info.section(bundle, kind::BLOCK_PAGE);
        let page = if page_sec.is_empty() {
            None
        } else {
            let ok = page_sec.len() >= 8;
            let (h, c) = if ok {
                (u32_at(page_sec, 0) as usize, u32_at(page_sec, 4) as usize)
            } else {
                (0, 0)
            };
            if !ok || h.checked_add(c).is_none_or(|n| 8 + n > page_sec.len()) {
                return Err(Error::BadLayout("bad block page section"));
            }
            Some((&page_sec[8..8 + h], &page_sec[8 + h..8 + h + c]))
        };

        Ok(Tables {
            rules,
            n_rules,
            strings,
            page,
        })
    }

    /// View of a bundle that already passed `validate` (only the cheap
    /// table headers are read again).
    pub fn view(bundle: &'a [u8], info: &Info) -> Tables<'a> {
        Tables::validate_tables(bundle, info).unwrap_or(Tables {
            rules: &[],
            n_rules: 0,
            strings: &[],
            page: None,
        })
    }

    fn validate_tables(bundle: &'a [u8], info: &Info) -> Result<Tables<'a>, Error> {
        let strings = info.section(bundle, kind::STRINGS);
        let (rules, n_rules) = records(
            info.section(bundle, kind::RULES),
            RULE_LEN,
            "bad rules section",
        )?;
        let sec = info.section(bundle, kind::BLOCK_PAGE);
        let page = (sec.len() >= 8).then(|| {
            let (h, c) = (u32_at(sec, 0) as usize, u32_at(sec, 4) as usize);
            (&sec[8..8 + h], &sec[8 + h..8 + h + c])
        });
        Ok(Tables {
            rules,
            n_rules,
            strings,
            page,
        })
    }

    pub fn n_rules(&self) -> usize {
        self.n_rules
    }

    pub fn rule(&self, i: usize) -> Option<RuleView<'a>> {
        let r = self.rules.get(i * RULE_LEN..(i + 1) * RULE_LEN)?;
        let (off, len) = (u32_at(r, 20) as usize, u32_at(r, 24) as usize);
        Some(RuleView {
            id: u32_at(r, 0),
            name: &self.strings[off..off + len],
            layer: r[4],
            stage: r[5],
            severity: r[6],
            any: r[7] == 1,
            score: i32_at(r, 8),
            cond_first: u32_at(r, 12),
            cond_count: u32_at(r, 16),
            paranoia: r[28],
        })
    }

    /// (template, support contact) of the default block page, if any.
    pub fn block_page(&self) -> Option<(&'a [u8], &'a [u8])> {
        self.page
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{SIG_LEN, Spec, build, public_key, verify};
    use ed25519_dalek::{Signer, SigningKey};

    const SEED: [u8; 32] = [9; 32];

    fn sample() -> Vec<RuleDef> {
        vec![
            RuleDef {
                id: 942_100,
                name: "SQLi via libinjection".into(),
                layer: code(LAYERS, "managed").unwrap(),
                stage: code(STAGES, "request_body").unwrap(),
                severity: 0,
                score: 5,
                paranoia: 1,
                any: false,
                conditions: vec![CondDef {
                    targets: vec![
                        TargetDef {
                            var: code(VARS, "args").unwrap(),
                            key: None,
                            exclude: vec![],
                            count: false,
                        },
                        TargetDef {
                            var: code(VARS, "request_cookies").unwrap(),
                            key: None,
                            exclude: vec![b"__utm".to_vec()],
                            count: false,
                        },
                    ],
                    transforms: vec![
                        code(TRANSFORMS, "url_decode_uni").unwrap(),
                        code(TRANSFORMS, "remove_nulls").unwrap(),
                    ],
                    op: code(OPERATORS, "detect_sqli").unwrap(),
                    negate: false,
                    value: Value::None,
                }],
            },
            RuleDef {
                id: 800_001,
                name: "scanner user agents".into(),
                layer: code(LAYERS, "managed").unwrap(),
                stage: code(STAGES, "request_headers").unwrap(),
                severity: 2,
                score: 20,
                paranoia: 0,
                any: true,
                conditions: vec![
                    CondDef {
                        targets: vec![TargetDef {
                            var: code(VARS, "request_headers").unwrap(),
                            key: Some(b"User-Agent".to_vec()),
                            exclude: vec![],
                            count: false,
                        }],
                        transforms: vec![code(TRANSFORMS, "lowercase").unwrap()],
                        op: code(OPERATORS, "pm").unwrap(),
                        negate: false,
                        value: Value::List(vec![b"sqlmap".to_vec(), b"nikto".to_vec()]),
                    },
                    CondDef {
                        targets: vec![TargetDef {
                            var: code(VARS, "request_headers").unwrap(),
                            key: Some(b"Content-Length".to_vec()),
                            exclude: vec![],
                            count: false,
                        }],
                        transforms: vec![],
                        op: code(OPERATORS, "gt").unwrap(),
                        negate: true,
                        value: Value::Int(1_000_000),
                    },
                ],
            },
        ]
    }

    fn page() -> BlockPage {
        BlockPage {
            html: b"<p>{{block_id}}</p>".to_vec(),
            support_contact: b"support@example.test".to_vec(),
        }
    }

    fn bundle_of(sections: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let refs: Vec<(u32, &[u8])> = sections.iter().map(|(k, b)| (*k, &b[..])).collect();
        let spec = Spec {
            version: 1,
            created_at_ms: 0,
            flags: 0,
            policies: &[],
            sections: &refs,
        };
        build(&spec, &SEED).unwrap()
    }

    fn resign(mut b: Vec<u8>) -> Vec<u8> {
        b.truncate(b.len() - SIG_LEN);
        let sig = SigningKey::from_bytes(&SEED).sign(&b);
        b.extend_from_slice(&sig.to_bytes());
        b
    }

    fn validate(b: &[u8]) -> Result<usize, Error> {
        let info = verify(b, &public_key(&SEED))?;
        Tables::validate(b, &info).map(|t| t.n_rules())
    }

    #[test]
    fn round_trip() {
        let b = bundle_of(&encode(&sample(), Some(&page())));
        let info = verify(&b, &public_key(&SEED)).unwrap();
        let t = Tables::validate(&b, &info).unwrap();
        assert_eq!(t.n_rules(), 2);
        let r = t.rule(0).unwrap();
        assert_eq!(
            (r.id, r.name, r.score, r.any, r.cond_first, r.cond_count),
            (942_100, &b"SQLi via libinjection"[..], 5, false, 0, 1)
        );
        let r = t.rule(1).unwrap();
        assert_eq!(
            (
                r.id,
                r.severity,
                r.any,
                r.cond_first,
                r.cond_count,
                r.paranoia
            ),
            (800_001, 2, true, 1, 2, 0)
        );
        assert!(t.rule(2).is_none());
        assert_eq!(
            t.block_page(),
            Some((&b"<p>{{block_id}}</p>"[..], &b"support@example.test"[..]))
        );
        // every known section sits on a 4 KB boundary
        for k in 1..=kind::KNOWN {
            assert_eq!(info.sections[k as usize].0 % 4096, 0, "kind {k}");
        }
    }

    #[test]
    fn no_rules_no_page() {
        let b = bundle_of(&encode(&[], None));
        assert_eq!(validate(&b), Ok(0));
        let info = verify(&b, &public_key(&SEED)).unwrap();
        assert_eq!(Tables::validate(&b, &info).unwrap().block_page(), None);
        // and a bundle without any section at all
        assert_eq!(validate(&bundle_of(&[])), Ok(0));
    }

    /// A compiler bug must never become an out-of-bounds read: signed but
    /// inconsistent records are refused.
    #[test]
    fn signed_but_inconsistent_records_are_rejected() {
        let mut sections = encode(&sample(), Some(&page()));
        let cases: Vec<(u32, usize, u8, &str)> = vec![
            (kind::CONDITIONS, 8, 200, "bad condition record"), // operator code
            (kind::CONDITIONS, 8 + 4, 99, "bad condition record"), // transform code
            (kind::CONDITIONS, 8 + 24, 9, "bad condition record"), // target_count
            (kind::RULES, 8 + 4, 9, "bad rule record"),         // layer
            (kind::RULES, 8 + 16, 7, "bad rule record"),        // cond_count
            (kind::TARGETS, 8, 77, "bad target record"),        // var
            (kind::TARGETS, 8 + 16, 50, "bad target record"),   // exclude_count
            (kind::LISTS, 8 + 4, 0xff, "list entry out of bounds"), // string length
            (kind::RULES, 0, 0xff, "bad rules section"),        // record count
            (kind::BLOCK_PAGE, 0, 0xff, "bad block page section"), // html length
        ];
        for (k, off, byte, msg) in cases {
            let saved = sections.clone();
            let sec = &mut sections.iter_mut().find(|(kk, _)| *kk == k).unwrap().1;
            sec[off] = byte;
            assert_eq!(
                validate(&bundle_of(&sections)),
                Err(Error::BadLayout(msg)),
                "kind {k} off {off}"
            );
            sections = saved;
        }
    }

    #[test]
    fn overlapping_sections_are_rejected() {
        let b = bundle_of(&encode(&sample(), None));
        let info = verify(&b, &public_key(&SEED)).unwrap();
        // point CONDITIONS at the RULES section: offsets no longer increase
        let dir = u64::from_le_bytes(b[32..40].try_into().unwrap()) as usize;
        let mut t = b.clone();
        let rules_off = info.sections[kind::RULES as usize].0 as u64;
        t[dir + 8 + 24 + 8..dir + 8 + 24 + 16].copy_from_slice(&rules_off.to_le_bytes());
        assert_eq!(
            validate(&resign(t)),
            Err(Error::BadLayout("bad section bounds"))
        );
    }

    #[test]
    fn codes_follow_the_schema_enums() {
        let schema: &str = include_str!("../../docs/spec/ir.schema.json");
        for name in VARS
            .iter()
            .chain(TRANSFORMS)
            .chain(OPERATORS)
            .chain(LAYERS)
            .chain(STAGES)
            .chain(SEVERITIES)
        {
            assert!(
                schema.contains(&format!("\"{name}\"")),
                "{name} missing from ir.schema.json"
            );
        }
    }
}
