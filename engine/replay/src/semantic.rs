//! False positives of the semantic detectors (W20-R-01): runs labelled
//! requests through a bundle, as [`crate::evaluate`] does, and counts the
//! matches of the rules whose operator is a semantic detector
//! (`detect_sqli`, `detect_xss`, `detect_cmdi`, `detect_ssti`, `detect_nosql`) per
//! detector and label: per SQLi fingerprint, per field, alone or with other
//! rules. A benign label (`benign...`) counts false positives, an attack
//! label (`sql-injection`, `xss`, ...) the detection rate, `replay` (traffic
//! samples, not labelled) candidates to review.
//!
//! The values come from [`Tx::keep_match_values`]: not masked. Samples are
//! anonymized before they are stored (docs/spec/replay-sample.md), corpora
//! hold no personal data; the report keeps at most [`EXAMPLES`] values per
//! detector, of the benign and replay labels only.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use libstrata::detectors::injection::detect_sqli;
use libstrata::engine::Engine;
use libstrata::rules::OPERATORS;
use libstrata::tx::Tx;
use serde::Serialize;

use crate::{Acc, Result, Sample, parallel};

/// Values kept per detector in the report.
pub const EXAMPLES: usize = 20;
/// Longest value of an example, in bytes.
const EXAMPLE_LEN: usize = 160;
/// Label of traffic samples.
pub const REPLAY: &str = "replay";

const DETECTORS: [&str; 5] = [
    "detect_sqli",
    "detect_xss",
    "detect_cmdi",
    "detect_ssti",
    "detect_nosql",
];

/// Rule id -> detector name (`sqli`, ...) of every rule of the bundle with a
/// semantic operator in one of its conditions.
pub fn semantic_rules(engine: &Engine) -> BTreeMap<u32, &'static str> {
    let t = engine.tables();
    let mut out = BTreeMap::new();
    for i in 0..t.n_rules() {
        let Some(r) = t.rule(i) else { continue };
        for c in r.cond_first..r.cond_first.saturating_add(r.cond_count) {
            let Some(op) = t.cond(c).and_then(|c| OPERATORS.get(c.op as usize)) else {
                continue;
            };
            if DETECTORS.contains(op) {
                out.insert(r.id, &op["detect_".len()..]);
                break;
            }
        }
    }
    out
}

/// A label is benign when it starts with `benign`.
pub fn is_benign(label: &str) -> bool {
    label.starts_with("benign")
}

/// Counts of one label for one detector.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct LabelCounts {
    /// samples one of the detector's rules matched (enforced or reported)
    pub samples: u64,
    /// of those, samples the detector's rules matched only as report-only
    /// (a paranoia level in shadow)
    pub report_only: u64,
    /// of those, samples no other rule matched: the detector alone
    pub alone: u64,
    /// rule id -> samples
    pub rules: BTreeMap<u32, u64>,
    /// field (`ARGS:name`, a JSON key path...) -> samples
    pub fields: BTreeMap<String, u64>,
    /// SQLi fingerprint (libinjection token types) -> samples
    pub fingerprints: BTreeMap<String, u64>,
}

/// One match kept as an example.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct SemanticExample {
    pub label: String,
    pub rule: u32,
    pub field: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// the value the rule matched, transformed, cut to 160 bytes
    pub value: String,
    pub method: String,
    pub path: String,
}

/// One detector.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DetectorReport {
    pub rules: Vec<u32>,
    /// label -> counts
    pub labels: BTreeMap<String, LabelCounts>,
    /// matches on benign and replay samples
    pub examples: Vec<SemanticExample>,
}

/// A run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SemanticReport {
    pub elapsed_ms: u64,
    /// label -> samples
    pub samples: BTreeMap<String, u64>,
    /// detector -> report
    pub detectors: BTreeMap<String, DetectorReport>,
}

impl Acc for SemanticReport {
    fn merge(&mut self, o: Self) {
        for (k, v) in o.samples {
            *self.samples.entry(k).or_default() += v;
        }
        for (name, d) in o.detectors {
            let mine = self.detectors.entry(name).or_default();
            if mine.rules.is_empty() {
                mine.rules = d.rules;
            }
            for (label, c) in d.labels {
                let m = mine.labels.entry(label).or_default();
                m.samples += c.samples;
                m.report_only += c.report_only;
                m.alone += c.alone;
                for (dst, src) in [
                    (&mut m.fields, c.fields),
                    (&mut m.fingerprints, c.fingerprints),
                ] {
                    for (k, n) in src {
                        *dst.entry(k).or_default() += n;
                    }
                }
                for (k, n) in c.rules {
                    *m.rules.entry(k).or_default() += n;
                }
            }
            for e in d.examples {
                if mine.examples.len() < EXAMPLES {
                    mine.examples.push(e);
                }
            }
        }
    }
}

/// At most `n` bytes of `v`, as text.
fn cut(v: &[u8], n: usize) -> String {
    String::from_utf8_lossy(&v[..v.len().min(n)]).into_owned()
}

impl SemanticReport {
    fn new(rules: &BTreeMap<u32, &'static str>) -> Self {
        let mut r = SemanticReport::default();
        for (id, d) in rules {
            r.detectors
                .entry(d.to_string())
                .or_default()
                .rules
                .push(*id);
        }
        r
    }

    /// Runs one sample under `label`.
    fn add(
        &mut self,
        engine: &Arc<Engine>,
        rules: &BTreeMap<u32, &'static str>,
        label: &str,
        s: &Sample,
        policy: Option<&str>,
    ) {
        *self.samples.entry(label.to_string()).or_default() += 1;
        let mut t = Tx::new(Some(engine.clone()), s.node_id.as_bytes(), 0);
        t.keep_match_values();
        crate::run_tx(&mut t, s, policy);
        let kept = t.match_values();
        let others = kept.iter().any(|m| !rules.contains_key(&m.rule));
        let mut seen: BTreeMap<&str, bool> = BTreeMap::new();
        for m in kept {
            let Some(det) = rules.get(&m.rule) else {
                continue;
            };
            // per detector: enforced as soon as one of its rules is
            let e = seen.entry(det).or_insert(true);
            *e &= m.report_only;
        }
        for (det, only_reported) in seen {
            let d = self.detectors.entry(det.to_string()).or_default();
            let c = d.labels.entry(label.to_string()).or_default();
            c.samples += 1;
            if only_reported {
                c.report_only += 1;
            }
            let alone = !others
                && kept
                    .iter()
                    .all(|m| rules.get(&m.rule).is_some_and(|x| *x == det));
            if alone {
                c.alone += 1;
            }
            let mut fields: Vec<&str> = vec![];
            let mut fps: Vec<String> = vec![];
            for m in kept.iter().filter(|m| rules.get(&m.rule) == Some(&det)) {
                *c.rules.entry(m.rule).or_default() += 1;
                if !fields.contains(&m.field.as_str()) {
                    fields.push(&m.field);
                }
                let fp = if det == "sqli" {
                    detect_sqli(&m.value)
                        .map(|f| String::from_utf8_lossy(f.as_bytes()).into_owned())
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                if !fp.is_empty() && !fps.contains(&fp) {
                    fps.push(fp.clone());
                }
                if (is_benign(label) || label == REPLAY) && d.examples.len() < EXAMPLES {
                    d.examples.push(SemanticExample {
                        label: label.to_string(),
                        rule: m.rule,
                        field: m.field.clone(),
                        fingerprint: fp,
                        value: cut(&m.value, EXAMPLE_LEN),
                        method: s.method.clone(),
                        path: s.uri.clone(),
                    });
                }
            }
            for f in fields {
                *c.fields.entry(f.to_string()).or_default() += 1;
            }
            for f in fps {
                *c.fingerprints.entry(f).or_default() += 1;
            }
        }
    }

    /// The report in Markdown: one table per detector, rate per label.
    pub fn markdown(&self, title: &str) -> String {
        let mut o = format!("# {title}\n\n| Label | Samples |\n|---|---:|\n");
        for (l, n) in &self.samples {
            o += &format!("| {l} | {n} |\n");
        }
        for (name, d) in &self.detectors {
            o += &format!(
                "\n## {name} (rules {})\n\n| Label | Matched | % | Report only | Alone |\n|---|---:|---:|---:|---:|\n",
                d.rules
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            for (l, n) in &self.samples {
                let c = d.labels.get(l).cloned().unwrap_or_default();
                o += &format!(
                    "| {l} | {} | {:.2} | {} | {} |\n",
                    c.samples,
                    100.0 * c.samples as f64 / (*n).max(1) as f64,
                    c.report_only,
                    c.alone
                );
            }
            let fps: Vec<String> = d
                .labels
                .iter()
                .filter(|(l, _)| is_benign(l) || l.as_str() == REPLAY)
                .flat_map(|(l, c)| {
                    c.fingerprints
                        .iter()
                        .map(move |(f, n)| format!("`{f}` {n} ({l})"))
                })
                .collect();
            if !fps.is_empty() {
                o += &format!(
                    "\nFingerprints on benign and replay samples: {}\n",
                    fps.join(", ")
                );
            }
            if !d.examples.is_empty() {
                o += "\n| Label | Rule | Field | Fingerprint | Value |\n|---|---:|---|---|---|\n";
                for e in &d.examples {
                    o += &format!(
                        "| {} | {} | `{}` | {} | `{}` |\n",
                        e.label,
                        e.rule,
                        e.field.replace('|', "\\|").replace('`', "'"),
                        e.fingerprint,
                        e.value
                            .replace('|', "\\|")
                            .replace('`', "'")
                            .replace(['\n', '\r'], " ")
                    );
                }
            }
        }
        o
    }
}

/// Runs labelled samples (corpora, value lists) and the samples of replay
/// files (label [`REPLAY`]) on `threads` threads.
pub fn run(
    engine: Arc<Engine>,
    labelled: &[(String, Sample)],
    files: &[&Path],
    policy: Option<&str>,
    threads: usize,
) -> Result<SemanticReport> {
    let start = Instant::now();
    let rules = semantic_rules(&engine);
    if rules.is_empty() {
        return Err("the bundle has no rule with a semantic operator".into());
    }
    let threads = threads.max(1);
    let mut report = SemanticReport::new(&rules);
    let chunk = labelled.len().div_ceil(threads).max(1);
    let parts: Vec<SemanticReport> = std::thread::scope(|scope| {
        let workers: Vec<_> = labelled
            .chunks(chunk)
            .map(|part| {
                let (engine, rules) = (&engine, &rules);
                scope.spawn(move || {
                    let mut r = SemanticReport::default();
                    for (label, s) in part {
                        r.add(engine, rules, label, s, policy);
                    }
                    r
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|w| w.join().map_err(|_| "a worker panicked".to_string()))
            .collect::<Result<Vec<_>>>()
    })?;
    for p in parts {
        report.merge(p);
    }
    if !files.is_empty() {
        let r: SemanticReport = parallel(files, threads, &|rep: &mut SemanticReport, s| {
            rep.add(&engine, &rules, REPLAY, s, policy)
        })?;
        report.merge(r);
    }
    report.elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(report)
}
