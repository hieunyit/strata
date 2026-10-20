//! Replay core (W11-R-01, nginx-module.md › Control plane: Replay service):
//! reads traffic samples in format 1 (docs/spec/replay-sample.md, Parquet,
//! written by control-plane/replay) and runs each request through a bundle,
//! on several threads, into a report by route: what the bundle decides now
//! against what was decided when the request was sampled.
//!
//! The samples are anonymized: sensitive values are tokens
//! (`~h:<hex>:<class><len>`), the client address too, so `ip_match` rules
//! do not replay. The replay runner and the report of W12-R-01 build on
//! this.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use libstrata::engine::Engine;
use libstrata::tx::Tx;
use libstrata::verdict::{ACTION_ALLOW, ACTION_BLOCK, ACTION_CHALLENGE, ACTION_LOG};
use parquet::basic::{Compression, LogicalType, Repetition, Type as PhysicalType, ZstdLevel};
use parquet::data_type::{BoolType, ByteArray, ByteArrayType, Int64Type};
use parquet::file::metadata::KeyValue;
use parquet::file::properties::WriterProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::writer::SerializedFileWriter;
use parquet::record::Field;
use parquet::schema::types::Type;
use serde::Serialize;

pub mod corpus;
pub mod semantic;

/// Sample format this crate reads and writes.
pub const FORMAT: &str = "1";
pub const META_FORMAT: &str = "strata.replay.format";
pub const META_KEY_ID: &str = "strata.replay.anon_key_id";

/// One request of a sample file (docs/spec/replay-sample.md › File).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    pub ts_ms: i64,
    pub node_id: String,
    pub policy: String,
    pub method: String,
    pub raw_uri: String,
    pub uri: String,
    pub args: String,
    pub proto: String,
    pub client: String,
    /// JSON `[[name, value], ...]`
    pub headers: String,
    pub body: Vec<u8>,
    pub body_len: i64,
    pub body_truncated: bool,
    /// verdict when sampled: allow, log, block, error
    pub action: String,
    /// rules matched when sampled, comma separated
    pub rules: String,
}

pub type Result<T> = std::result::Result<T, String>;

/// Every sample of a file; the format must be [`FORMAT`]. Returns the
/// anonymization key id too.
pub fn read_file(path: &Path) -> Result<(String, Vec<Sample>)> {
    let mut out = vec![];
    let key = for_each(path, |s| {
        out.push(s);
        Ok(())
    })?;
    Ok((key, out))
}

/// Calls `f` for every sample of a file, in order; returns the key id.
pub fn for_each(path: &Path, mut f: impl FnMut(Sample) -> Result<()>) -> Result<String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let reader = SerializedFileReader::new(file).map_err(|e| format!("{}: {e}", path.display()))?;
    let meta = reader.metadata().file_metadata();
    let kv = |k: &str| {
        meta.key_value_metadata()
            .and_then(|m| m.iter().find(|e| e.key == k))
            .and_then(|e| e.value.clone())
    };
    if kv(META_FORMAT).as_deref() != Some(FORMAT) {
        return Err(format!(
            "{}: sample format {:?}, want {FORMAT}",
            path.display(),
            kv(META_FORMAT)
        ));
    }
    let key = kv(META_KEY_ID).unwrap_or_default();
    let rows = reader
        .get_row_iter(None)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    for row in rows {
        let row = row.map_err(|e| format!("{}: {e}", path.display()))?;
        let mut s = Sample::default();
        for (name, field) in row.get_column_iter() {
            let text = || match field {
                Field::Str(v) => v.clone(),
                Field::Bytes(b) => String::from_utf8_lossy(b.data()).into_owned(),
                _ => String::new(),
            };
            match (name.as_str(), field) {
                ("ts_ms", Field::Long(v)) => s.ts_ms = *v,
                ("body_len", Field::Long(v)) => s.body_len = *v,
                ("body_truncated", Field::Bool(v)) => s.body_truncated = *v,
                ("body", Field::Bytes(b)) => s.body = b.data().to_vec(),
                ("body", Field::Str(v)) => s.body = v.as_bytes().to_vec(),
                ("node_id", _) => s.node_id = text(),
                ("policy", _) => s.policy = text(),
                ("method", _) => s.method = text(),
                ("raw_uri", _) => s.raw_uri = text(),
                ("uri", _) => s.uri = text(),
                ("args", _) => s.args = text(),
                ("proto", _) => s.proto = text(),
                ("client", _) => s.client = text(),
                ("headers", _) => s.headers = text(),
                ("action", _) => s.action = text(),
                ("rules", _) => s.rules = text(),
                _ => {}
            }
        }
        f(s)?;
    }
    Ok(key)
}

fn schema() -> Arc<Type> {
    let str_col = |n: &str| {
        Arc::new(
            Type::primitive_type_builder(n, PhysicalType::BYTE_ARRAY)
                .with_repetition(Repetition::REQUIRED)
                .with_logical_type(Some(LogicalType::String))
                .build()
                .unwrap(),
        )
    };
    let col = |n: &str, t| {
        Arc::new(
            Type::primitive_type_builder(n, t)
                .with_repetition(Repetition::REQUIRED)
                .build()
                .unwrap(),
        )
    };
    let fields = vec![
        col("ts_ms", PhysicalType::INT64),
        str_col("node_id"),
        str_col("policy"),
        str_col("method"),
        str_col("raw_uri"),
        str_col("uri"),
        str_col("args"),
        str_col("proto"),
        str_col("client"),
        str_col("headers"),
        col("body", PhysicalType::BYTE_ARRAY),
        col("body_len", PhysicalType::INT64),
        col("body_truncated", PhysicalType::BOOLEAN),
        str_col("action"),
        str_col("rules"),
    ];
    Arc::new(
        Type::group_type_builder("sample")
            .with_fields(fields)
            .build()
            .unwrap(),
    )
}

/// Writes samples as one file of format 1, one row group per `group` rows
/// (tools and tests; the control plane writes the real ones).
pub fn write_file(path: &Path, key_id: &str, samples: &[Sample], group: usize) -> Result<()> {
    let file = File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::default()))
        .set_key_value_metadata(Some(vec![
            KeyValue::new(META_FORMAT.to_string(), FORMAT.to_string()),
            KeyValue::new(META_KEY_ID.to_string(), key_id.to_string()),
        ]))
        .build();
    let mut w =
        SerializedFileWriter::new(file, schema(), Arc::new(props)).map_err(|e| e.to_string())?;
    for chunk in samples.chunks(group.max(1)) {
        let mut rg = w.next_row_group().map_err(|e| e.to_string())?;
        let mut col = 0;
        while let Some(mut c) = rg.next_column().map_err(|e| e.to_string())? {
            let bytes = |f: fn(&Sample) -> &[u8]| -> Vec<ByteArray> {
                chunk
                    .iter()
                    .map(|s| ByteArray::from(f(s).to_vec()))
                    .collect()
            };
            let r = match col {
                0 => c.typed::<Int64Type>().write_batch(
                    &chunk.iter().map(|s| s.ts_ms).collect::<Vec<_>>(),
                    None,
                    None,
                ),
                11 => c.typed::<Int64Type>().write_batch(
                    &chunk.iter().map(|s| s.body_len).collect::<Vec<_>>(),
                    None,
                    None,
                ),
                12 => c.typed::<BoolType>().write_batch(
                    &chunk.iter().map(|s| s.body_truncated).collect::<Vec<_>>(),
                    None,
                    None,
                ),
                _ => {
                    let v = match col {
                        1 => bytes(|s| s.node_id.as_bytes()),
                        2 => bytes(|s| s.policy.as_bytes()),
                        3 => bytes(|s| s.method.as_bytes()),
                        4 => bytes(|s| s.raw_uri.as_bytes()),
                        5 => bytes(|s| s.uri.as_bytes()),
                        6 => bytes(|s| s.args.as_bytes()),
                        7 => bytes(|s| s.proto.as_bytes()),
                        8 => bytes(|s| s.client.as_bytes()),
                        9 => bytes(|s| s.headers.as_bytes()),
                        10 => bytes(|s| &s.body),
                        13 => bytes(|s| s.action.as_bytes()),
                        _ => bytes(|s| s.rules.as_bytes()),
                    };
                    c.typed::<ByteArrayType>().write_batch(&v, None, None)
                }
            };
            r.map_err(|e| e.to_string())?;
            c.close().map_err(|e| e.to_string())?;
            col += 1;
        }
        rg.close().map_err(|e| e.to_string())?;
    }
    w.close().map_err(|e| e.to_string())?;
    Ok(())
}

/// What the bundle decided for one sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub action: &'static str,
    pub rules: Vec<u32>,
}

fn action_name(a: u32, error: bool) -> &'static str {
    if error {
        return "error";
    }
    match a {
        ACTION_ALLOW => "allow",
        ACTION_LOG => "log",
        ACTION_CHALLENGE => "challenge",
        ACTION_BLOCK => "block",
        _ => "error",
    }
}

/// Runs one sample through the engine, as the connector would.
/// `policy` replaces the sample's policy when set (a draft under another
/// name).
pub fn evaluate(engine: &Arc<Engine>, s: &Sample, policy: Option<&str>) -> Outcome {
    let mut t = Tx::new(Some(engine.clone()), s.node_id.as_bytes(), 0);
    run_tx(&mut t, s, policy);
    let v = t.verdict();
    Outcome {
        action: action_name(v.action, v.error != libstrata::verdict::OK),
        rules: v.rules[..v.n_rules as usize].to_vec(),
    }
}

/// Feeds one sample to a transaction, as the connector would.
fn run_tx(t: &mut Tx, s: &Sample, policy: Option<&str>) {
    t.set_client_addr(s.client.as_bytes());
    t.set_policy(policy.unwrap_or(&s.policy).as_bytes());
    t.request_line(
        s.method.as_bytes(),
        s.raw_uri.as_bytes(),
        s.uri.as_bytes(),
        s.args.as_bytes(),
        s.proto.as_bytes(),
    );
    let headers: Vec<(String, String)> =
        serde_json::from_str::<Vec<(String, String)>>(&s.headers).unwrap_or_default();
    let h: Vec<(&[u8], &[u8])> = headers
        .iter()
        .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
        .collect();
    t.request_headers(&h);
    t.request_body_chunk(&s.body, true);
}

/// Counts of one route (policy).
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct RouteReport {
    pub samples: u64,
    /// action now -> count
    pub actions: BTreeMap<String, u64>,
    /// "<when sampled> -> <now>" for the samples whose action changed
    pub changed: BTreeMap<String, u64>,
    /// allowed or logged when sampled, blocked now: candidate false
    /// positives of the bundle under test
    pub newly_blocked: u64,
    /// blocked when sampled, not now: candidate false negatives
    pub no_longer_blocked: u64,
}

/// A replay run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub samples: u64,
    pub elapsed_ms: u64,
    pub per_second: u64,
    pub threads: usize,
    pub routes: BTreeMap<String, RouteReport>,
    /// rule id -> samples it matched now
    pub rules: BTreeMap<u32, u64>,
}

impl Report {
    fn add(&mut self, s: &Sample, o: &Outcome) {
        self.samples += 1;
        let r = self.routes.entry(s.policy.clone()).or_default();
        r.samples += 1;
        *r.actions.entry(o.action.to_string()).or_default() += 1;
        if s.action != o.action {
            *r.changed
                .entry(format!("{} -> {}", s.action, o.action))
                .or_default() += 1;
            if o.action == "block" && (s.action == "allow" || s.action == "log") {
                r.newly_blocked += 1;
            }
            if s.action == "block" {
                r.no_longer_blocked += 1;
            }
        }
        for id in &o.rules {
            *self.rules.entry(*id).or_default() += 1;
        }
    }

    fn merge(&mut self, o: Report) {
        self.samples += o.samples;
        for (k, v) in o.routes {
            let r = self.routes.entry(k).or_default();
            r.samples += v.samples;
            r.newly_blocked += v.newly_blocked;
            r.no_longer_blocked += v.no_longer_blocked;
            for (a, n) in v.actions {
                *r.actions.entry(a).or_default() += n;
            }
            for (a, n) in v.changed {
                *r.changed.entry(a).or_default() += n;
            }
        }
        for (k, v) in o.rules {
            *self.rules.entry(k).or_default() += v;
        }
    }
}

/// Batches of samples handed to the workers.
const BATCH: usize = 512;

/// Accumulates what workers find; merged at the end.
trait Acc: Default + Send {
    fn merge(&mut self, o: Self);
}

impl Acc for Report {
    fn merge(&mut self, o: Self) {
        Report::merge(self, o)
    }
}

/// Runs `f` on every sample of `files` on `threads` threads: a reader
/// thread streams batches through a bounded queue, so memory stays flat
/// whatever the number of samples.
fn parallel<A: Acc>(
    files: &[&Path],
    threads: usize,
    f: &(dyn Fn(&mut A, &Sample) + Sync),
) -> Result<A> {
    let threads = threads.max(1);
    let (tx, rx) = sync_channel::<Vec<Sample>>(threads * 4);
    let rx: Arc<Mutex<Receiver<Vec<Sample>>>> = Arc::new(Mutex::new(rx));
    std::thread::scope(|scope| -> Result<A> {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                let rx = rx.clone();
                scope.spawn(move || {
                    let mut acc = A::default();
                    loop {
                        let batch = match rx.lock() {
                            Ok(r) => r.recv(),
                            Err(_) => break,
                        };
                        let Ok(batch) = batch else { break };
                        for s in &batch {
                            f(&mut acc, s);
                        }
                    }
                    acc
                })
            })
            .collect();
        let mut read_err = None;
        for file in files {
            let mut batch = Vec::with_capacity(BATCH);
            let r = for_each(file, |s| {
                batch.push(s);
                if batch.len() == BATCH {
                    tx.send(std::mem::replace(&mut batch, Vec::with_capacity(BATCH)))
                        .map_err(|_| "replay workers stopped".to_string())?;
                }
                Ok(())
            });
            if let Err(e) = r {
                read_err = Some(e);
                break;
            }
            if !batch.is_empty() && tx.send(batch).is_err() {
                read_err = Some("replay workers stopped".to_string());
                break;
            }
        }
        drop(tx);
        let mut total = A::default();
        for w in workers {
            total.merge(
                w.join()
                    .map_err(|_| "a replay worker panicked".to_string())?,
            );
        }
        match read_err {
            Some(e) => Err(e),
            None => Ok(total),
        }
    })
}

/// Replays every sample of `files` on `threads` threads.
pub fn run(
    engine: Arc<Engine>,
    files: &[&Path],
    policy: Option<&str>,
    threads: usize,
) -> Result<Report> {
    let start = Instant::now();
    let mut report: Report = parallel(files, threads, &|rep: &mut Report, s: &Sample| {
        let o = evaluate(&engine, s, policy);
        rep.add(s, &o);
    })?;
    let elapsed = start.elapsed();
    report.elapsed_ms = elapsed.as_millis() as u64;
    report.per_second = (report.samples as f64 / elapsed.as_secs_f64().max(1e-9)) as u64;
    report.threads = threads.max(1);
    Ok(report)
}

/// A sample whose verdict differs between the draft and the baseline.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Example {
    pub ts_ms: i64,
    pub node_id: String,
    pub method: String,
    /// as sampled: already anonymized
    pub raw_uri: String,
    pub draft: String,
    pub baseline: String,
    pub draft_rules: Vec<u32>,
    pub baseline_rules: Vec<u32>,
}

/// Examples kept per route and kind of change.
const EXAMPLES: usize = 5;

/// One route (policy) of a comparison.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CompareRoute {
    pub samples: u64,
    /// action -> count, with the draft and with the baseline
    pub draft: BTreeMap<String, u64>,
    pub baseline: BTreeMap<String, u64>,
    /// blocked by the draft, not by the baseline: candidate false positives
    pub newly_blocked: u64,
    /// blocked by the baseline, not by the draft: candidate false negatives
    pub newly_allowed: u64,
    /// the draft's rules on the newly blocked samples, and the baseline's on
    /// the newly allowed ones
    pub newly_blocked_rules: BTreeMap<u32, u64>,
    pub newly_allowed_rules: BTreeMap<u32, u64>,
    /// path (first two segments) -> newly blocked
    pub newly_blocked_paths: BTreeMap<String, u64>,
    /// the action recorded when the sample was taken (the bundle in force
    /// then; the label of corpus samples: allow benign, block attack) ->
    /// newly blocked, and -> newly allowed
    pub newly_blocked_sampled: BTreeMap<String, u64>,
    pub newly_allowed_sampled: BTreeMap<String, u64>,
    pub examples_blocked: Vec<Example>,
    pub examples_allowed: Vec<Example>,
}

/// A draft bundle against the bundle in force, on the same samples
/// (W12-R-01).
#[derive(Clone, Debug, Default, Serialize)]
pub struct Comparison {
    pub samples: u64,
    pub elapsed_ms: u64,
    pub routes: BTreeMap<String, CompareRoute>,
}

impl Acc for Comparison {
    fn merge(&mut self, o: Self) {
        self.samples += o.samples;
        for (k, v) in o.routes {
            let r = self.routes.entry(k).or_default();
            r.samples += v.samples;
            r.newly_blocked += v.newly_blocked;
            r.newly_allowed += v.newly_allowed;
            for (dst, src) in [(&mut r.draft, v.draft), (&mut r.baseline, v.baseline)] {
                for (a, n) in src {
                    *dst.entry(a).or_default() += n;
                }
            }
            for (dst, src) in [
                (&mut r.newly_blocked_rules, v.newly_blocked_rules),
                (&mut r.newly_allowed_rules, v.newly_allowed_rules),
            ] {
                for (a, n) in src {
                    *dst.entry(a).or_default() += n;
                }
            }
            for (a, n) in v.newly_blocked_sampled {
                *r.newly_blocked_sampled.entry(a).or_default() += n;
            }
            for (a, n) in v.newly_allowed_sampled {
                *r.newly_allowed_sampled.entry(a).or_default() += n;
            }
            for (a, n) in v.newly_blocked_paths {
                *r.newly_blocked_paths.entry(a).or_default() += n;
            }
            for (dst, src) in [
                (&mut r.examples_blocked, v.examples_blocked),
                (&mut r.examples_allowed, v.examples_allowed),
            ] {
                for e in src {
                    if dst.len() < EXAMPLES {
                        dst.push(e);
                    }
                }
            }
        }
    }
}

fn path_prefix(uri: &str) -> String {
    let p = uri.split('?').next().unwrap_or("");
    let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).take(2).collect();
    format!("/{}", segs.join("/"))
}

/// Replays `files` through a draft bundle and the baseline (the bundle in
/// force): per route, what the draft would block that the baseline lets
/// through, and the reverse, with the rules responsible.
pub fn compare(
    draft: Arc<Engine>,
    baseline: Arc<Engine>,
    files: &[&Path],
    policy: Option<&str>,
    threads: usize,
) -> Result<Comparison> {
    let start = Instant::now();
    let mut c: Comparison = parallel(files, threads, &|c: &mut Comparison, s: &Sample| {
        let d = evaluate(&draft, s, policy);
        let b = evaluate(&baseline, s, policy);
        c.samples += 1;
        let r = c
            .routes
            .entry(policy.unwrap_or(&s.policy).to_string())
            .or_default();
        r.samples += 1;
        *r.draft.entry(d.action.to_string()).or_default() += 1;
        *r.baseline.entry(b.action.to_string()).or_default() += 1;
        let ex = || Example {
            ts_ms: s.ts_ms,
            node_id: s.node_id.clone(),
            method: s.method.clone(),
            raw_uri: s.raw_uri.clone(),
            draft: d.action.to_string(),
            baseline: b.action.to_string(),
            draft_rules: d.rules.clone(),
            baseline_rules: b.rules.clone(),
        };
        match (d.action == "block", b.action == "block") {
            (true, false) => {
                r.newly_blocked += 1;
                for id in &d.rules {
                    *r.newly_blocked_rules.entry(*id).or_default() += 1;
                }
                *r.newly_blocked_paths
                    .entry(path_prefix(&s.uri))
                    .or_default() += 1;
                *r.newly_blocked_sampled.entry(s.action.clone()).or_default() += 1;
                if r.examples_blocked.len() < EXAMPLES {
                    r.examples_blocked.push(ex());
                }
            }
            (false, true) => {
                r.newly_allowed += 1;
                *r.newly_allowed_sampled.entry(s.action.clone()).or_default() += 1;
                for id in &b.rules {
                    *r.newly_allowed_rules.entry(*id).or_default() += 1;
                }
                if r.examples_allowed.len() < EXAMPLES {
                    r.examples_allowed.push(ex());
                }
            }
            _ => {}
        }
    })?;
    c.elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(c)
}

impl Comparison {
    /// The comparison as a Markdown report.
    pub fn markdown(&self, title: &str) -> String {
        let mut o = format!(
            "# {title}\n\n{} samples, {} ms.\n\n",
            self.samples, self.elapsed_ms
        );
        o.push_str("| Route | Samples | Blocked (baseline → draft) | Newly blocked (candidate FP) | Newly allowed (candidate FN) |\n| --- | --- | --- | --- | --- |\n");
        for (k, r) in &self.routes {
            let blk = |m: &BTreeMap<String, u64>| m.get("block").copied().unwrap_or(0);
            o.push_str(&format!(
                "| `{k}` | {} | {} → {} | {} ({:.2}%) | {} |\n",
                r.samples,
                blk(&r.baseline),
                blk(&r.draft),
                r.newly_blocked,
                100.0 * r.newly_blocked as f64 / r.samples.max(1) as f64,
                r.newly_allowed
            ));
        }
        for (k, r) in &self.routes {
            if r.newly_blocked == 0 && r.newly_allowed == 0 {
                continue;
            }
            o.push_str(&format!("\n## `{k}`\n\n"));
            let top = |m: &BTreeMap<u32, u64>| {
                let mut v: Vec<_> = m.iter().collect();
                v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                v.iter()
                    .take(10)
                    .map(|(id, n)| format!("{id} ({n})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let sampled = |m: &BTreeMap<String, u64>| {
                m.iter()
                    .map(|(k, n)| format!("{k} {n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            if r.newly_blocked > 0 {
                o.push_str(&format!(
                    "Newly blocked, by action when sampled (the label of corpus samples): {}\n\n",
                    sampled(&r.newly_blocked_sampled)
                ));
                o.push_str(&format!(
                    "Rules of the newly blocked: {}\n\n",
                    top(&r.newly_blocked_rules)
                ));
                let mut p: Vec<_> = r.newly_blocked_paths.iter().collect();
                p.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                o.push_str(&format!(
                    "Paths: {}\n\n",
                    p.iter()
                        .take(10)
                        .map(|(k, n)| format!("`{k}` ({n})"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if r.newly_allowed > 0 {
                o.push_str(&format!(
                    "Newly allowed, by action when sampled: {}\n\n",
                    sampled(&r.newly_allowed_sampled)
                ));
                o.push_str(&format!(
                    "Baseline rules of the newly allowed: {}\n\n",
                    top(&r.newly_allowed_rules)
                ));
            }
            for e in r.examples_blocked.iter().chain(&r.examples_allowed) {
                let uri: String = e.raw_uri.chars().take(120).collect();
                o.push_str(&format!(
                    "- {} `{}`: {} → {} (draft rules {:?}, baseline {:?})\n",
                    e.method,
                    uri.replace('`', "'"),
                    e.baseline,
                    e.draft,
                    e.draft_rules,
                    e.baseline_rules
                ));
            }
        }
        o
    }
}

/// Maps a bundle file for replay.
pub fn load_engine(bundle: &Path, pubkey: &Path) -> Result<Arc<Engine>> {
    let b = std::fs::read(bundle).map_err(|e| format!("{}: {e}", bundle.display()))?;
    let k = std::fs::read(pubkey).map_err(|e| format!("{}: {e}", pubkey.display()))?;
    let key: [u8; 32] = k
        .get(..32)
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| format!("{}: public key is not 32 bytes", pubkey.display()))?;
    let e = Engine::map(Box::new(strata_hs::AlignedBuf::from_bytes(&b)), &key)
        .map_err(|(rc, m)| format!("{}: bundle refused ({rc}): {m}", bundle.display()))?;
    Ok(Arc::new(e))
}
