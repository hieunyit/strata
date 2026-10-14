//! Soak 14/10/2026 (W09-Q-02): mapping the full signature package on many
//! thread-pool threads, as NGINX does, grew a worker by about 18 MB per
//! new thread (one glibc malloc arena each). strata_engine_map now maps on
//! one loader thread (src/loader.rs): memory stays flat. Slow (a full
//! Hyperscan compile): run with
//! cargo test --release -p libstrata-ffi --test arena -- --ignored --nocapture

use std::path::{Path, PathBuf};
use std::sync::mpsc;

use libstrata::bundle::public_key;
use strata::abi::strata_err_t;
use strata::ffi::{EngineHandle, strata_engine_map, strata_engine_release};
use strata_compiler::{Build, compile, from_yaml, policies_from, rules_from_ir};

const SEED: [u8; 32] = [47; 32];

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every rule file under `dir` (as `strata-rules release` gathers them).
fn rule_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if p.is_dir() {
            if name != "schema" && name != "tests" && name != "reviews" {
                rule_files(&p, out);
            }
        } else if name.ends_with(".yaml") {
            out.push(p);
        }
    }
}

fn rss_mb() -> f64 {
    let s = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: f64 = s.split_whitespace().nth(1).unwrap().parse().unwrap();
    pages * 4096.0 / 1048576.0
}

#[test]
#[ignore]
fn mapping_on_many_threads_keeps_memory_flat() {
    let mut files = vec![];
    rule_files(&repo().join("rules"), &mut files);
    let mut defs = vec![];
    for f in files {
        let doc = from_yaml(&std::fs::read_to_string(&f).unwrap()).unwrap();
        let doc = if doc.get("rule").is_some() {
            serde_json::json!({"ir_version": 1, "ruleset": {"name": "p", "version": "1"}, "rules": [doc["rule"].clone()]})
        } else if doc.get("ir_version").is_some() {
            doc
        } else {
            continue;
        };
        defs.extend(rules_from_ir(&doc).unwrap());
    }
    let pol = policies_from(
        &from_yaml("policies: [{ name: example-api, mode: enforce }]").unwrap(),
        Path::new("."),
    )
    .unwrap();
    let b = compile(
        &defs,
        &pol,
        &Build {
            version: 1,
            created_at_ms: 0,
            rollback: false,
        },
        &SEED,
    )
    .unwrap();
    let buf = strata_hs::AlignedBuf::from_bytes(&b);
    let (base, len) = (buf.as_ref().as_ptr() as usize, b.len());
    let key = public_key(&SEED);

    // long-lived threads, as NGINX's thread pool
    type Job = Box<dyn FnOnce() + Send>;
    let pool: Vec<mpsc::Sender<(Job, mpsc::Sender<()>)>> = (0..16)
        .map(|_| {
            let (tx, rx) = mpsc::channel::<(Job, mpsc::Sender<()>)>();
            std::thread::spawn(move || {
                for (job, done) in rx {
                    job();
                    let _ = done.send(());
                }
            });
            tx
        })
        .collect();
    let run_on = |i: usize, job: Job| {
        let (dtx, drx) = mpsc::channel();
        pool[i % pool.len()].send((job, dtx)).unwrap();
        drx.recv().unwrap();
    };

    let mut rss = vec![];
    for round in 0..24 {
        let (htx, hrx) = mpsc::channel::<usize>();
        run_on(
            round,
            Box::new(move || {
                let mut err = strata_err_t {
                    code: 0,
                    msg: [0; strata::abi::STRATA_ERR_MSG_SIZE],
                };
                // SAFETY: base/len point into buf (alive for the test, 4 KB
                // aligned), key is 32 bytes.
                let h =
                    unsafe { strata_engine_map(base as *const u8, len, key.as_ptr(), &mut err) };
                assert!(!h.is_null(), "map: {}", err.code);
                htx.send(h as usize).unwrap();
            }),
        );
        let h = hrx.recv().unwrap();
        run_on(
            round + 1,
            Box::new(move || {
                // SAFETY: the only reference, from strata_engine_map above.
                unsafe { strata_engine_release(h as *mut EngineHandle) };
            }),
        );
        rss.push(rss_mb());
        eprintln!("round {round}: rss {:.1} MB", rss[round]);
    }
    // before the loader thread: about +18 MB a round up to 16 rounds
    let grown = rss[23] - rss[3];
    assert!(
        grown < 40.0,
        "grew {grown:.1} MB over 20 maps on 16 threads"
    );
}
