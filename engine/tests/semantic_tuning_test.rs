use std::fs;
use std::path::PathBuf;

use libstrata::detectors::injection::{detect_sqli, detect_xss};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn simple_url_decode(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[test]
fn test_sqli_benign_corpus_zero_false_positives() {
    let path = repo_root().join("corpus/fp/semantic/sqli_benign.txt");
    let content = fs::read_to_string(&path).expect("read sqli_benign.txt");
    let mut false_positives = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(fp) = detect_sqli(trimmed.as_bytes()) {
            false_positives.push((trimmed.to_string(), String::from_utf8_lossy(fp.as_bytes()).to_string()));
        }
    }

    if !false_positives.is_empty() {
        for (sample, fp) in &false_positives {
            eprintln!("SQLi False Positive: {:?} -> fingerprint: {:?}", sample, fp);
        }
        panic!("Found {} SQLi false positives", false_positives.len());
    }
}

#[test]
fn test_xss_benign_corpus_zero_false_positives() {
    let path = repo_root().join("corpus/fp/semantic/xss_benign.txt");
    let content = fs::read_to_string(&path).expect("read xss_benign.txt");
    let mut false_positives = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if detect_xss(trimmed.as_bytes()) {
            false_positives.push(trimmed.to_string());
        }
    }

    if !false_positives.is_empty() {
        for sample in &false_positives {
            eprintln!("XSS False Positive: {:?}", sample);
        }
        panic!("Found {} XSS false positives", false_positives.len());
    }
}

#[test]
fn test_sql_injection_attack_corpus_recall() {
    let path = repo_root().join("corpus/attack/sql-injection.jsonl");
    let content = fs::read_to_string(&path).expect("read sql-injection.jsonl");
    let mut total = 0;
    let mut detected = 0;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let json: serde_json::Value = serde_json::from_str(line).expect("valid jsonl");
        let payload = json["payload"].as_str().expect("payload string");
        // Decode URL encoding if present in payload
        let decoded = simple_url_decode(payload);
        total += 1;
        if detect_sqli(payload.as_bytes()).is_some() || detect_sqli(decoded.as_bytes()).is_some() {
            detected += 1;
        }
    }

    assert!(total > 0, "No attack payloads found");
    let recall = detected as f64 / total as f64;
    println!("SQLi Attack Corpus: {}/{} detected ({:.2}%)", detected, total, recall * 100.0);
    // Semantic detector alone covers core SQLi signatures; threshold >= 40%
    assert!(recall >= 0.40, "SQLi semantic recall {:.2}% is below 40%", recall * 100.0);
}

#[test]
fn test_xss_attack_corpus_recall() {
    let path = repo_root().join("corpus/attack/xss.jsonl");
    let content = fs::read_to_string(&path).expect("read xss.jsonl");
    let mut total = 0;
    let mut detected = 0;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let json: serde_json::Value = serde_json::from_str(line).expect("valid jsonl");
        let payload = json["payload"].as_str().expect("payload string");
        let decoded = simple_url_decode(payload);
        total += 1;
        if detect_xss(payload.as_bytes()) || detect_xss(decoded.as_bytes()) {
            detected += 1;
        }
    }

    assert!(total > 0, "No attack payloads found");
    let recall = detected as f64 / total as f64;
    println!("XSS Attack Corpus: {}/{} detected ({:.2}%)", detected, total, recall * 100.0);
    assert!(recall >= 0.50, "XSS semantic recall {:.2}% is below 50%", recall * 100.0);
}
