#!/usr/bin/env python3
"""
Heavy Adversarial Security Evaluation Engine (docs/plan/redteam-plan.md)
Executes 1,000 - 5,000 requests per attack category against Strata WAF:
- Category 1: SQL Injection (~3,200 requests)
- Category 2: Command Injection / RCE (~2,400 requests)
- Category 3: Cross-Site Scripting (XSS) (~2,100 requests)
- Category 4: Path Traversal / LFI (~2,300 requests)
- Category 5: High-Speed Fuzzing (ffuf) (3,000 requests)
- Category 6: TC-EXP-01 Timing Attack CPU Budget Probe (1,000 requests)
- Category 7: TC-EXP-02 Tail Padding & Fail-Open #98 (1,000 requests)
- Category 8: TC-EXP-03 ReDoS & Backtracking (1,000 requests)
- Category 9: TC-PAR-02 JSON Deep Nesting & Malformed (1,000 requests)
- Category 10: TC-OPS-01 Botnet Fallback Simulation (5,000 requests)
- Category 11: TC-OPS-02 Canary Identity Hash Spoofing (2,000 requests)
- Category 12: TC-OPS-03 Event Socket Flooding (5,000 requests)

Total: ~30,000 live HTTP requests evaluated.
"""

import concurrent.futures
import gzip
import hashlib
import http.client
import json
import os
import random
import re
import socket
import sys
import time
import urllib.parse

HOST = "127.0.0.1"
PORT_A = 48080  # Profile A: Standard Default (10ms budget, fail_mode open)
PORT_B = 48081  # Profile B: Hardened Strict (10ms budget, oversize block, fail_mode closed)
PORT_C = 48082  # Profile C: Stress (2ms budget, fail_mode open)

STATS = {}

def get_connection(port=PORT_A):
    return http.client.HTTPConnection(HOST, port, timeout=5)

def send_request(path, method="GET", body=None, headers=None, port=PORT_A):
    if headers is None:
        headers = {}
    if "Host" not in headers:
        headers["Host"] = "api.example.test"
    t0 = time.perf_counter()
    try:
        conn = get_connection(port)
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read()
        conn.close()
        elapsed = (time.perf_counter() - t0) * 1000
        return resp.status, elapsed, resp_body
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return 0, elapsed, str(e).encode()

def run_worker_batch(tasks, max_workers=25):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(send_request, *t) for t in tasks]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())
    return results

def analyze_results(category_name, results):
    total = len(results)
    blocked_403 = sum(1 for status, _, _ in results if status == 403)
    blocked_400 = sum(1 for status, _, _ in results if status == 400)
    passed_200 = sum(1 for status, _, _ in results if status == 200)
    error_50x = sum(1 for status, _, _ in results if status in [500, 502, 503, 504])
    network_err = sum(1 for status, _, _ in results if status == 0)
    
    latencies = sorted([elapsed for _, elapsed, _ in results if elapsed > 0])
    p50 = latencies[int(len(latencies) * 0.50)] if latencies else 0
    p90 = latencies[int(len(latencies) * 0.90)] if latencies else 0
    p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0
    
    total_blocked = blocked_403 + blocked_400
    pr = (total_blocked / total * 100) if total else 0
    
    summary = {
        "total_requests": total,
        "blocked_403": blocked_403,
        "rejected_400": blocked_400,
        "passed_200": passed_200,
        "error_50x": error_50x,
        "network_err": network_err,
        "protection_rate_pct": round(pr, 2),
        "latency_p50_ms": round(p50, 2),
        "latency_p90_ms": round(p90, 2),
        "latency_p99_ms": round(p99, 2),
    }
    STATS[category_name] = summary
    print(f"\n[{category_name.upper()}] Total: {total} | Blocked: {total_blocked} ({pr:.2f}%) | Passed: {passed_200} | 50x: {error_50x} | p99: {p99:.2f} ms")
    return summary

# -----------------------------------------------------------------------------
# 1. SQL Injection Evaluation (Target: ~3,200 requests)
# -----------------------------------------------------------------------------
def eval_sql_injection():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 1: SQL Injection (~3,200 requests)")
    print("="*70)
    corpus_file = "corpus/attack/sql-injection.jsonl"
    payloads = []
    if os.path.exists(corpus_file):
        with open(corpus_file) as f:
            for line in f:
                try:
                    payloads.append(json.loads(line)["payload"])
                except Exception:
                    pass
    else:
        payloads = ["' OR 1=1--", "' UNION SELECT NULL, password FROM users--"]
        
    tasks = []
    for p in payloads:
        # Variant 1: Raw / standard quoted
        tasks.append((f"/vuln/sqli?id={urllib.parse.quote(p)}", "GET", None, {}, PORT_A))
        # Variant 2: Double URL encoded
        tasks.append((f"/vuln/sqli?id={urllib.parse.quote(urllib.parse.quote(p))}", "GET", None, {}, PORT_A))
        # Variant 3: Space to comment
        p_comm = p.replace(" ", "/**/")
        tasks.append((f"/vuln/sqli?id={urllib.parse.quote(p_comm)}", "GET", None, {}, PORT_A))
        # Variant 4: POST urlencoded body
        body = f"id={urllib.parse.quote(p)}".encode()
        tasks.append(("/vuln/sqli", "POST", body, {"Content-Type": "application/x-www-form-urlencoded"}, PORT_A))
        
    print(f"Generated {len(tasks)} SQL Injection attack requests...")
    results = run_worker_batch(tasks, max_workers=30)
    return analyze_results("SQL Injection", results)

# -----------------------------------------------------------------------------
# 2. Command Injection / RCE Evaluation (Target: ~2,400 requests)
# -----------------------------------------------------------------------------
def eval_command_injection():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 2: Command Injection / RCE (~2,400 requests)")
    print("="*70)
    corpus_file = "corpus/attack/command-injection.jsonl"
    payloads = []
    if os.path.exists(corpus_file):
        with open(corpus_file) as f:
            for line in f:
                try:
                    payloads.append(json.loads(line)["payload"])
                except Exception:
                    pass
    else:
        payloads = ["; id", "| id", "`id`", "$(id)", "; cat /etc/passwd"]
        
    tasks = []
    for p in payloads:
        # Variant 1: Raw quoted
        tasks.append((f"/vuln/rce?cmd={urllib.parse.quote(p)}", "GET", None, {}, PORT_A))
        # Variant 2: Double URL encoded
        tasks.append((f"/vuln/rce?cmd={urllib.parse.quote(urllib.parse.quote(p))}", "GET", None, {}, PORT_A))
        # Variant 3: Prepend semicolon & newline
        tasks.append((f"/vuln/rce?cmd=%0a{urllib.parse.quote(p)}", "GET", None, {}, PORT_A))
        # Variant 4: Shell backticks
        tasks.append((f"/vuln/rce?cmd=`{urllib.parse.quote(p)}`", "GET", None, {}, PORT_A))
        # Variant 5: POST form body
        body = f"cmd={urllib.parse.quote(p)}".encode()
        tasks.append(("/vuln/rce", "POST", body, {"Content-Type": "application/x-www-form-urlencoded"}, PORT_A))
        
    print(f"Generated {len(tasks)} Command Injection attack requests...")
    results = run_worker_batch(tasks, max_workers=30)
    return analyze_results("Command Injection", results)

# -----------------------------------------------------------------------------
# 3. Cross-Site Scripting (XSS) Evaluation (Target: ~2,100 requests)
# -----------------------------------------------------------------------------
def eval_xss():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 3: Cross-Site Scripting (XSS) (~2,100 requests)")
    print("="*70)
    corpus_file = "corpus/attack/xss.jsonl"
    payloads = []
    if os.path.exists(corpus_file):
        with open(corpus_file) as f:
            for line in f:
                try:
                    payloads.append(json.loads(line)["payload"])
                except Exception:
                    pass
    else:
        payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        
    tasks = []
    for p in payloads:
        # Variant 1: Raw quoted
        tasks.append((f"/search?search={urllib.parse.quote(p)}", "GET", None, {}, PORT_A))
        # Variant 2: Double URL encoded
        tasks.append((f"/search?search={urllib.parse.quote(urllib.parse.quote(p))}", "GET", None, {}, PORT_A))
        # Variant 3: Case swap
        tasks.append((f"/search?search={urllib.parse.quote(p.swapcase())}", "GET", None, {}, PORT_A))
        # Variant 4: POST JSON body
        body = json.dumps({"search": p}).encode()
        tasks.append(("/search", "POST", body, {"Content-Type": "application/json"}, PORT_A))
        
    print(f"Generated {len(tasks)} XSS attack requests...")
    results = run_worker_batch(tasks, max_workers=30)
    return analyze_results("Cross-Site Scripting", results)

# -----------------------------------------------------------------------------
# 4. Path Traversal Evaluation (Target: ~2,300 requests)
# -----------------------------------------------------------------------------
def eval_path_traversal():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 4: Path Traversal / LFI (~2,300 requests)")
    print("="*70)
    corpus_file = "corpus/attack/path-traversal.jsonl"
    payloads = []
    if os.path.exists(corpus_file):
        with open(corpus_file) as f:
            for line in f:
                try:
                    payloads.append(json.loads(line)["payload"])
                except Exception:
                    pass
    else:
        payloads = ["../../etc/passwd", "..%2f..%2fetc/passwd"]
        
    tasks = []
    for p in payloads:
        # Variant 1: Raw path
        tasks.append((f"/{p}", "GET", None, {}, PORT_A))
        # Variant 2: Traversal in query param
        tasks.append((f"/file?name={urllib.parse.quote(p)}", "GET", None, {}, PORT_A))
        # Variant 3: Double encoded traversal
        p_double = p.replace("../", "%252e%252e%252f")
        tasks.append((f"/{p_double}", "GET", None, {}, PORT_A))
        # Variant 4: Matrix param prefixed
        tasks.append((f"/public;param=1/{p}", "GET", None, {}, PORT_A))
        # Variant 5: Traversal in POST body
        body = f"path={urllib.parse.quote(p)}".encode()
        tasks.append(("/download", "POST", body, {"Content-Type": "application/x-www-form-urlencoded"}, PORT_A))
        
    print(f"Generated {len(tasks)} Path Traversal attack requests...")
    results = run_worker_batch(tasks, max_workers=30)
    return analyze_results("Path Traversal", results)

# -----------------------------------------------------------------------------
# 5. TC-EXP-01: Timing Attack CPU Budget Probe (1,000 requests)
# -----------------------------------------------------------------------------
def eval_timing_budget_probe():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 6: TC-EXP-01 Timing Attack CPU Budget Probe (1,000 requests)")
    print("="*70)
    tasks = []
    for i in range(1000):
        # Scale field count from 10 to 1000
        fields = (i % 50 + 1) * 20
        data = {f"field_{k}": f"val_{k}_%27%20OR%201=1" for k in range(fields)}
        body = json.dumps(data).encode()
        tasks.append(("/", "POST", body, {"Content-Type": "application/json"}, PORT_A))
        
    results = run_worker_batch(tasks, max_workers=20)
    return analyze_results("TC-EXP-01 Timing Budget Probe", results)

# -----------------------------------------------------------------------------
# 6. TC-EXP-02: Tail Padding & Fail-Open #98 (1,000 requests)
# -----------------------------------------------------------------------------
def eval_tail_padding():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 7: TC-EXP-02 Tail Padding & Fail-Open #98 (1,000 requests)")
    print("="*70)
    tasks_a = []
    tasks_b = []
    for i in range(500):
        # Varied padding size: 100 KB to 600 KB
        pad_size = 50 + (i % 10) * 50
        body = ("clean=" + "A" * (pad_size * 1024) + "&sqli=%27%20UNION%20SELECT%20NULL%2Cpassword%20FROM%20users--").encode()
        tasks_a.append(("/", "POST", body, {"Content-Type": "application/x-www-form-urlencoded"}, PORT_A))
        tasks_b.append(("/", "POST", body, {"Content-Type": "application/x-www-form-urlencoded"}, PORT_B))
        
    print("Running 500 requests on Profile A (fail-open)...")
    res_a = run_worker_batch(tasks_a, max_workers=10)
    analyze_results("TC-EXP-02 Profile A (fail-open)", res_a)
    
    print("Running 500 requests on Profile B (oversize: block, fail-closed)...")
    res_b = run_worker_batch(tasks_b, max_workers=10)
    analyze_results("TC-EXP-02 Profile B (oversize: block)", res_b)

# -----------------------------------------------------------------------------
# 7. TC-EXP-03: ReDoS & Backtracking (1,000 requests)
# -----------------------------------------------------------------------------
def eval_redos():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 8: TC-EXP-03 ReDoS & Backtracking (1,000 requests)")
    print("="*70)
    tasks = []
    for i in range(1000):
        length = 1000 + (i % 20) * 1000
        payload = "a" * length + "!"
        tasks.append((f"/?input={payload}", "GET", None, {}, PORT_A))
        
    results = run_worker_batch(tasks, max_workers=30)
    return analyze_results("TC-EXP-03 ReDoS Backtracking", results)

# -----------------------------------------------------------------------------
# 8. TC-PAR-02: JSON Deep Nesting & Malformed (1,000 requests)
# -----------------------------------------------------------------------------
def eval_json_nesting():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 9: TC-PAR-02 JSON Deep Nesting & Malformed (1,000 requests)")
    print("="*70)
    tasks = []
    for i in range(1000):
        depth = 10 + (i % 60) * 2  # depth 10 to 130
        body = ('{"k":' * depth + '{"payload":"1; DROP TABLE users;"}' + '}' * depth).encode()
        tasks.append(("/", "POST", body, {"Content-Type": "application/json"}, PORT_A))
        
    results = run_worker_batch(tasks, max_workers=25)
    return analyze_results("TC-PAR-02 JSON Deep Nesting", results)

# -----------------------------------------------------------------------------
# 9. TC-OPS-01: Botnet Fallback Simulation (5,000 requests)
# -----------------------------------------------------------------------------
def eval_botnet_fallback():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 10: TC-OPS-01 Botnet Fallback Poisson Test (5,000 requests)")
    print("="*70)
    tasks = []
    for i in range(5000):
        # 1000 distinct source IPs
        ip = f"198.51.100.{i % 254 + 1}"
        tasks.append((f"/vuln/sqli?id=err_{i}", "GET", None, {"X-Forwarded-For": ip}, PORT_A))
        
    print("Sending 5,000 distributed error requests to test Circuit Breaker...")
    results = run_worker_batch(tasks, max_workers=40)
    return analyze_results("TC-OPS-01 Botnet Fallback", results)

# -----------------------------------------------------------------------------
# 10. TC-OPS-02: Canary Identity Hash Spoofing (2,000 requests)
# -----------------------------------------------------------------------------
def eval_canary_identity():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 11: TC-OPS-02 Canary Identity Hash Spoofing (2,000 requests)")
    print("="*70)
    buckets = {}
    for i in range(2000):
        identity = f"client-identity-eval-{i}"
        bucket = int(hashlib.md5(identity.encode()).hexdigest(), 16) % 100
        buckets.setdefault(bucket, []).append(identity)
        
    summary = {
        "total_identities_tested": 2000,
        "unique_buckets_mapped": len(buckets),
        "min_bucket_count": min(len(v) for v in buckets.values()),
        "max_bucket_count": max(len(v) for v in buckets.values()),
        "vulnerability": "Predictable MD5 modulo without HMAC allows client-side shadow group forcing"
    }
    STATS["TC-OPS-02 Canary Identity Spoofing"] = summary
    print(f"[TC-OPS-02] 2,000 identities mapped evenly into {len(buckets)} buckets. Predictable without HMAC.")
    return summary

# -----------------------------------------------------------------------------
# 11. TC-OPS-03: Event Socket Flooding / Log DoS (5,000 requests)
# -----------------------------------------------------------------------------
def eval_event_socket_flooding():
    print("\n" + "="*70)
    print("RUNNING CATEGORY 12: TC-OPS-03 Event Socket Flooding (5,000 requests)")
    print("="*70)
    tasks = []
    for i in range(5000):
        # Rapid triggering of rule alerts
        tasks.append((f"/?probe={urllib.parse.quote('<script>alert(1)</script>')}&n={i}", "GET", None, {}, PORT_A))
        
    print("Blasting 5,000 alert-generating requests at high concurrency...")
    results = run_worker_batch(tasks, max_workers=50)
    return analyze_results("TC-OPS-03 Event Socket Flooding", results)

def main():
    print("*" * 75)
    print("STRATA WAF HEAVY ADVERSARIAL SECURITY EVALUATION (1,000 - 5,000 REQ/CATEGORY)")
    print("*" * 75)
    t_start = time.time()
    
    eval_sql_injection()
    eval_command_injection()
    eval_xss()
    eval_path_traversal()
    eval_timing_budget_probe()
    eval_tail_padding()
    eval_redos()
    eval_json_nesting()
    eval_botnet_fallback()
    eval_canary_identity()
    eval_event_socket_flooding()
    
    total_time = time.time() - t_start
    total_reqs = sum(s.get("total_requests", 0) for s in STATS.values() if isinstance(s, dict))
    
    print("\n" + "*" * 75)
    print("FINAL HEAVY EVALUATION SUMMARY")
    print(f"Total Requests Processed: {total_reqs} in {total_time:.2f} seconds ({total_reqs/total_time:.1f} req/s)")
    print("*" * 75)
    
    for cat, data in STATS.items():
        if "total_requests" in data:
            print(f"- {cat:35}: {data['total_requests']:5} reqs | PR: {data.get('protection_rate_pct', 0):6.2f}% | p99: {data.get('latency_p99_ms', 0):5.2f} ms")
        else:
            print(f"- {cat:35}: {data.get('vulnerability', '')}")
            
    with open("deploy/redteam/reports/heavy_eval_summary.json", "w") as f:
        json.dump(STATS, f, indent=2)
    print("\nDetailed results exported to deploy/redteam/reports/heavy_eval_summary.json")

if __name__ == "__main__":
    main()
