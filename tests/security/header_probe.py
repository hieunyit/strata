#!/usr/bin/env python3
"""Loopback-only NGINX probe with an in-memory SQLite SQLi oracle.

Outputs every measured HTTP attempt and separate WAF/HTTP/oracle evidence.
It does not test botnet fallback, canary hashing, event delivery or browser XSS.
"""
import argparse
from collections import Counter
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, quote, unquote, urlsplit

MARKER = 'STRATA_SQL_ORACLE'


class Oracle(BaseHTTPRequestHandler):
    def do_GET(self):
        target = urlsplit(self.path)
        query = parse_qs(target.query)
        expression = query.get('id', ['1'])[0]
        if target.path == '/header-sql':
            expression = unquote(self.headers.get('X-Example-Filter', '1'))
        db = sqlite3.connect(':memory:')
        try:
            db.executescript("CREATE TABLE items(id INTEGER, marker TEXT); INSERT INTO items VALUES(1,'public');")
            # Intentionally vulnerable fixture, isolated from any real DB/files.
            rows = db.execute('SELECT marker FROM items WHERE id = ' + expression).fetchall()
            status, result = 200, {'rows': rows}
        except sqlite3.Error:
            status, result = 400, {'error': 'fixture query rejected'}
        finally:
            db.close()
        raw = json.dumps(result).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


def request(port, uri, headers):
    start = time.perf_counter()
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    try:
        conn.request('GET', uri, headers={'Host': 'api.example.test', **headers})
        response = conn.getresponse()
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('response exceeds 64 KiB')
        try:
            oracle = [MARKER] in json.loads(raw).get('rows', [])
        except (ValueError, AttributeError):
            oracle = False
        return {'status': response.status, 'latency_ms': (time.perf_counter()-start)*1000,
                'action': response.getheader('X-Probe-Action'),
                'rules': response.getheader('X-Probe-Rules'),
                'event_id': response.getheader('X-Probe-Event'), 'oracle': oracle}
    except (OSError, ValueError, http.client.HTTPException) as error:
        return {'status': None, 'latency_ms': (time.perf_counter()-start)*1000,
                'transport_error': type(error).__name__, 'oracle': None}
    finally:
        conn.close()


def classify(case, baseline, result):
    if baseline['status'] is None or result['status'] is None:
        return 'transport_error'
    if case.get('oracle') and not baseline['oracle']:
        return 'invalid_attack_oracle'
    if result.get('action') == 'error':
        return 'inspection_error_reached' if result['status'] == 200 else 'inspection_error_rejected'
    if result.get('action') == 'block' and result['status'] == 403:
        return 'signature_block' if case['malicious'] else 'benign_block'
    if result['status'] >= 400:
        return 'http_rejection_without_signature_attribution'
    if result['oracle'] and case.get('oracle'):
        return 'backend_sql_oracle_reached'
    return 'reached_without_exploit_proof' if case['malicious'] else 'benign_pass'


def cases():
    sql = "-1 UNION SELECT '" + MARKER + "'--"
    return [
        {'id': 'query-sql-control', 'uri': '/query-sql?id='+quote(sql), 'headers': {}, 'malicious': True, 'oracle': True},
        {'id': 'header-sql-raw', 'uri': '/header-sql', 'headers': {'X-Example-Filter': sql}, 'malicious': True, 'oracle': True},
        {'id': 'header-sql-urlencoded', 'uri': '/header-sql', 'headers': {'X-Example-Filter': quote(sql)}, 'malicious': True, 'oracle': True},
        {'id': 'header-xss', 'uri': '/metadata', 'headers': {'X-Example-Text': '<script>alert(1)</script>'}, 'malicious': True, 'oracle': False},
        {'id': 'header-xss-urlencoded', 'uri': '/metadata', 'headers': {'X-Example-Text': '%3Cscript%3Ealert(1)%3C/script%3E'}, 'malicious': True, 'oracle': False},
        {'id': 'ordinary-filter', 'uri': '/header-sql', 'headers': {'X-Example-Filter': '1'}, 'malicious': False},
        {'id': 'ordinary-browser', 'uri': '/metadata', 'headers': {'Accept': 'text/html,application/xhtml+xml', 'Accept-Language': 'en-US,en;q=0.8', 'Sec-CH-UA': '"Chromium";v="122"'}, 'malicious': False},
        {'id': 'ordinary-jwt', 'uri': '/metadata', 'headers': {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJleGFtcGxlIn0.signature'}, 'malicious': False},
        {'id': 'ordinary-etag', 'uri': '/metadata', 'headers': {'If-None-Match': 'W/"example-v1"', 'X-Example-Text': 'select the best union membership plan'}, 'malicious': False},
        {'id': 'ordinary-trace', 'uri': '/metadata', 'headers': {'traceparent': '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01', 'Forwarded': 'for=192.0.2.4;proto=https;host=api.example.test'}, 'malicious': False},
    ]


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as file:
        for chunk in iter(lambda: file.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def run(args):
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    inputs = {key: Path(getattr(args, key)).resolve() for key in ('nginx', 'module', 'mkbundle', 'bundle', 'pubkey')}
    for path in [out, *inputs.values()]:
        if any(char in str(path) for char in ('"', '$', ';', '\n', '\r')):
            raise ValueError('unsupported configuration path')
    metadata = {key+'_sha256': sha(value) for key, value in inputs.items()}
    metadata.update(harness_sha256=sha(__file__), cases_sha256=hashlib.sha256(json.dumps(cases(),sort_keys=True).encode()).hexdigest(), scope='serial_loopback_http_and_sqlite_oracle', policy=args.policy,
                    rounds=args.rounds, cpu_budget_us=10000, fail_mode='open',
                    not_tested=['botnet fallback', 'canary hashing', 'event delivery', 'browser XSS'])
    server = ThreadingHTTPServer(('127.0.0.1', 0), Oracle)
    backend = threading.Thread(target=server.serve_forever, daemon=True)
    backend.start()
    try:
        with tempfile.TemporaryDirectory(prefix='probe-', dir=out) as work:
            root = Path(work)
            (root/'bundles').mkdir()
            (root/'logs').mkdir()
            (root/'bundles'/'bundle-1.sbn').write_bytes(inputs['bundle'].read_bytes())
            subprocess.run([str(inputs['mkbundle']), 'control', '--out', str(root/'control'), '--generation', '2', '--version', '1', '--name', 'bundle-1.sbn', '--bundle', str(inputs['bundle'])], check=True, capture_output=True)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            config = f'''load_module "{inputs['module']}";
daemon off;
worker_processes 2;
pid "{root}/nginx.pid";
error_log "{out}/nginx-error.log" notice;
events {{ worker_connections 128; }}
http {{
 access_log "{out}/nginx-access.log";
 client_body_temp_path "{root}/body";
 proxy_temp_path "{root}/proxy";
 fastcgi_temp_path "{root}/fastcgi";
 uwsgi_temp_path "{root}/uwsgi";
 scgi_temp_path "{root}/scgi";
 strata_control_file "{root}/control";
 strata_bundle_dir "{root}/bundles";
 strata_bundle_pubkey "{inputs['pubkey']}";
 strata_node_id header-probe;
 strata_metrics_file "{root}/metrics";
 server {{
  listen 127.0.0.1:{port};
  location / {{
   strata on;
   strata_policy {args.policy};
   strata_cpu_budget 10ms;
   strata_fail_mode open;
   add_header X-Probe-Action $strata_action always;
   add_header X-Probe-Rules $strata_rules always;
   add_header X-Probe-Event $strata_block_id always;
   proxy_pass http://127.0.0.1:{server.server_port};
  }}
 }}
}}
'''
            conf = root/'nginx.conf'
            conf.write_text(config)
            metadata['configuration_sha256'] = sha(conf)
            (out/'configuration.txt').write_text(config)
            with (out/'process.log').open('w') as log:
                process = subprocess.Popen([str(inputs['nginx']), '-p', str(root)+'/', '-c', str(conf)], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic()+10
                    while True:
                        if process.poll() is not None:
                            raise RuntimeError('NGINX exited; inspect process.log')
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                                break
                        except OSError:
                            if time.monotonic() > deadline:
                                raise RuntimeError('NGINX readiness timeout')
                            time.sleep(.05)
                    counts, statuses = Counter(), Counter()
                    measured = 0
                    with (out/'requests.jsonl').open('w') as records:
                        for attempt in range(args.rounds):
                            for case in cases():
                                base = request(server.server_port, case['uri'], case['headers'])
                                result = request(port, case['uri'], case['headers'])
                                classification = classify(case, base, result)
                                counts[classification] += 1
                                statuses[str(result['status']) if result['status'] is not None else 'transport_error'] += 1
                                measured += 1
                                records.write(json.dumps({'case': case['id'], 'attempt': attempt, 'baseline': base, 'proxy': result, 'classification': classification})+'\n')
                    assert sum(statuses.values()) == sum(counts.values()) == measured > 0
                    valid = counts['invalid_attack_oracle'] == counts['transport_error'] == 0
                    summary = {'valid_measurement': valid, 'measured_pairs': measured, 'measured_http_attempts': measured*2, 'proxy_status_counts': dict(statuses), 'classifications': dict(counts)}
                    (out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
                    (out/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
                    print(json.dumps(summary))
                    if not valid:
                        raise RuntimeError('measurement incomplete; inspect requests.jsonl')
                finally:
                    if process.poll() is None:
                        process.send_signal(signal.SIGQUIT)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
    finally:
        server.shutdown()
        server.server_close()
        backend.join(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('nginx', 'module', 'mkbundle', 'bundle', 'pubkey', 'out'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--policy', default='example-api')
    parser.add_argument('--rounds', type=int, default=1)
    arguments = parser.parse_args()
    if not 1 <= arguments.rounds <= 100:
        parser.error('rounds must be 1..100')
    if not arguments.policy or not all(c.isascii() and (c.isalnum() or c in '._-') for c in arguments.policy) or len(arguments.policy)>55:
        parser.error('invalid policy name')
    run(arguments)
