#!/usr/bin/env python3
"""Measure first and subsequent HTTP requests of real NGINX workers/reloads."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def metrics(path):
    raw = path.read_bytes() if path.exists() else b''
    # Metrics v1: header 64 bytes, worker slot 448 bytes, u64 counters.
    if len(raw) < 512:
        return None
    header = struct.unpack_from('<8s4I', raw)
    if header == (b'\0' * 8, 0, 0, 0, 0):
        return None
    if header != (b'STRMET1\0', 1, 1, 448, 50) or len(raw) != 512:
        raise RuntimeError('unexpected metrics layout or worker count')
    return struct.unpack_from('<50Q', raw, 64)


def until(predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.01)
    raise RuntimeError('worker/metrics readiness timeout')


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run(args):
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    nginx, module, bundle, pub, mkbundle = [Path(p).resolve() for p in
        [args.nginx, args.module, args.bundle, args.pubkey, args.mkbundle]]
    version = struct.unpack_from('<Q', bundle.read_bytes(), 16)[0]
    hot = Path(args.hot_bundle).resolve() if args.hot_bundle else None
    hot_version = struct.unpack_from('<Q', hot.read_bytes(), 16)[0] if hot else None
    if hot and hot_version <= version:
        raise ValueError('hot bundle version must increase')
    metadata = {'scope': 'worker_first_transaction_and_reload_not_cold_host_cache',
                'cpu_budget_us': 10000, 'fail_mode': 'open', 'workers': 1,
                'reloads': args.reloads, 'warm_per_worker': args.warm,
                'request_uri_sha256': hashlib.sha256(args.uri.encode('ascii')).hexdigest(),
                'expected_status': args.expected_status,
                'activation_mode': 'hot_bundle' if hot else 'worker_reload',
                'cpu': args.cpu, 'bundle_version': version,
                'hashes': {str(p): sha(p) for p in [nginx, module, bundle, pub, mkbundle, Path(__file__)]}}
    if hot:
        metadata.update(hot_bundle_sha256=sha(hot), hot_bundle_version=hot_version)
    with tempfile.TemporaryDirectory(prefix='cold-', dir=out) as directory:
        root = Path(directory)
        (root / 'bundles').mkdir()
        (root / 'bundles' / f'bundle-{version}.sbn').write_bytes(bundle.read_bytes())
        if hot:
            (root / 'bundles' / f'bundle-{hot_version}.sbn').write_bytes(hot.read_bytes())
        subprocess.run([str(mkbundle), 'control', '--out', str(root / 'control'),
                        '--generation', '2', '--version', str(version), '--name',
                        f'bundle-{version}.sbn', '--bundle', str(bundle)], check=True, capture_output=True)
        front, backend = port(), port()
        while backend == front:
            backend = port()
        metric = root / 'metrics'
        # Drain the event/counter socket without changing node-side event policy.
        sink = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sink.bind(str(root / 'events.sock'))
        sink.settimeout(.1)
        stop = threading.Event()
        datagrams = []
        reader_errors = []
        def drain():
            while not stop.is_set():
                try:
                    raw = sink.recv(8193)
                    if len(datagrams) >= 4096:
                        raise RuntimeError('datagram bound exceeded')
                    datagrams.append({'length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
                except socket.timeout:
                    continue
                except Exception as error:
                    reader_errors.append(str(error))
                    stop.set()
        reader = threading.Thread(target=drain)
        reader.start()
        config = f'''load_module "{module}";
daemon off;
worker_processes 1;
worker_cpu_affinity {1 << args.cpu:b};
pid "{root}/master.pid";
error_log "{out}/error.log" notice;
events {{ worker_connections 128; }}
http {{
 log_format probe '$pid $strata_time_us $strata_action $strata_bundle_version';
 access_log "{out}/access.log" probe;
 client_body_temp_path "{root}/body";
 proxy_temp_path "{root}/proxy";
 fastcgi_temp_path "{root}/fastcgi";
 uwsgi_temp_path "{root}/uwsgi";
 scgi_temp_path "{root}/scgi";
 strata_control_file "{root}/control";
 strata_bundle_dir "{root}/bundles";
 strata_bundle_pubkey "{pub}";
 strata_node_id cold-worker-probe;
 strata_metrics_file "{metric}";
 strata_event_socket unix:{root}/events.sock;
 server {{ listen 127.0.0.1:{front}; location / {{
  strata on; strata_policy example-api;
  strata_cpu_budget 10ms; strata_fail_mode open;
  add_header X-Probe-Pid $pid always;
  add_header X-Probe-Bundle $strata_bundle_version always;
  proxy_pass http://127.0.0.1:{backend};
 }} }}
 server {{ listen 127.0.0.1:{backend}; location / {{ return 200 'ok'; }} }}
}}
'''
        conf = root / 'nginx.conf'
        conf.write_text(config)
        metadata['configuration_sha256'] = sha(conf)
        (out / 'configuration.txt').write_text(config)
        records = []
        with (out / 'process.log').open('w') as log:
            process = subprocess.Popen([str(nginx), '-p', str(root) + '/', '-c', str(conf)], stdout=log, stderr=log, start_new_session=True)
            try:
                old_pid = 0
                for cycle in range(args.reloads + 1):
                    expected_version = hot_version if hot and cycle else version
                    if cycle:
                        if hot:
                            subprocess.run([str(mkbundle), 'control', '--in-place', '--out', str(root / 'control'),
                                            '--generation', '4', '--version', str(hot_version), '--name',
                                            f'bundle-{hot_version}.sbn', '--bundle', str(hot)], check=True, capture_output=True)
                        else:
                            process.send_signal(signal.SIGHUP)
                    def ready():
                        if process.poll() is not None:
                            raise RuntimeError('NGINX exited; inspect process.log')
                        value = metrics(metric)
                        if not value or value[1] != expected_version:
                            return None
                        if hot and cycle:
                            return value if value[0] == old_pid else None
                        return value if value[0] != old_pid and not Path(f'/proc/{old_pid}').exists() else None
                    current = until(ready)
                    worker_pid = current[0]
                    for index in range(args.warm + 1):
                        before = metrics(metric)
                        start = time.perf_counter_ns()
                        conn = http.client.HTTPConnection('127.0.0.1', front, timeout=5)
                        conn.request('GET', args.uri, headers={'Host': 'api.example.test', 'User-Agent': 'example-client/1', 'Connection': 'close'})
                        response = conn.getresponse()
                        response.read()
                        wall_ns = time.perf_counter_ns() - start
                        observed_pid = int(response.getheader('X-Probe-Pid', '0'))
                        observed_bundle = int(response.getheader('X-Probe-Bundle', '0'))
                        status = response.status
                        conn.close()
                        def completed():
                            value = metrics(metric)
                            return value if value and sum(value[2:6]) == sum(before[2:6]) + 1 and sum(value[12:21]) == sum(before[12:21]) + 1 else None
                        after = until(completed, 2)
                        if after[0] != worker_pid or observed_pid != worker_pid or observed_bundle != expected_version:
                            raise RuntimeError('request reached an unexpected/unready worker')
                        record = {'cycle': cycle, 'worker_pid': worker_pid,
                                  'bundle_version': expected_version,
                                  'phase': 'first' if index == 0 else 'warm', 'index': index,
                                  'status': status, 'wall_ns': wall_ns,
                                  'engine_ns': after[11] - before[11],
                                  'budget_hits': after[10] - before[10],
                                  'fail_open': after[7] - before[7], 'fail_closed': after[8] - before[8]}
                        records.append(record)
                        with (out / "requests.jsonl").open("a") as stream:
                            stream.write(json.dumps(record) + "\n")
                        if status != args.expected_status:
                            raise RuntimeError(f'unexpected response: {status}, expected {args.expected_status}')
                    old_pid = worker_pid
            finally:
                process.send_signal(signal.SIGQUIT) if process.poll() is None else None
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                stop.set()
                reader.join(timeout=2)
                sink.close()
        if reader_errors:
            raise RuntimeError('event drain failed: ' + str(reader_errors))
        (out / 'requests.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records))
        (out / 'datagrams.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in datagrams))
        summary = {}
        for phase in ['first', 'warm']:
            rows = [r for r in records if r['phase'] == phase]
            times = sorted(r['engine_ns'] for r in rows)
            summary[phase] = {'requests': len(rows), 'engine_ns_min': min(times),
                              'engine_ns_p50': times[len(times) // 2], 'engine_ns_max': max(times),
                              'budget_hits': sum(r['budget_hits'] for r in rows),
                              'fail_open': sum(r['fail_open'] for r in rows)}
        assert len(records) == (args.reloads + 1) * (args.warm + 1)
        metadata['datagrams_received'] = len(datagrams)
        (out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
        (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['nginx', 'module', 'bundle', 'pubkey', 'mkbundle', 'out']:
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--reloads', type=int, default=10)
    parser.add_argument('--warm', type=int, default=20)
    parser.add_argument('--cpu', type=int, default=6)
    parser.add_argument('--uri', default='/probe?q=ordinary')
    parser.add_argument('--expected-status', type=int, choices=[200, 403], default=200)
    parser.add_argument('--hot-bundle', help='with --reloads 1, activate a newer signed bundle without restarting the worker')
    options = parser.parse_args()
    if not 1 <= options.reloads <= 100 or not 1 <= options.warm <= 100 or not 0 <= options.cpu <= 1023:
        parser.error('bounded reload/warm/cpu values required')
    if not options.uri.startswith('/') or len(options.uri) > 4096 or not all(33 <= ord(c) <= 126 for c in options.uri):
        parser.error('URI must be a bounded ASCII origin-form path without spaces/control bytes')
    if options.hot_bundle and options.reloads != 1:
        parser.error('hot bundle mode requires --reloads 1')
    run(options)
