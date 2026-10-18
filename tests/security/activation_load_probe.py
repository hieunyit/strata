#!/usr/bin/env python3
"""Measure real HTTP latency across one signed hot-bundle activation under paced load."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

from cold_worker_probe import metrics, port, until


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def percentiles(rows):
    def summary(key):
        values = sorted(r[key] for r in rows if r.get(key) is not None)
        return {f'p{p}': values[max(0, math.ceil(len(values) * p / 100) - 1)] if values else None for p in (50, 99, 100)}
    return {'requests': len(rows), 'wall_ns': summary('wall_ns'), 'scheduled_ns': summary('scheduled_ns'), 'dispatch_delay_ns': summary('dispatch_delay_ns'), 'engine_us': summary('engine_us'),
            'errors': sum(r.get('error') is not None or r.get('status') != 200 or r.get('action') != 'allow' for r in rows)}


def memory(pid):
    values = {}
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        key, _, value = line.partition(':')
        if key in ('VmRSS', 'VmHWM'):
            values[key] = int(value.split()[0])
    if len(values) != 2:
        raise RuntimeError('worker memory metrics missing')
    return values


def run(a):
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    paths = {k: Path(getattr(a, k)).resolve() for k in ('nginx', 'module', 'bundle', 'hot_bundle', 'pubkey', 'mkbundle')}
    versions = {k: struct.unpack_from('<Q', paths[k].read_bytes(), 16)[0] for k in ('bundle', 'hot_bundle')}
    if versions['hot_bundle'] <= versions['bundle']:
        raise ValueError('hot bundle version must increase')
    metadata = {'scope': 'one-worker-paced-HTTP-one-hot-activation-not-production-SLO', 'activation': not a.steady,
                'rate_per_second': a.rate, 'seconds': a.seconds, 'clients': a.clients, 'worker_cpu': a.cpu,
                'driver_cpus': sorted(os.sched_getaffinity(0)), 'cpu_budget_us': 10000, 'fail_mode': 'open',
                'versions': versions, 'hashes': {k: digest(p) for k, p in paths.items()}, 'source_sha256': digest(__file__)}
    records, sink_errors, controls = [], [], {}
    stop = threading.Event()
    with tempfile.TemporaryDirectory(prefix='activation-', dir=out) as directory:
        root = Path(directory)
        (root / 'bundles').mkdir()
        for k, v in versions.items():
            (root / 'bundles' / f'bundle-{v}.sbn').write_bytes(paths[k].read_bytes())
        def publish(v, generation, inplace=False):
            cmd = [str(paths['mkbundle']), 'control', '--out', str(root / 'control'), '--generation', str(generation),
                   '--version', str(v), '--name', f'bundle-{v}.sbn', '--bundle', str(root / 'bundles' / f'bundle-{v}.sbn')]
            if inplace:
                cmd += ['--in-place']
            subprocess.run(cmd, check=True, capture_output=True, timeout=5)
        publish(versions['bundle'], 2)
        sink = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sink.bind(str(root / 'events.sock')); sink.settimeout(.1)
        datagrams = [0]
        def drain():
            while not stop.is_set():
                try:
                    raw = sink.recv(8193)
                    if len(raw) > 8192 or datagrams[0] >= 10000:
                        raise RuntimeError('event datagram limit exceeded')
                    datagrams[0] += 1
                except socket.timeout:
                    continue
                except Exception as e:
                    sink_errors.append(str(e)); return
        front, back = port(), port()
        while back == front:
            back = port()
        conf = f'''load_module "{paths['module']}";
daemon off;
worker_processes 1;
worker_cpu_affinity {1 << a.cpu:b};
pid "{root}/master.pid";
error_log "{out}/error.log" notice;
events {{ worker_connections 256; }}
http {{
 log_format probe '$pid $strata_action $strata_time_us $strata_bundle_version';
 access_log "{out}/access.log" probe;
 client_body_temp_path "{root}/body";
 proxy_temp_path "{root}/proxy";
 fastcgi_temp_path "{root}/fastcgi";
 uwsgi_temp_path "{root}/uwsgi";
 scgi_temp_path "{root}/scgi";
 strata_control_file "{root}/control";
 strata_bundle_dir "{root}/bundles";
 strata_bundle_pubkey "{paths['pubkey']}";
 strata_metrics_file "{root}/metrics";
 strata_node_id activation-probe;
 strata_event_socket unix:{root}/events.sock;
 server {{ listen 127.0.0.1:{front}; location / {{
  strata on; strata_policy example-api; strata_cpu_budget 10ms; strata_fail_mode open;
  add_header X-Probe-Pid $pid always;
  add_header X-Probe-Bundle $strata_bundle_version always;
  add_header X-Probe-Action $strata_action always;
  add_header X-Probe-Time $strata_time_us always;
  proxy_pass http://127.0.0.1:{back};
 }} }}
 server {{ listen 127.0.0.1:{back}; location / {{ return 200 'ok'; }} }}
}}
'''
        (out / 'configuration.txt').write_text(conf)
        (root / 'nginx.conf').write_text(conf)
        reader = threading.Thread(target=drain); reader.start()
        process = None
        try:
            with (out / 'process.log').open('w') as log:
                process = subprocess.Popen([str(paths['nginx']), '-p', str(root) + '/', '-c', str(root / 'nginx.conf')], stdout=log, stderr=log, start_new_session=True)
                def ready():
                    if process.poll() is not None:
                        raise RuntimeError('NGINX exited before readiness')
                    m = metrics(root / 'metrics')
                    return m if m and m[1] == versions['bundle'] else None
                before = until(ready)
                worker = before[0]
                metadata['memory_before_kib'] = memory(worker)
                start = time.monotonic_ns()
                def request(index, due):
                    sent = time.monotonic_ns()
                    row = {'index': index, 'due_ns': due - start, 'sent_ns': sent - start}
                    conn = http.client.HTTPConnection('127.0.0.1', front, timeout=3)
                    try:
                        conn.request('GET', '/probe?q=ordinary', headers={'Host': 'api.example.test', 'User-Agent': 'example-client/1', 'Connection': 'close'})
                        response = conn.getresponse(); body = response.read(1024)
                        row.update(status=response.status, action=response.getheader('X-Probe-Action'),
                                   bundle=int(response.getheader('X-Probe-Bundle', '0')), pid=int(response.getheader('X-Probe-Pid', '0')),
                                   engine_us=int(response.getheader('X-Probe-Time', '-1')), body_ok=body == b'ok')
                    except Exception as e:
                        row['error'] = type(e).__name__
                    finally:
                        row['wall_ns'] = time.monotonic_ns() - sent
                        row['dispatch_delay_ns'] = sent - due
                        row['scheduled_ns'] = row['wall_ns'] + row['dispatch_delay_ns']
                        conn.close()
                    return row
                def activate():
                    if stop.wait(a.seconds / 2):
                        return
                    try:
                        controls['write_start_ns'] = time.monotonic_ns() - start
                        publish(versions['hot_bundle'], 4, True)
                        controls['write_end_ns'] = time.monotonic_ns() - start
                    except Exception as e:
                        sink_errors.append('publisher: ' + type(e).__name__)
                publisher = threading.Thread(target=activate) if not a.steady else None
                if publisher:
                    publisher.start()
                futures = []
                with ThreadPoolExecutor(max_workers=a.clients) as executor:
                    for index in range(a.seconds * a.rate):
                        due = start + index * 1000000000 // a.rate
                        wait = (due - time.monotonic_ns()) / 1e9
                        if wait > 0:
                            time.sleep(wait)
                        # Bound queued work. A driver miss is recorded, never counted as a completed HTTP request.
                        pending = sum(not f.done() for f in futures[-a.clients * 2:])
                        if pending >= a.clients * 2:
                            records.append({'index': index, 'due_ns': due - start, 'error': 'driver_queue_full'})
                            continue
                        futures.append(executor.submit(request, index, due))
                    records.extend(f.result() for f in futures)
                if publisher:
                    publisher.join(timeout=6)
                    if publisher.is_alive():
                        raise RuntimeError('publisher failed to stop')
                after = metrics(root / 'metrics')
                if not after or after[0] != worker:
                    raise RuntimeError('worker changed or metrics missing')
                metadata['memory_after_kib'] = memory(worker)
                metadata.update(load_elapsed_ns=time.monotonic_ns() - start, process_exit_before_stop=process.poll(), worker_pid=worker, final_bundle=after[1], datagrams=datagrams[0],
                                metrics={'requests': sum(after[2:6]) - sum(before[2:6]), 'budget_hits': after[10] - before[10],
                                         'fail_open': after[7] - before[7], 'fail_closed': after[8] - before[8]})
        finally:
            if process and process.poll() is None:
                process.send_signal(signal.SIGQUIT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
            stop.set(); reader.join(timeout=2); sink.close()
    records.sort(key=lambda r: r['index'])
    completed = [r for r in records if r.get('status') is not None]
    switch = controls.get('write_start_ns', a.seconds * 500000000)
    new_rows = [r for r in completed if r.get('bundle') == versions['hot_bundle']]
    first_new = min((r['sent_ns'] + r['wall_ns'] for r in new_rows), default=None)
    transition_end = max(switch + 1000000000, (first_new or switch) + 500000000)
    controls['first_new_response_ns'] = first_new
    summary = {'offered': a.seconds * a.rate, 'records': len(records), 'completed_http': len(completed), 'actual_completed_rps': len(completed) * 1e9 / metadata['load_elapsed_ns'], 'all': percentiles(records),
               'before': percentiles([r for r in completed if r['sent_ns'] >= 1000000000 and r['sent_ns'] + r['wall_ns'] < switch - 1000000000]),
               'transition': percentiles([r for r in completed if r['sent_ns'] <= transition_end and r['sent_ns'] + r['wall_ns'] >= switch - 1000000000]),
               'after': percentiles([r for r in completed if r['sent_ns'] > transition_end]), 'control': controls}
    failures = []
    if len(completed) != a.seconds * a.rate or metadata['metrics']['requests'] != len(completed): failures.append('incomplete/offered/metrics mismatch')
    if any(r.get('status') != 200 or r.get('action') != 'allow' or not r.get('body_ok') or r.get('pid') != metadata['worker_pid'] or r.get('engine_us', -1) < 0 for r in records): failures.append('HTTP/verdict/worker error')
    if any(metadata['metrics'][k] for k in ('budget_hits', 'fail_open', 'fail_closed')): failures.append('inspection incomplete')
    if not a.steady and (metadata['final_bundle'] != versions['hot_bundle'] or not any(r.get('bundle') == versions['hot_bundle'] for r in completed)): failures.append('activation not observed')
    if metadata['process_exit_before_stop'] is not None: failures.append('NGINX exited during load')
    errors = (out / 'error.log').read_text()
    if any(marker in errors for marker in ('[alert]', '[crit]', '[emerg]', 'exited on signal')): failures.append('NGINX alert/crash')
    if sink_errors: failures += sink_errors
    summary['failures'] = failures
    for name, value in [('metadata', metadata), ('summary', summary)]: (out / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')
    (out / 'requests.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records))
    print(json.dumps(summary))
    return 1 if failures else 0


def arguments():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('nginx', 'module', 'bundle', 'hot-bundle', 'pubkey', 'mkbundle', 'out'): p.add_argument('--' + key, required=True)
    p.add_argument('--rate', type=int, default=200); p.add_argument('--seconds', type=int, default=12)
    p.add_argument('--clients', type=int, default=8); p.add_argument('--cpu', type=int, default=6)
    p.add_argument('--steady', action='store_true')
    a = p.parse_args()
    if not 1 <= a.rate <= 500 or not 6 <= a.seconds <= 30 or a.rate * a.seconds > 10000 or not 1 <= a.clients <= 16 or not 0 <= a.cpu <= 1023:
        p.error('bounded rate/seconds/clients/cpu required')
    return a


if __name__ == '__main__':
    raise SystemExit(run(arguments()))
