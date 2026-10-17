"""Linux-only offline C ABI process resource comparison; not NGINX RSS/SLO."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            value.update(chunk)
    return value.hexdigest()

out = Path('build/l3-cache-resources')
out.mkdir(exist_ok=True)
bundle = 'build/current-pack/header-v4.sbn'
public = 'connectors/nginx/t/fixtures/bundle.pub'
with (out / 'resources.jsonl').open('w') as log:
    for index, label in enumerate(['baseline', 'prepared', 'prepared', 'baseline']):
        binary = 'build/l3-cold-profile-bin' if label == 'baseline' else 'target/release/examples/cold_profile'
        argv = ['taskset', '-c', '9', binary, bundle, public] + ([] if label == 'baseline' else ['--prepare'])
        with (out / f'{index}-{label}.jsonl').open('w') as stdout:
            start = time.monotonic()
            process = subprocess.Popen(argv, stdout=stdout)
            deadline = start + 30
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    break
                if time.monotonic() >= deadline:
                    process.kill()
                    os.wait4(process.pid, 0)
                    raise RuntimeError('diagnostic process timeout')
                time.sleep(.01)
            process.returncode = os.waitstatus_to_exitcode(status)
            if process.returncode:
                raise RuntimeError(f'diagnostic exit {process.returncode}')
        record = {'index': index, 'label': label, 'argv': argv,
                  'elapsed_s': time.monotonic() - start, 'maxrss_kib': usage.ru_maxrss,
                  'user_cpu_s': usage.ru_utime, 'system_cpu_s': usage.ru_stime,
                  'binary_sha256': digest(binary),
                  'bundle_sha256': digest(bundle)}
        log.write(json.dumps(record) + '\n')
        log.flush()
        print(json.dumps(record))
