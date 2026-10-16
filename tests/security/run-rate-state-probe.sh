#!/usr/bin/env bash
# Run inside the dev image. Reads one pinned prototype; does not change it.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=build/m3-rate-measurement
source_commit=95246eb19c2af79642e602336641952c43ecf03e
mkdir -p "$out"
git show "$source_commit:engine/src/ratelimit.rs" > "$out/prototype.rs"
rustc --edition=2024 -D warnings -O tests/security/rate_state_probe.rs -o "$out/probe"
taskset -c 6-10 "$out/probe" > "$out/pressure.jsonl"
taskset -c 6 "$out/probe" --bench > "$out/bench.jsonl"
python3 - <<'PY'
from pathlib import Path
import datetime,hashlib,json,subprocess
out=Path('build/m3-rate-measurement')
paths=[out/'prototype.rs',Path('tests/security/rate_state_probe.rs'),Path('tests/security/run-rate-state-probe.sh'),out/'probe']
metadata={'prototype_commit':'95246eb19c2af79642e602336641952c43ecf03e',
 'source_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
 'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),
 'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'pressure_cpus':'6-10','bench_cpu':'6','scope':'unmodified_standalone_prototype_no_NGINX_enforcement',
 'user_decision':'measurement_only_no_saturation_behavior_change'}
(out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
for p in [out/'pressure.jsonl',out/'bench.jsonl']:
 rows=[json.loads(line) for line in p.read_text().splitlines()]
 assert len(rows)==(6 if 'pressure' in p.name else 5),rows
 print(p.read_text(),end='')
print('Measurement complete; vulnerability observations are not a security PASS.')
PY
