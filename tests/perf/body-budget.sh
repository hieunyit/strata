#!/usr/bin/env bash
# Engine-only generated workload. No policy/default changes or remote services.
# Run inside deploy/dev/run.sh; bundle must be signed with the supplied public key.
set -euo pipefail
bundle=${1:?body-budget.sh BUNDLE PUBKEY OUTDIR}
pubkey=${2:?public key required}
out=${3:?output directory required}
iterations=${ITERATIONS:-100}
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
mkdir -p "$out"
cargo build --release -p strata-eval --bin strata-bench
python3 - "$bundle" "$pubkey" "$out/metadata.json" <<'PY'
import hashlib,json,pathlib,subprocess,sys,platform
files={n:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for n,p in zip(['bundle_sha256','pubkey_sha256','binary_sha256'],sys.argv[1:3]+['target/release/strata-bench'])}
files.update(source_head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 source_diff_sha256=hashlib.sha256(subprocess.check_output(['git','diff','HEAD','--','engine'])).hexdigest(),
 platform=platform.platform(),kind='engine_serial_generated_workload')
pathlib.Path(sys.argv[3]).write_text(json.dumps(files,indent=2)+'\n')
PY
for budget in 10000 0; do
    target/release/strata-bench --bundle "$bundle" --pubkey "$pubkey" \
        --iterations "$iterations" --budget-us "$budget" > "$out/budget-$budget.jsonl" 2> "$out/budget-$budget.log"
done
for warm in no yes; do
    flags=()
    if [ "$warm" = yes ]; then flags+=(--warm); fi
    target/release/strata-bench --bundle "$bundle" --pubkey "$pubkey" \
        --only small --cold 10 --budget-us 10000 "${flags[@]}" > "$out/cold-$warm.jsonl" 2> "$out/cold-$warm.log"
done
