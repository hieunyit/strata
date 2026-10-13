#!/usr/bin/env bash
# W09-Q-01: the benchmark matrix (bench.sh), each cell RUNS times, as JSON
# lines in build/bench/<version>.jsonl, then the Markdown table
# (bench-report.py) on stdout.
# Usage: bench-all.sh <nginx-version> [seconds] [runs]  (dev image)
set -euo pipefail
version="${1:?usage: bench-all.sh <nginx-version> [seconds] [runs]}"
seconds="${2:-30}"
runs="${3:-3}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
out="$root/build/bench/$version.jsonl"
mkdir -p "$(dirname "$out")"
: > "$out"
# throughput: 64 connections saturate the two workers; latency overhead: 4
# connections, no queueing, so p50/p99 are the per-request cost
cell() { # scenario mode connections
    for _ in $(seq "$runs"); do
        "$here/bench.sh" "$version" "$1" "$2" "$seconds" "$3" |
            python3 -c "import json,sys; r=json.loads(sys.stdin.read()); r['conns']=$3; r['seconds']=$seconds; print(json.dumps(r))" |
            tee -a "$out" >&2
    done
}
for scenario in small 64k 1m h2; do
    for mode in off p01 full; do
        cell "$scenario" "$mode" 64
        [ "$scenario" = h2 ] || cell "$scenario" "$mode" 4
    done
done
cell small events 64
python3 "$here/bench-report.py" "$version" "$out"
