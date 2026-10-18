#!/usr/bin/env bash
# deploy/redteam/run-eval.sh
# Automated Red Team Evaluation Runner (docs/plan/redteam-plan.md)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

echo "=== [1/4] Checking and starting Red Team Lab Stack ==="
docker compose -f "$HERE/compose.yaml" up -d --wait

echo "=== [2/4] Running GoTestWAF Automated Benchmark Suite ==="
mkdir -p "$HERE/reports"
chmod 777 "$HERE/reports" 2>/dev/null || true

docker run --rm --network host \
    -v "$HERE/reports:/reports" \
    wallarm/gotestwaf:latest \
    --url "http://127.0.0.1:48080/" \
    --wafName "Strata-ProfileA" \
    --noEmailReport \
    --reportPath /reports \
    --reportName "gotestwaf-eval" \
    --testSet owasp || true

echo "=== [3/4] Running 10 Adversarial Test Specifications ==="
python3 "$HERE/eval/run_scenarios.py"

echo "=== [4/4] Evaluation Complete. Results in deploy/redteam/reports/ ==="
ls -la "$HERE/reports/"
