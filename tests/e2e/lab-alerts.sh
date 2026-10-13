#!/usr/bin/env bash
# W10-Q-01 end to end on a running lab (make lab-up): the alert rules of
# deploy/monitoring/alerts.yml run in vmalert against what VictoriaMetrics
# scrapes from the agents and the control plane.
#
#   1. Healthy lab: StrataAgentDown, StrataAgentDisconnected,
#      StrataDgramQueueTooShort and StrataControlPlaneDown are not firing
#      (the agents run with net.unix.max_dgram_qlen = 8192).
#   2. agent-1 is stopped: StrataAgentDown fires for agent-1, not agent-2.
#   3. agent-1 is started again: the alert resolves.
#
# VMALERT (default http://127.0.0.1:18880) and LAB_PROJECT_DIR allow running
# it against staging.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
lab="${LAB_PROJECT_DIR:-$here/../../deploy/lab}"
vmalert="${VMALERT:-http://127.0.0.1:18880}"
compose=(docker compose -f "$lab/compose.yaml" --env-file "$lab/.state/env")
fail() { echo "lab-alerts: FAIL: $*" >&2; exit 1; }
step() { echo "lab-alerts: $*"; }

# firing <alertname> [instance]: the alert is firing (for that instance)
firing() {
    curl -fsS "$vmalert/api/v1/alerts" | python3 -c '
import json, sys
name, inst = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else None)
alerts = json.load(sys.stdin)["data"]["alerts"]
sys.exit(0 if any(a["name"] == name and a["state"] == "firing"
                  and (inst is None or a["labels"].get("instance") == inst) for a in alerts) else 1)
' "$@"
}
wait_for() { # seconds description command...
    local limit=$1 what=$2 start=$SECONDS; shift 2
    until "$@"; do
        [ $((SECONDS - start)) -lt "$limit" ] || fail "$what not within ${limit}s"
        sleep 5
    done
    step "$what after $((SECONDS - start))s"
}
not_firing() { ! firing "$@"; }

curl -fsS "$vmalert/api/v1/rules" | grep -q StrataAgentDown || fail "vmalert has no Strata rules"
# the rules need a few evaluations and scrapes before 'up' is known
sleep 20
for a in StrataAgentDown StrataAgentDisconnected StrataDgramQueueTooShort StrataControlPlaneDown; do
    if firing "$a"; then fail "$a fires on a healthy lab"; fi
done
step "healthy lab: no agent or control plane alert firing"

trap '"${compose[@]}" start agent-1 >/dev/null 2>&1 || true' EXIT
"${compose[@]}" stop agent-1 >/dev/null
step "agent-1 stopped"
# 2 minutes 'for', 15 s scrapes and evaluations
wait_for 300 "StrataAgentDown firing for agent-1" firing StrataAgentDown agent-1:9469
if firing StrataAgentDown agent-2:9469; then fail "StrataAgentDown fires for agent-2, which runs"; fi

"${compose[@]}" start agent-1 >/dev/null
trap - EXIT
step "agent-1 started"
wait_for 180 "StrataAgentDown resolved" not_firing StrataAgentDown
echo "lab-alerts: PASS"
