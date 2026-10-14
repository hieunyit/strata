#!/usr/bin/env bash
# W11-G1-01 on the lab (make lab-up) with the real agent and NGINX: the node
# fallback forces every policy into shadow when the block rate jumps.
#
#   1. Baseline: about 60 req/s on node-1 (NGINX 1.30.5), clean, for
#      the 12 warm-up intervals of 5 s and a little more. The test attack
#      is blocked (403).
#   2. Spike: 50% attacks. Within 6 s of the first spike interval closing,
#      the attack passes (200: shadow) on node-1; node-2 still blocks.
#      strata_agent_fallback_triggers_total{reason="block_rate"} grows.
#   3. clearForceShadow on node-1: it blocks again.
#
# Usage: tests/e2e/lab-fallback.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
lab="$here/../../deploy/lab"
# shellcheck disable=SC1091
. "$lab/.state/env"
cp=http://127.0.0.1:18090
attack='/files/%2e%2e/etc/passwd'
fail() { echo "lab-fallback: FAIL: $*" >&2; exit 1; }
step() { echo "lab-fallback $(date -u +%H:%M:%S): $*"; }
token() {
    curl -fsS http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token \
        -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
        -d username=lab-operator --data-urlencode "password=$LAB_OPERATOR_PASSWORD" |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
api() { curl -fsS -H "Authorization: Bearer $(token)" -H 'Content-Type: application/json' "$@"; }
code() { curl -s --path-as-is -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' "http://127.0.0.1:$1$2"; }
triggers() {
    docker exec strata-lab-agent-1-1 curl -s 127.0.0.1:9469/metrics |
        awk '/^strata_agent_fallback_triggers_total\{reason="block_rate"\}/ {print $2} END {}' | head -1
}
# load <seconds> <attacks per 100>: about 60 req/s to node-1, in 6 parallel loops
load() {
    local until=$((SECONDS + $1)) pct=$2
    for w in 1 2 3 4 5 6; do
        (
            i=0
            while [ $SECONDS -lt $until ]; do
                i=$((i + 1))
                if [ $((RANDOM % 100)) -lt "$pct" ]; then p=$attack; else p="/items?id=$w-$i"; fi
                curl -s --path-as-is -o /dev/null -m 2 -H 'Host: api.example.test' "http://127.0.0.1:18080$p"
                sleep 0.1
            done
        ) &
    done
    wait
}

[ "$(code 18080 "$attack")" = 403 ] || fail "node-1 does not block before the test (already in shadow?)"
node1=$(api "$cp/v1/nodes" | python3 -c 'import json,sys; print([n["id"] for n in json.load(sys.stdin)["nodes"] if n.get("proxy_version")=="1.30.5" and not n.get("revoked") and n.get("online")][0])')
# the agent learns from its start: restart it so the warm-up is this baseline
docker restart strata-lab-agent-1-1 >/dev/null
until docker exec strata-lab-agent-1-1 curl -sf 127.0.0.1:9469/metrics >/dev/null 2>&1; do sleep 1; done
before=$(triggers); before=${before:-0}
step "1. baseline (clean) for 75 s on node-1 ($node1)"
# clean: with ~1% attacks at this volume, chance alone trips the fallback (#65)
load 75 0
[ "$(code 18080 "$attack")" = 403 ] || fail "node-1 fell back during the baseline"
step "2. spike: 50% attacks"
start=$SECONDS
load 15 50 &
spike=$!
until [ "$(code 18080 "$attack")" = 200 ]; do
    [ $((SECONDS - start)) -lt 16 ] || fail "node-1 still blocks 16 s into the spike"
    sleep 0.2
done
t=$((SECONDS - start))
wait $spike
[ "$(code 18081 "$attack")" = 403 ] || fail "node-2 stopped blocking too"
after=$(triggers)
[ "${after:-0}" != "$before" ] || fail "fallback trigger counter did not move ($before)"
step "2. node-1 in shadow ${t} s after the spike started (spike detected at the first 5 s interval end + at most 1 s), node-2 still blocks, triggers $before → $after"
api -X POST "$cp/v1/nodes:clearForceShadow" -d "{\"node_id\":\"$node1\"}" >/dev/null
start=$SECONDS
until [ "$(code 18080 "$attack")" = 403 ]; do
    [ $((SECONDS - start)) -lt 15 ] || fail "node-1 still in shadow 15 s after clearForceShadow"
    sleep 0.5
done
step "3. clearForceShadow: node-1 blocks again after $((SECONDS - start)) s"
echo "lab-fallback: PASS"
