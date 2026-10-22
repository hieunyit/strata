#!/usr/bin/env bash
# W11-G1-01 on the lab (make lab-up) with the real agent and NGINX: the node
# fallback forces every policy into shadow when the block rate jumps.
#
#   1. Baseline: about 60 req/s on node-1 (NGINX 1.30.5), 1% attacks, for
#      the 12 warm-up intervals of 5 s and more. Before #65 this level
#      tripped the fallback by chance; now it must not. The test attack is
#      blocked (403).
#   2. #65: one source floods 50% attacks for 15 s. Its blocks count at
#      most 3 per 5 s: node-1 keeps blocking, no trigger.
#   3. Audit 22/10/2026: 12 sources (containers of the lab network, one
#      /24) at 50% attacks used to trip it; a network now counts once and
#      at least 20 networks must block: node-1 keeps blocking, no trigger.
#      A trip from many networks is covered by the unit test
#      TestNodeFallsBackWithinSixSeconds (the lab has one network).
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
# spread <seconds> <sources>: that many containers on the lab network, each
# about 10 req/s to node-1 with 50% attacks: one client address each
spread() {
    local ids=() i
    for i in $(seq 1 "$2"); do
        ids+=("$(docker run -d --rm --cpuset-cpus=6-10 --network strata-lab_default --entrypoint sh strata-lab-runtime:dev -c "
            end=\$((\$(date +%s) + $1)); i=0
            while [ \$(date +%s) -lt \$end ]; do
                i=\$((i + 1))
                if [ \$((i % 2)) = 0 ]; then p='$attack'; else p=/items?id=s$i-\$i; fi
                curl -s --path-as-is -o /dev/null -m 2 -H 'Host: api.example.test' \"http://nginx-stable:8080\$p\"
                sleep 0.1
            done")")
    done
    docker wait "${ids[@]}" >/dev/null 2>&1 || true
}

[ "$(code 18080 "$attack")" = 403 ] || fail "node-1 does not block before the test (already in shadow?)"
node1=$(api "$cp/v1/nodes" | python3 -c 'import json,sys; print([n["id"] for n in json.load(sys.stdin)["nodes"] if n.get("proxy_version")=="1.30.5" and not n.get("revoked") and n.get("online")][0])')
# the agent learns from its start: restart it so the warm-up is this baseline
docker restart strata-lab-agent-1-1 >/dev/null
until docker exec strata-lab-agent-1-1 curl -sf 127.0.0.1:9469/metrics >/dev/null 2>&1; do sleep 1; done
before=$(triggers); before=${before:-0}
step "1. baseline (1% attacks) for 90 s on node-1 ($node1)"
load 90 1
[ "$(code 18080 "$attack")" = 403 ] || fail "node-1 fell back during the baseline (#65: chance)"
[ "$(triggers)" = "$before" ] || fail "fallback triggered during the baseline"
step "2. one source, 50% attacks for 15 s (#65)"
load 15 50
sleep 6 # the last interval closes
[ "$(code 18080 "$attack")" = 403 ] || fail "one source forced node-1 into shadow (#65)"
[ "$(triggers)" = "$before" ] || fail "fallback triggered by one source"
step "3. 12 sources of one /24, 50% attacks (audit 22/10)"
spread 15 12
sleep 6 # the last interval closes
[ "$(code 18080 "$attack")" = 403 ] || fail "12 sources of one network forced node-1 into shadow"
[ "$(triggers)" = "$before" ] || fail "fallback triggered by one network"
echo "lab-fallback: PASS"
