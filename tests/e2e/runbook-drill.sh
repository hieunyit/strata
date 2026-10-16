#!/usr/bin/env bash
# W10-N-01: rehearses the runbook (docs/runbook/README.md) on the lab or on
# staging, with the commands the runbook gives, and times each step:
#
#   1. Ép shadow: node-1 forced to shadow for example-api, then cleared.
#   2. Rollback bundle: a bad deploy (example-api to shadow) is rolled back
#      to the policy version before it; the nodes block again.
#   3. Tắt module: `strata off;` on node-1 and reload, then on again.
#
# Usage: tests/e2e/runbook-drill.sh [lab|staging]
# Staging reads its passwords from STAGING_STATE (default
# deploy/staging/.state of this checkout).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
envname=${1:-lab}
case "$envname" in
    lab) p=1 project=strata-lab state="$root/deploy/lab/.state" ;;
    staging) p=2 project=strata-staging state="${STAGING_STATE:-$root/deploy/staging/.state}" ;;
    *) echo "usage: runbook-drill.sh [lab|staging]" >&2; exit 2 ;;
esac
# shellcheck disable=SC1091
. "$state/env"
CP=http://127.0.0.1:${p}8090
nodes=("${p}8080" "${p}8081")
attack='/files/%2e%2e/etc/passwd'
fail() { echo "drill[$envname]: FAIL: $*" >&2; exit 1; }
step() { echo "drill[$envname] $(date -u +%H:%M:%S): $*"; }

TOKEN=$(curl -fsS "http://127.0.0.1:${p}8180/realms/strata/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
    -d username=lab-admin --data-urlencode "password=$LAB_ADMIN_PASSWORD" |
    sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || fail "no token"
api() { curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
APPROVER=$(curl -fsS "http://127.0.0.1:${p}8180/realms/strata/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
    -d username=lab-approver --data-urlencode "password=$LAB_APPROVER_PASSWORD" |
    sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$APPROVER" ] || fail "no approver token"
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
code() { curl -s -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' "http://127.0.0.1:$1$attack"; }
# until_code <port> <status> <seconds>: prints the seconds it took
until_code() {
    local start=$SECONDS
    until [ "$(code "$1")" = "$2" ]; do
        [ $((SECONDS - start)) -lt "$3" ] || fail "node :$1 does not answer $2 within $3 s"
        sleep 0.2
    done
    echo $((SECONDS - start))
}
for n in "${nodes[@]}"; do [ "$(code "$n")" = 403 ] || fail "node :$n does not block before the drill"; done
# a rollout waits for every enrolled node: revoke nodes that are gone first
# (runbook, "Agent mất kết nối"; alert StrataNodesOffline)
off=$(api "$CP/v1/nodes" | json "' '.join(n['id'] for n in d['nodes'] if not n.get('online') and not n.get('revoked'))")
[ -z "$off" ] || fail "enrolled nodes offline ($off): a rollout would wait for them"
step "start: both nodes block the test attack"

# --- 1. Ép shadow -------------------------------------------------------------
node1=$(api "$CP/v1/nodes" | json "[n['id'] for n in d['nodes'] if n.get('online') and not n.get('revoked')][0]")
host1=$(api "$CP/v1/nodes" | json "[n['hostname'] for n in d['nodes'] if n['id']=='$node1'][0]")
# which port is that node? the one that passes once it is in shadow
api -X POST "$CP/v1/nodes:forceShadow" -d "{\"node_id\":\"$node1\",\"policy_id\":\"example-api\",\"duration_seconds\":600}" >/dev/null
start=$SECONDS
port1=""
until [ -n "$port1" ]; do
    for n in "${nodes[@]}"; do [ "$(code "$n")" = 200 ] && port1=$n; done
    [ $((SECONDS - start)) -lt 15 ] || fail "no node in shadow 15 s after forceShadow"
    sleep 0.2
done
t=$((SECONDS - start))
other=${nodes[0]}; [ "$other" = "$port1" ] && other=${nodes[1]}
[ "$(code "$other")" = 403 ] || fail "forceShadow of one node changed the other"
step "1. forceShadow $node1 ($host1, :$port1) example-api: shadow after ${t} s, the other node still blocks"
api -X POST "$CP/v1/nodes:clearForceShadow" -d "{\"node_id\":\"$node1\",\"policy_id\":\"example-api\"}" >/dev/null
t=$(until_code "$port1" 403 15)
step "1. clearForceShadow: blocking again after ${t} s"

# --- 2. Rollback bundle ---------------------------------------------------------
good=$(api "$CP/v1/policies/example-api" | json "d['policy']['version']")
deploy_wait() { # deploys, waits for the rollout; sets ver and ro
    local out st start=$SECONDS
    out=$(api -X POST "$CP/v1/policies/example-api:deploy" -d '{}')
    ver=$(json "d['bundle']['version']" <<< "$out") ro=$(json "d['rollout_id']" <<< "$out")
    until st=$(api "$CP/v1/rollouts/$ro" | json "d['rollout']['state']") && [ "$st" = DONE ]; do
        case "$st" in FAILED|ABORTED) fail "rollout $ro: $st" ;; esac
        [ $((SECONDS - start)) -lt 120 ] || fail "rollout $ro not done in 120 s ($st)"
        sleep 0.5
    done
}
# approvals wait for the version's replay (PO 16/10: nothing is approved
# without a DONE replay); the replay of a draft takes seconds to minutes
replay_done() { # policy version
    local st start=$SECONDS
    until st=$(api "$CP/v1/policies/$1/versions/$2/replay" | sed -n 's/.*"state":"\([A-Z]*\)".*/\1/p' | head -1) && [ "$st" = DONE ]; do
        [ "$st" = FAILED ] && return 1
        [ $((SECONDS - start)) -lt 900 ] || return 1
        sleep 2
    done
}
patch_spec() { # spec JSON
    local etag
    etag=$(api "$CP/v1/policies/example-api" | json "d['policy']['etag']")
    api -X PATCH "$CP/v1/policies/example-api" -d "{\"etag\":\"$etag\",\"spec\":$1}" >/dev/null
    # four eyes (W13-G2-02): lab-admin submits, lab-approver approves
    v=$(api -X POST "$CP/v1/policies/example-api:submit" -d '{}' | json "d['version']['version']")
    replay_done example-api "$v" || fail "the replay of version $v did not finish"
    curl -fsS -o /dev/null -H "Authorization: Bearer $APPROVER" -H 'Content-Type: application/json' \
        -X POST "$CP/v1/policies/example-api:approve" -d "{\"version\":$v}" || fail "approve version $v"
}
spec_good=$(api "$CP/v1/policies/example-api/versions/$good" | json "json.dumps(d['version']['spec'])")
bad=$(python3 -c "import json,sys; s=json.loads(sys.argv[1]); s['mode']='MODE_SHADOW'; print(json.dumps(s))" "$spec_good")
patch_spec "$bad"
deploy_wait; bver=$ver bro=$ro
for n in "${nodes[@]}"; do until_code "$n" 200 15 >/dev/null; done
step "2. bad deploy: example-api in shadow, bundle $bver (rollout $bro): both nodes let the attack through"
start=$SECONDS
patch_spec "$spec_good"
deploy_wait; rver=$ver rro=$ro
for n in "${nodes[@]}"; do until_code "$n" 403 15 >/dev/null; done
now=$(api "$CP/v1/policies/example-api" | json "d['policy']['version']")
same=$(api "$CP/v1/policies/example-api/versions/$now" | json "json.dumps(d['version']['spec'])")
[ "$same" = "$spec_good" ] || fail "the rolled back spec differs from version $good"
step "2. rollback to policy version $good (now version $now, same spec): bundle $rver (rollout $rro), both nodes block again after $((SECONDS - start)) s"

# --- 3. Tắt module --------------------------------------------------------------
svc=nginx-stable; [ "$port1" = "${p}8081" ] && svc=nginx-mainline
c=$project-$svc-1
nv=$(docker exec "$c" sh -c 'echo $NGINX_VERSION')
ngx=(/opt/nginx/"$nv"/nginx -p /tmp/nginx -c /tmp/nginx/nginx.conf)
# the runbook's quick switch: every `strata on;` becomes `strata off;`
# (an http-level `strata off;` would not override the locations' `on`)
restore() { docker exec "$c" sed -i 's|strata off;  # runbook drill|strata on;|' /tmp/nginx/nginx.conf; docker exec "$c" "${ngx[@]}" -s reload; }
trap restore EXIT
docker exec "$c" sed -i 's|strata on;|strata off;  # runbook drill|' /tmp/nginx/nginx.conf
docker exec "$c" "${ngx[@]}" -t -q
docker exec "$c" "${ngx[@]}" -s reload
t=$(until_code "$port1" 200 15)
hdr=$(curl -s -D - -o /dev/null -H 'Host: api.example.test' "http://127.0.0.1:$port1$attack")
if grep -qi '^x-strata-block-id' <<< "$hdr"; then fail "module still inspects with strata off"; fi
other_code=$(code "$other")
[ "$other_code" = 403 ] || fail "the other node stopped blocking ($other_code)"
step "3. strata off on $svc + reload: no inspection after ${t} s (no Block ID), the other node still blocks"
trap - EXIT
restore
t=$(until_code "$port1" 403 15)
step "3. strata back on: blocking again after ${t} s"
echo "drill[$envname]: PASS"
