#!/usr/bin/env bash
# W10-G2-01 / #47 end to end on a running lab (make lab-up): shadow events
# reach ClickHouse and the API.
#
#   1. example-web is in shadow: a path traversal under /web/ passes (200)
#      on both NGINX nodes; the access log names its Event ID (EVT-...).
#   2. Each Event ID is found by GET /v1/events/{id} with action "shadow",
#      policy example-web, the rule that matched.
#   3. events:search with action=shadow and policy example-web lists them.
#   4. Negative: the enforce policy still blocks (403, STR- id stored as
#      "block"), and a clean request under /web/ makes no event.
#
# Usage: tests/e2e/lab-shadow-events.sh [lab|staging]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
case "${1:-lab}" in
    lab) p=1 project=strata-lab state="$root/deploy/lab/.state" ;;
    staging) p=2 project=strata-staging state="${STAGING_STATE:-$root/deploy/staging/.state}" ;;
    *) echo "usage: lab-shadow-events.sh [lab|staging]" >&2; exit 2 ;;
esac
# shellcheck disable=SC1091
. "$state/env"
cp=http://127.0.0.1:${p}8090
fail() { echo "shadow-events: FAIL: $*" >&2; exit 1; }
step() { echo "shadow-events: $*"; }
token() {
    curl -fsS "http://127.0.0.1:${p}8180/realms/strata/protocol/openid-connect/token" \
        -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
        -d username=lab-operator --data-urlencode "password=$LAB_OPERATOR_PASSWORD" |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
api() { curl -fsS -H "Authorization: Bearer $(token)" -H 'Content-Type: application/json' "$@"; }
code() { curl -s --path-as-is -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' "http://127.0.0.1:$1$2"; }
# id_from_log <container> <marker>: the blk= of the access log line with marker
id_from_log() { docker logs --since 2m "$1" 2>&1 | grep -F "$2" | grep -o 'blk=[A-Z]\{3\}-[0-9A-Z-]*' | tail -1 | cut -d= -f2 || true; }

since=$(date -u +%FT%TZ)
ids=()
for n in stable:${p}8080 mainline:${p}8081; do
    c=$project-nginx-${n%%:*}-1 port=${n##*:}
    marker="shadow-e2e-$RANDOM$RANDOM"
    got=$(code "$port" "/web/files/%2e%2e/etc/passwd?m=$marker")
    [ "$got" = 200 ] || fail "node :$port answers $got to an attack under the shadow policy, not 200"
    id=$(id_from_log "$c" "$marker")
    [[ "$id" == EVT-* ]] || fail "node :$port logged no Event ID for the shadow request (got '$id')"
    ids+=("$id")
done
step "1. both nodes let the attack through in shadow, Event IDs ${ids[*]}"

for id in "${ids[@]}"; do
    start=$SECONDS
    until ev=$(api "$cp/v1/events/$id" 2>/dev/null); do
        [ $((SECONDS - start)) -lt 60 ] || fail "event $id not found through the API in 60 s"
        sleep 2
    done
    python3 -c '
import json, sys
e = json.loads(sys.argv[1]); e = e.get("event", e)
assert e["action"] == "shadow", e["action"]
assert e["policy_id"] == "example-web", e["policy_id"]
assert e.get("matched_rules"), "no matched rule"
' "$ev" || fail "event $id: $ev"
done
step "2. both events stored with action shadow, policy example-web, matched rules"

found=$(api -X POST "$cp/v1/events:search" -d "{\"from\":\"$since\",\"action\":\"shadow\",\"policy_id\":\"example-web\",\"page_size\":100}" |
    python3 -c 'import json,sys; print(" ".join(e["block_id"] for e in json.load(sys.stdin).get("events", [])))')
for id in "${ids[@]}"; do [[ " $found " == *" $id "* ]] || fail "events:search action=shadow does not list $id ($found)"; done
step "3. events:search action=shadow lists them"

[ "$(code "${p}8080" '/files/%2e%2e/etc/passwd')" = 403 ] || fail "the enforce policy no longer blocks"
marker="clean-e2e-$RANDOM$RANDOM"
[ "$(code "${p}8080" "/web/ok?m=$marker")" = 200 ] || fail "a clean request under /web/ is not 200"
id=$(id_from_log "$project-nginx-stable-1" "$marker")
[ "$id" = "-" ] || [ -z "$id" ] || fail "a clean request made an event ($id)"
step "4. enforce still blocks; a clean request makes no event"
echo "shadow-events: PASS"
