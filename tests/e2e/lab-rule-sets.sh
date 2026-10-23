#!/usr/bin/env bash
# RS-5 (docs/plan/rule-sets.md) on a running lab (make lab-up):
#
#   1. example-api (enforce) only logs a scanner user agent (rule 500100,
#      signature pack): a request with it passes on both NGINX builds.
#   2. lab-admin turns rule set bots-scanners to block and overrides SQL
#      injection rule 942100 to log, with a reason; submits. The replay of
#      the version lists both rules among those whose action changes.
#      lab-approver approves (four eyes); deploy; the bundle needs
#      section.17 (OVERRIDE), which both lab modules declare.
#   3. Both nodes answer the scanner with 403 and a Block ID; the same
#      request with a browser user agent passes.
#   4. Rollback: the version before is deployed again (same spec as
#      before the drill); the scanner passes again.
#
# Tokens are asked for with the passwords on curl's standard input, never
# on its command line.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
lab="$here/../../deploy/lab"
# shellcheck disable=SC1091
. "$lab/.state/env"
CP=http://127.0.0.1:18090
nodes=(18080 18081)
scanner='sqlmap/1.8.4#stable (https://sqlmap.org)'
browser='Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0'
fail() { echo "lab-rule-sets: FAIL: $*" >&2; exit 1; }
step() { echo "lab-rule-sets $(date -u +%H:%M:%S): $*"; }

token() { # user password-variable
    { printf 'grant_type=password&client_id=strata-lab-cli&username=%s&client_secret=' "$1"
      python3 -c 'import os,sys,urllib.parse; sys.stdout.write(urllib.parse.quote(os.environ["S"], safe="") + "&password=" + urllib.parse.quote(os.environ["P"], safe=""))'
    } | curl -fsS http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token --data @- |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
# the secrets reach python through its environment only, not argv
TOKEN=$(S="$LAB_CLI_SECRET" P="$LAB_ADMIN_PASSWORD" token lab-admin)
[ -n "$TOKEN" ] || fail "no token for lab-admin"
APPROVER=$(S="$LAB_CLI_SECRET" P="$LAB_APPROVER_PASSWORD" token lab-approver)
[ -n "$APPROVER" ] || fail "no token for lab-approver"
api() { curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
code() { # port user-agent
    curl -s -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' -A "$2" "http://127.0.0.1:$1/v1/items"
}
until_code() { # port user-agent status seconds
    local start=$SECONDS
    until [ "$(code "$1" "$2")" = "$3" ]; do
        [ $((SECONDS - start)) -lt "$4" ] || fail "node :$1 does not answer $3 within $4 s"
        sleep 0.2
    done
}
replay_done() { # policy version: prints the replay operation
    local out st start=$SECONDS
    while :; do
        out=$(api "$CP/v1/policies/$1/versions/$2/replay")
        st=$(json "d.get('operation', d).get('state', '')" <<<"$out")
        [ "$st" = DONE ] && { echo "$out"; return; }
        [ "$st" = FAILED ] && fail "replay of version $2 failed"
        [ $((SECONDS - start)) -lt 900 ] || fail "replay of version $2 not done in 900 s"
        sleep 2
    done
}
deploy_wait() { # deploys example-api, waits for the rollout; prints the bundle version
    local out ro st start=$SECONDS
    out=$(api -X POST "$CP/v1/policies/example-api:deploy" -d '{}')
    ro=$(json "d['rollout_id']" <<<"$out")
    until st=$(api "$CP/v1/rollouts/$ro" | json "d['rollout']['state']") && [ "$st" = DONE ]; do
        case "$st" in FAILED|ABORTED) fail "rollout $ro: $st: $(api "$CP/v1/rollouts/$ro")" ;; esac
        [ $((SECONDS - start)) -lt 120 ] || fail "rollout $ro not done in 120 s ($st)"
        sleep 0.5
    done
    json "d['bundle']['version']" <<<"$out"
}
save() { # spec JSON: a new version, submitted, replayed, approved; prints the version
    local etag v
    etag=$(api "$CP/v1/policies/example-api" | json "d['policy']['etag']")
    api -X PATCH "$CP/v1/policies/example-api" -d "{\"etag\":\"$etag\",\"spec\":$1}" >/dev/null
    v=$(api -X POST "$CP/v1/policies/example-api:submit" -d '{}' | json "d['version']['version']")
    echo "$v"
}
approve() { # version
    curl -fsS -o /dev/null -H "Authorization: Bearer $APPROVER" -H 'Content-Type: application/json' \
        -X POST "$CP/v1/policies/example-api:approve" -d "{\"version\":$1}" || fail "approve version $1"
}

off=$(api "$CP/v1/nodes" | json "' '.join(n['id'] for n in d['nodes'] if not n.get('online') and not n.get('revoked'))")
[ -z "$off" ] || fail "enrolled nodes offline ($off): a rollout would wait for them"
caps=$(api "$CP/v1/nodes" | json "' '.join(str('section.17' in (n.get('capabilities') or [])) for n in d['nodes'] if n.get('online') and not n.get('revoked'))")
case "$caps" in *False*|"") fail "an online node does not declare section.17 (module older than RS-1?): $caps" ;; esac

# --- 1 -----------------------------------------------------------------------
good=$(api "$CP/v1/policies/example-api" | json "d['policy']['version']")
spec_good=$(api "$CP/v1/policies/example-api/versions/$good" | json "json.dumps(d['version']['spec'])")
if [ "$(json "bool(d.get('rule_sets') or d.get('rule_overrides'))" <<<"$spec_good")" = True ]; then
    fail "example-api version $good already has rule sets or overrides (an earlier run left them?)"
fi
for n in "${nodes[@]}"; do
    [ "$(code "$n" "$scanner")" = 200 ] || fail "node :$n does not let the scanner through before the drill"
done
step "1. example-api v$good: the scanner user agent passes on both nodes (logged only)"

# --- 2 -----------------------------------------------------------------------
new=$(python3 -c '
import json, sys
s = json.loads(sys.argv[1])
s["rule_sets"] = [{"set": "bots-scanners", "action": "POLICY_RULE_ACTION_BLOCK"}]
s["rule_overrides"] = [{"rule": 942100, "action": "POLICY_RULE_ACTION_LOG", "reason": "RS-5 lab drill: watch libinjection on /v1/items"}]
print(json.dumps(s))' "$spec_good")
v=$(save "$new")
rep=$(replay_done example-api "$v")
changes=$(json "' '.join(f\"{c['rule']}:{c.get('from','')}>{c.get('to','')}\" for c in (d.get('operation', d).get('replay', {}).get('rule_actions') or {}).get('rules', []))" <<<"$rep")
case " $changes " in *" 500100:log>block "*) ;; *) fail "replay of v$v does not list 500100 log>block: $changes" ;; esac
case " $changes " in *" 942100:score>log "*) ;; *) fail "replay of v$v does not list 942100 score>log: $changes" ;; esac
step "2. v$v saved and replayed: rule actions changed: $changes"
approve "$v"
start=$SECONDS
b=$(deploy_wait)
step "2. v$v approved by lab-approver and deployed as bundle $b"

# --- 3 -----------------------------------------------------------------------
for n in "${nodes[@]}"; do
    until_code "$n" "$scanner" 403 15
    hdr=$(curl -s -o /dev/null -D - -H 'Host: api.example.test' -A "$scanner" "http://127.0.0.1:$n/v1/items")
    grep -qiE '^X-Strata-Block-Id: STR-' <<<"$hdr" || fail "node :$n blocks the scanner without a Block ID"
    [ "$(code "$n" "$browser")" = 200 ] || fail "node :$n blocks a browser"
done
step "3. both nodes block the scanner with a Block ID after $((SECONDS - start)) s; a browser passes"

# --- 4 -----------------------------------------------------------------------
start=$SECONDS
v=$(save "$spec_good")
replay_done example-api "$v" >/dev/null
approve "$v"
b=$(deploy_wait)
for n in "${nodes[@]}"; do until_code "$n" "$scanner" 200 15; done
now=$(api "$CP/v1/policies/example-api/versions/$v" | json "json.dumps(d['version']['spec'])")
[ "$now" = "$spec_good" ] || fail "the rolled back spec differs from v$good"
step "4. rollback to the spec of v$good (now v$v, bundle $b): the scanner passes again after $((SECONDS - start)) s"
echo "lab-rule-sets: all steps passed"
