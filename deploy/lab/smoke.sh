#!/usr/bin/env bash
# Checks a running lab (make lab-up): every component answers, both NGINX
# builds block an attack with a Block ID, an event goes worker socket ->
# agent -> PushEvents -> ClickHouse -> API -> UI, and the agents' metrics
# reach VictoriaMetrics and Grafana.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$here/.state/env"
compose=(docker compose -f "$here/compose.yaml" --env-file "$here/.state/env")
fail=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }
check() { # name command...
    local name=$1; shift
    if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}
retry() { # seconds command...
    local end=$((SECONDS + $1)); shift
    until "$@"; do [ $SECONDS -lt $end ] || return 1; sleep 2; done
}

# token <user>: an access token for a lab user (strata-lab-cli, password grant).
token() {
    local pwvar="LAB_${1#lab-}_PASSWORD"; pwvar=${pwvar^^}
    curl -fsS http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token \
        -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
        -d "username=$1" --data-urlencode "password=${!pwvar}" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
status() { # url [curl args...]: prints the HTTP status
    local url=$1; shift
    curl -s -o /dev/null -w '%{http_code}' "$@" "$url"
}

echo "components"
check "postgres"   "${compose[@]}" exec -T postgres pg_isready -U strata -d strata
check "clickhouse" curl -fsS -u "strata:$CLICKHOUSE_PASSWORD" "http://127.0.0.1:18123/?query=EXISTS+TABLE+default.events"
check "minio"      curl -fsS http://127.0.0.1:19000/minio/health/live
check "minio bucket strata-bundles" "${compose[@]}" run --rm -T minio-init ls lab/strata-bundles
check "keycloak realm strata" curl -fsS http://127.0.0.1:18180/realms/strata/.well-known/openid-configuration
check "control plane healthz" curl -fsS http://127.0.0.1:18090/healthz
check "ui"         curl -fsS http://127.0.0.1:18088/

echo "admin API: OIDC (Keycloak) and RBAC"
declare -A tok
for u in viewer operator approver admin; do
    tok[$u]=$(token "lab-$u" || true)
    if [ -n "${tok[$u]}" ]; then ok "token for lab-$u"; else bad "token for lab-$u"; fi
done
auth() { echo "Authorization: Bearer ${tok[$1]}"; }
[ "$(status http://127.0.0.1:18090/v1/version)" = 401 ] && ok "GET /v1/version without a token: 401" || bad "GET /v1/version without a token: 401"
[ "$(status http://127.0.0.1:18090/v1/version -H 'Authorization: Bearer x.y.z')" = 401 ] && ok "GET /v1/version with a forged token: 401" || bad "GET /v1/version with a forged token: 401"
for u in viewer operator approver admin; do
    check "GET /v1/version as $u" sh -c "curl -fsS -H '$(auth $u)' http://127.0.0.1:18090/v1/version | grep -q '\"api_version\":\"v1\"'"
done
check "control plane API (search as viewer)" curl -fsS -X POST -H 'Content-Type: application/json' -H "$(auth viewer)" -d '{}' http://127.0.0.1:18090/v1/events:search

echo "fleet: enrolled agents (W04-G1-01)"
nodes() { curl -fsS -H "$(auth viewer)" http://127.0.0.1:18090/v1/nodes; }
online2() { [ "$(nodes | grep -o '"online":true' | wc -l)" -ge 2 ]; }
if retry 30 online2; then ok "both agents enrolled and online"; else bad "both agents enrolled and online"; fi
[ "$(status http://127.0.0.1:18090/v1/groups -X POST -H "$(auth operator)" -H 'Content-Type: application/json' -d '{"id":"x","name":"x"}')" = 403 ] \
    && ok "operator may not create groups: 403" || bad "operator may not create groups: 403"

echo "policies and bundles (W04-G2-01)"
api() { # role method path [body]: prints the body, status on the last line
    curl -s -w '\n%{http_code}' -X "$2" -H "$(auth "$1")" -H 'Content-Type: application/json' ${4:+-d "$4"} "http://127.0.0.1:18090$3"
}
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -1; }
pid=smoke-$(date +%s)
out=$(api operator POST /v1/policies "{\"id\":\"$pid\",\"name\":\"$pid\",\"spec\":{\"mode\":\"MODE_SHADOW\"}}")
[ "$(tail -1 <<<"$out")" = 200 ] && ok "operator creates policy $pid" || bad "operator creates policy $pid: $out"
etag1=$(head -n -1 <<<"$out" | field etag)
out=$(api operator PATCH "/v1/policies/$pid" "{\"etag\":\"$etag1\",\"spec\":{\"mode\":\"MODE_ENFORCE\"}}")
[ "$(tail -1 <<<"$out")" = 200 ] && grep -q '"version":2' <<<"$out" && ok "edit with the current etag: version 2" || bad "edit with the current etag: $out"
out=$(api operator PATCH "/v1/policies/$pid" "{\"etag\":\"$etag1\",\"spec\":{\"mode\":\"MODE_SHADOW\"}}")
[ "$(tail -1 <<<"$out")" = 409 ] && ok "edit with a stale etag: 409" || bad "edit with a stale etag: $out"
op=$(head -n -1 <<<"$out" | field replay_operation)
replayed() { api viewer GET "/v1/operations/$op" | grep -q '"done":true'; }
if [ -n "$op" ] && retry 120 replayed && api viewer GET "/v1/operations/$op" | grep -q '"state":"DONE"'; then
    ok "version 2 replayed on its own against the bundle in force ($op, W13-G2-01)"
else
    bad "version 2 replayed on its own: $op $(api viewer GET "/v1/operations/$op" | head -c 300)"
fi
[ "$(api operator POST "/v1/policies/$pid:deploy" '{}' | tail -1)" = 400 ] && ok "deploy of a draft: 400 (four eyes)" || bad "deploy of a draft: 400"
[ "$(api operator POST "/v1/policies/$pid:submit" '{}' | tail -1)" = 200 ] && ok "operator submits version 2" || bad "operator submits version 2"
[ "$(api operator POST "/v1/policies/$pid:approve" '{"version":2}' | tail -1)" = 403 ] && ok "operator may not approve: 403" || bad "operator may not approve: 403"
[ "$(api approver POST "/v1/policies/$pid:approve" '{"version":2,"comment":"smoke"}' | tail -1)" = 200 ] && ok "approver approves version 2" || bad "approver approves version 2"
out=$(api operator POST "/v1/policies/$pid:deploy" '{}')
key=$(head -n -1 <<<"$out" | field object_key); sum=$(head -n -1 <<<"$out" | field sha256)
if [ "$(tail -1 <<<"$out")" = 200 ] && [ -n "$key" ]; then ok "deploy built and signed a bundle ($key)"; else bad "deploy: $out"; fi
stored=$("${compose[@]}" run --rm -T minio-init cat "lab/strata-bundles/$key" 2>/dev/null | sha256sum | cut -d' ' -f1)
[ -n "$sum" ] && [ "$stored" = "$sum" ] && ok "bundle in MinIO, sha256 matches" || bad "bundle in MinIO, sha256 matches ($stored vs $sum)"

echo "nginx + ngx_http_strata_module"
declare -A blocked
for port in 18080 18081; do
    check "$port pass" curl -fsS -H 'Host: api.example.test' "http://127.0.0.1:$port/v1/items"
    hdr=$(curl -s -o /dev/null -D - -H 'Host: api.example.test' -H 'Accept: application/json' \
        "http://127.0.0.1:$port/files/%2e%2e/etc/passwd" || true)
    blocked[$port]=$(sed -n 's/^[Xx]-[Ss]trata-[Bb]lock-[Ii]d: *\(STR-[^[:space:]]*\).*/\1/p' <<<"$hdr" | head -1)
    if grep -q '^HTTP/1.1 403' <<<"$hdr" && [ -n "${blocked[$port]}" ]; then
        ok "$port blocks a path traversal with Block ID ${blocked[$port]}"
    else
        bad "$port blocks a path traversal with a Block ID"
    fi
done

echo "event path: worker socket -> agent -> control plane -> API, UI"
for port in 18080 18081; do
    id=${blocked[$port]}
    [ -n "$id" ] || { bad "$port: no Block ID to look up"; continue; }
    found() { curl -fsS -H "$(auth operator)" "http://127.0.0.1:18090/v1/events/$id" 2>/dev/null | grep -q "$id"; }
    if retry 30 found; then ok "$port: event $id stored and found by Block ID"; else bad "$port: event $id stored and found by Block ID"; fi
    check "$port: event found through the UI proxy" curl -fsS -H "$(auth operator)" "http://127.0.0.1:18088/v1/events/$id"
    check "$port: viewer gets the client IP masked" sh -c "curl -fsS -H '$(auth viewer)' http://127.0.0.1:18090/v1/events/$id | grep -qE '\"client_ip\":\"[0-9.]+\\.0/24\"'"
    check "$port: operator gets the full client IP" sh -c "curl -fsS -H '$(auth operator)' http://127.0.0.1:18090/v1/events/$id | grep -qE '\"client_ip\":\"[0-9.]+\"'"
done

echo "metrics"
series() { curl -fsS 'http://127.0.0.1:18428/api/v1/query?query=strata_agent_events_received_total' | grep -o '"instance":"agent-[12]:9469"' | sort -u | wc -l | grep -q 2; }
if retry 60 series; then ok "VictoriaMetrics scrapes both agents"; else bad "VictoriaMetrics scrapes both agents"; fi
up() { curl -fsS 'http://127.0.0.1:18428/api/v1/query?query=strata_metrics_file_up%3D%3D1' | grep -o '"instance":"agent-[12]:9469"' | sort -u | wc -l | grep -q 2; }
if retry 60 up; then ok "both agents read the NGINX metrics file"; else bad "both agents read the NGINX metrics file"; fi
for uid in strata-module strata-agent strata-control-plane strata-shadow-fp; do
    check "grafana dashboard $uid" sh -c "curl -fsS -u 'admin:$GRAFANA_ADMIN_PASSWORD' 'http://127.0.0.1:13000/api/dashboards/uid/$uid' | grep -q '\"uid\":\"$uid\"'"
done
cpscraped() { curl -fsS -u "admin:$GRAFANA_ADMIN_PASSWORD" \
    'http://127.0.0.1:13000/api/datasources/proxy/uid/vm/api/v1/query?query=strata_cp_build_info' | grep -q control-plane; }
if retry 60 cpscraped; then ok "grafana reads strata_cp_* (control plane scraped)"; else bad "grafana reads strata_cp_* (control plane scraped)"; fi
chds() { curl -fsS -u "admin:$GRAFANA_ADMIN_PASSWORD" http://127.0.0.1:13000/api/datasources/uid/clickhouse/health | grep -q '"status":"OK"'; }
if retry 60 chds; then ok "grafana ClickHouse datasource healthy"; else bad "grafana ClickHouse datasource healthy"; fi
chq() { curl -s -o /dev/null -w '%{http_code}' -u "grafana:$GRAFANA_CLICKHOUSE_PASSWORD" 'http://127.0.0.1:18123/' --data-binary "$1"; }
[ "$(chq 'SELECT count() FROM default.events')" = 200 ] && ok "ClickHouse user grafana reads events" || bad "ClickHouse user grafana reads events"
[ "$(chq 'SELECT name FROM system.users')" != 200 ] && ok "ClickHouse user grafana cannot read system tables" || bad "ClickHouse user grafana cannot read system tables"
[ "$(chq "INSERT INTO default.events (block_id) VALUES ('x')")" != 200 ] && ok "ClickHouse user grafana cannot write" || bad "ClickHouse user grafana cannot write"
check "vmalert loaded the Strata alert rules" sh -c "curl -fsS http://127.0.0.1:18880/api/v1/rules | grep -q StrataAgentDown"
# right after a restart the agents may not be scraped yet: retry like above
agentseries() { curl -fsS -u "admin:$GRAFANA_ADMIN_PASSWORD" \
    'http://127.0.0.1:13000/api/datasources/proxy/uid/vm/api/v1/query?query=strata_agent_spool_bytes' | grep -q agent-1; }
if retry 60 agentseries; then ok "grafana reads strata_agent_* from VictoriaMetrics"; else bad "grafana reads strata_agent_* from VictoriaMetrics"; fi

[ $fail = 0 ] && echo "lab smoke: all checks passed" || { echo "lab smoke: FAILED"; exit 1; }
