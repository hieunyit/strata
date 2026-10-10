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

echo "components"
check "postgres"   "${compose[@]}" exec -T postgres pg_isready -U strata -d strata
check "clickhouse" curl -fsS -u "strata:$CLICKHOUSE_PASSWORD" "http://127.0.0.1:18123/?query=EXISTS+TABLE+default.events"
check "minio"      curl -fsS http://127.0.0.1:19000/minio/health/live
check "minio bucket strata-bundles" "${compose[@]}" run --rm -T minio-init ls lab/strata-bundles
check "keycloak realm strata" curl -fsS http://127.0.0.1:18180/realms/strata/.well-known/openid-configuration
check "control plane API" curl -fsS -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:18090/v1/events:search
check "ui"         curl -fsS http://127.0.0.1:18088/

echo "nginx + ngx_http_strata_module"
for port in 18080 18081; do
    check "$port pass" curl -fsS -H 'Host: api.example.test' "http://127.0.0.1:$port/v1/items"
    hdr=$(curl -s -o /dev/null -D - -H 'Host: api.example.test' -H 'Accept: application/json' \
        "http://127.0.0.1:$port/files/%2e%2e/etc/passwd" || true)
    if grep -q '^HTTP/1.1 403' <<<"$hdr" && grep -qiE '^X-Strata-Block-Id: STR-' <<<"$hdr"; then
        ok "$port blocks a path traversal with a Block ID"
    else
        bad "$port blocks a path traversal with a Block ID"
    fi
done

echo "event path (strata-emit stands in for the worker until W07-N-01)"
id=$("${compose[@]}" exec -T agent-1 strata-emit -event-socket unix:/run/strata/events.sock | tr -d '\r')
found() { curl -fsS "http://127.0.0.1:18090/v1/events/$id" 2>/dev/null | grep -q "$id"; }
if retry 30 found; then ok "event $id stored and found by Block ID"; else bad "event $id stored and found by Block ID"; fi
check "event found through the UI proxy" curl -fsS "http://127.0.0.1:18088/v1/events/$id"

echo "metrics"
series() { curl -fsS 'http://127.0.0.1:18428/api/v1/query?query=strata_agent_events_received_total' | grep -o '"instance":"agent-[12]:9469"' | sort -u | wc -l | grep -q 2; }
if retry 60 series; then ok "VictoriaMetrics scrapes both agents"; else bad "VictoriaMetrics scrapes both agents"; fi
check "grafana dashboard Strata node" sh -c "curl -fsS -u 'admin:$GRAFANA_ADMIN_PASSWORD' 'http://127.0.0.1:13000/api/search?query=Strata%20node' | grep -q strata-node"
check "grafana reads strata_agent_* from VictoriaMetrics" sh -c "curl -fsS -u 'admin:$GRAFANA_ADMIN_PASSWORD' \
    'http://127.0.0.1:13000/api/datasources/proxy/uid/vm/api/v1/query?query=strata_agent_spool_bytes' | grep -q agent-1"

[ $fail = 0 ] && echo "lab smoke: all checks passed" || { echo "lab smoke: FAILED"; exit 1; }
