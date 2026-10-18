#!/usr/bin/env bash
# W09-G2-01: the event store on a real ClickHouse (the lab's version and
# schema), with about RECENT events in the last 24 hours and OLDER over the
# 29 days before (defaults 10 million each, ~115 events/s for a day), then
# TestClickHousePerf and TestClickHouseTTL (control-plane/ingest), and
# TestClickHouseAPIPerf (control-plane/api: the same targets through the
# REST API). The Go tests run in the dev image (deploy/dev/run.sh).
# The data are made inside ClickHouse (numbers()): Block IDs carry their
# time as libstrata's do; rule IDs, IPs, paths and actions are drawn with
# skew (a few hot IPs and rules, most traffic on example-api).
# Usage: tests/perf/clickhouse.sh [keep]   ("keep": leave both fixtures running)
# Includes real PostgreSQL annotation overlays and 1% synthetic cost-bearing
# events. The synthetic timings are data-shape fixtures, not cost calibration.
# PERF_CPUS: pin SQL stores and tests to these CPUs (docker --cpuset-cpus).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
name="strata-ch-perf-$(date +%s)-$$"
recent="${RECENT:-10000000}"
older="${OLDER:-10000000}"
pw=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
cpus=()
[ -z "${PERF_CPUS:-}" ] || cpus=(--cpuset-cpus "$PERF_CPUS")
ids=()
cleanup() {
    local status=$?
    trap - EXIT
    for id in "${ids[@]}"; do
        if ! docker rm -fv "$id" >/dev/null; then status=1; fi
    done
    exit "$status"
}
[ "${1:-}" = keep ] || trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
container_id=$(docker create --name "$name" "${cpus[@]}" -p 127.0.0.1::9000 \
    -e CLICKHOUSE_USER=strata -e CLICKHOUSE_PASSWORD="$pw" -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
    --ulimit nofile=262144:262144 \
    -v "$root/control-plane/ingest/schema.sql:/docker-entrypoint-initdb.d/10-events.sql:ro" \
    clickhouse/clickhouse-server:25.8.33)
ids+=("$container_id")
docker start "$container_id" >/dev/null
pg_id=$(docker create --name "$name-pg" "${cpus[@]}" -p 127.0.0.1::5432 -e POSTGRES_PASSWORD="$pw" postgres:17.11)
ids+=("$pg_id")
docker start "$pg_id" >/dev/null
native_addr=$(docker port "$container_id" 9000/tcp)
pg_addr=$(docker port "$pg_id" 5432/tcp)
echo "ClickHouse fixture: $name at $native_addr"
echo "PostgreSQL fixture: $name-pg at $pg_addr"
q() { docker exec -i "$container_id" clickhouse-client --user strata --password "$pw" "$@"; }
ready=0
for _ in $(seq 120); do
    if q --connect_timeout 1 --receive_timeout 2 --query "EXISTS TABLE events" 2>/dev/null | grep -q '^1$' && \
        docker exec "$pg_id" pg_isready -q -t 1 -U postgres; then ready=1; break; fi
    sleep 1
done
if [ "$ready" != 1 ]; then echo "ClickHouse fixture did not become ready" >&2; exit 1; fi

# one INSERT ... SELECT per range; ts in ms
fill() { # count from-seconds-ago span-seconds
    q --max_insert_threads 4 --query "
INSERT INTO events (block_id, timestamp, node_id, connector_type, policy_id, policy_version,
    client_ip, identity, request_id, http_method, http_host, http_path, status_code, action,
    score_protocol, score_sqli, score_xss, score_anomaly, matched_rules,
    violations.rule_id, violations.layer, violations.field, violations.snippet, received_at,
    rule_costs.rule_id, rule_costs.samples, rule_costs.total_ns, rule_costs.max_ns)
WITH
    toUInt64(toUnixTimestamp64Milli(now64(3))) - $2 * 1000 + (cityHash64(number, 1) % ($3 * 1000)) AS ms,
    cityHash64(number, 2) AS h,
    cityHash64(number, 99) % 100 = 0 AS cost_sampled,
    toUInt128(ms) * pow(2, 38)::UInt128 + toUInt128(h % 1024) * pow(2, 28)::UInt128 + toUInt128(cityHash64(number, 3) % 268435456) AS bits,
    '0123456789ABCDEFGHJKMNPQRSTVWXYZ' AS a,
    arrayStringConcat(arrayMap(i -> substring(a, toUInt8(bitAnd(bitShiftRight(bits, 75 - 5 * i), 31)) + 1, 1), range(16))) AS s,
    [942100, 941100, 930120, 920170, 913100, 100013, 100011, 932160, 455193, 700001] AS rules,
    arrayDistinct(arrayMap(k -> rules[1 + (cityHash64(number, 10 + k) % 1000) % (if(k = 0, 4, 10))], range(1 + h % 3))) AS mr
SELECT
    concat(if(h % 5 = 0, 'EVT-', 'STR-'), substring(s, 1, 4), '-', substring(s, 5, 4), '-', substring(s, 9, 4), '-', substring(s, 13, 4)),
    fromUnixTimestamp64Milli(toInt64(ms)),
    concat('node-', toString(1 + h % 8)), 'nginx',
    ['example-api', 'example-api', 'example-api', 'example-web', 'example-admin'][1 + h % 5], 1 + h % 20,
    if(h % 10 < 3, concat('203.0.113.', toString(h % 10)), IPv4NumToString(toUInt32(cityHash64(number, 4)))),
    '', hex(cityHash64(number, 5)),
    ['GET', 'GET', 'GET', 'POST', 'POST', 'PUT', 'DELETE'][1 + h % 7], 'api.example.test',
    concat(['/v1/items', '/v1/search', '/login', '/admin', '/static/app.js', '/v1/files'][1 + h % 6], '/', toString(h % 1000)),
    if(h % 5 = 0, 200, 403), if(h % 5 = 0, 'shadow', 'block'),
    toInt32(h % 50), toInt32(if(has(mr, 942100), 100, 0)), toInt32(if(has(mr, 941100), 100, 0)), toInt32(100 + h % 100),
    mr, mr, arrayMap(r -> if(r < 200000, 'protocol', 'managed'), mr),
    arrayMap(r -> 'ARGS:q', mr), arrayMap(r -> 'x', mr),
    fromUnixTimestamp64Milli(toInt64(ms + 50)),
    if(cost_sampled, [942100, 0, 941100], []), if(cost_sampled, [1, 3, 1], []),
    if(cost_sampled, [250000, 200000, 150000], []), if(cost_sampled, [250000, 100000, 150000], [])
FROM numbers($1)"
}
start=$(date +%s)
fill "$recent" 86400 86400
fill "$older" $((30 * 86400)) $((29 * 86400))
q --query "OPTIMIZE TABLE events FINAL"
rows=$(q --query 'SELECT count() FROM events')
cost_events=$(q --query 'SELECT countIf(length(rule_costs.rule_id) > 0) FROM events')
disk=$(q --query "SELECT formatReadableSize(sum(bytes_on_disk)) FROM system.parts WHERE database = currentDatabase() AND table = 'events' AND active")
if [ "$rows" -ne "$((recent + older))" ]; then echo "unexpected fixture row count: $rows" >&2; exit 1; fi
echo "filled in $(( $(date +%s) - start )) s: $rows rows, $disk active disk, $cost_events cost-bearing events"
# the dev image, on the host network to reach the published port
STRATA_DEV_DOCKER_ARGS="${STRATA_DEV_DOCKER_ARGS:-} --network host ${cpus[*]}" \
    "$root/deploy/dev/run.sh" env CLICKHOUSE_PERF_ADDR="$native_addr" CLICKHOUSE_PERF_PASSWORD="$pw" \
    STRATA_TEST_POSTGRES_DSN="postgres://postgres:$pw@$pg_addr/postgres?sslmode=disable" \
    sh -c "cd control-plane && go test -count=1 -v -run '^TestClickHouseAPIAnnotatedPerf$' ./api/ && go test -count=1 -v -run 'TestClickHouse(Perf|TTL)' ./ingest/" </dev/null
