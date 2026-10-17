#!/usr/bin/env bash
# Isolated real SQL stores for the rule-health HTTP handler integration test.
# No published ports, shared volumes, or staging/production configuration.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
tag="strata-health-$(date +%s)-$$"
network=$(docker network create "$tag")
ids=()
cleanup() {
    local status=$?
    trap - EXIT
    for id in "${ids[@]}"; do
        if ! docker rm -fv "$id" >/dev/null; then status=1; fi
    done
    if ! docker network rm "$network" >/dev/null; then status=1; fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
pw=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
cpus=()
[ -z "${TEST_CPUS:-}" ] || cpus=(--cpuset-cpus "$TEST_CPUS")
pg=$(docker create --name "$tag-pg" --network "$network" --network-alias postgres "${cpus[@]}" -e POSTGRES_PASSWORD="$pw" postgres:17.11)
ids+=("$pg")
docker start "$pg" >/dev/null
ch=$(docker create --name "$tag-ch" --network "$network" --network-alias clickhouse "${cpus[@]}" \
    -e CLICKHOUSE_USER=strata -e CLICKHOUSE_PASSWORD="$pw" -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
    --ulimit nofile=262144:262144 \
    -v "$root/control-plane/ingest/schema.sql:/docker-entrypoint-initdb.d/10-events.sql:ro" clickhouse/clickhouse-server:25.8.33)
ids+=("$ch")
docker start "$ch" >/dev/null
ready=0
for _ in $(seq 120); do
    if docker exec "$pg" pg_isready -q -t 1 -U postgres && \
       [ "$(docker exec "$ch" sh -c 'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --connect_timeout 1 --send_timeout 2 --receive_timeout 2 --max_execution_time 2 --query "EXISTS TABLE events"' 2>/dev/null)" = 1 ]; then
        ready=1; break
    fi
    sleep 1
done
if [ "$ready" != 1 ]; then echo 'SQL fixtures did not become ready' >&2; exit 1; fi
echo "Isolated SQL fixtures ready: $tag"
STRATA_DEV_DOCKER_ARGS="${STRATA_DEV_DOCKER_ARGS:-} --network $network ${cpus[*]}" \
    "$root/deploy/dev/run.sh" env \
    STRATA_TEST_POSTGRES_DSN="postgres://postgres:$pw@postgres:5432/postgres?sslmode=disable" \
    STRATA_TEST_CLICKHOUSE_ADDR=clickhouse:9000 STRATA_TEST_CLICKHOUSE_USER=strata STRATA_TEST_CLICKHOUSE_PASSWORD="$pw" \
    sh -ec 'cd control-plane; go test -race -count=1 -timeout 5m -v -run "^TestRuleHealthDurableSources$" ./api' </dev/null
