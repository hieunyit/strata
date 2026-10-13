#!/usr/bin/env bash
# W10-N-01: the node image (deploy/packaging/build-image.sh) against the
# running lab: enrolls with a token, gets the lab bundle, blocks with a
# Block ID the control plane finds; restarts from its volume without a new
# token; stops when the agent dies.
# Usage: deploy/packaging/test/test-image.sh [nginx-version...]  (default 1.30.5 1.31.6)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
lab="$root/deploy/lab"
work="$root/build/imagetest"
cp=http://127.0.0.1:18090
[ $# -gt 0 ] || set -- 1.30.5 1.31.6
# shellcheck disable=SC1091
. "$lab/.state/env"
fail() { echo "test-image: FAIL: $*" >&2; exit 1; }
step() { echo "test-image: [$n] $*"; }
# a fresh token for every call: an install can outlast the token's lifetime
new_token() {
    curl -fsS http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token \
        -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
        -d username=lab-admin --data-urlencode "password=$LAB_ADMIN_PASSWORD" |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
api() { curl -fsS -H "Authorization: Bearer $(new_token)" -H 'Content-Type: application/json' "$@"; }
rm -rf "$work" && mkdir -p "$work"
docker compose -f "$lab/compose.yaml" --env-file "$lab/.state/env" cp control-plane:/state/pki/ca.pem "$work/ca.pem"
chmod 0644 "$work/ca.pem"
cat > "$work/default.conf" <<'EOF'
server {
    listen 80;
    location / {
        strata on;
        strata_policy example-api;
        root /usr/share/nginx/html;
    }
}
EOF
containers=() volumes=() nodes=()
cleanup() {
    for c in "${containers[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
    for v in "${volumes[@]}"; do docker volume rm "$v" >/dev/null 2>&1 || true; done
    for nd in "${nodes[@]}"; do api -X DELETE "$cp/v1/nodes/$nd" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

for n in "$@"; do
    c=strata-imagetest-$n vol=strata-imagetest-$n
    containers+=("$c"); volumes+=("$vol")
    api -X POST "$cp/v1/groups/lab/enrollmentTokens" -d '{}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' > "$work/token-$n"
    run() {
        docker run -d --name "$c" --network strata-lab_default --cpuset-cpus="${PKGTEST_CPUS:-6-10}" \
            --sysctl net.unix.max_dgram_qlen=8192 -v "$vol:/var/lib/strata" -v "$work:/enroll:ro" \
            -v "$work/default.conf:/etc/nginx/conf.d/default.conf:ro" \
            -e STRATA_SERVER=control-plane:8443 -e STRATA_SERVER_NAME=cp.example.test -e STRATA_CA_FILE=/enroll/ca.pem \
            "$@" "strata-nginx:$n" >/dev/null
    }
    run -e "STRATA_ENROLL_TOKEN_FILE=/enroll/token-$n"
    code() { docker exec "$c" curl -s --path-as-is -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' "http://127.0.0.1$1"; }
    blocks() {
        local t=$SECONDS
        until [ "$(code '/files/%2e%2e/etc/passwd')" = 403 ]; do
            [ $((SECONDS - t)) -lt 90 ] || { docker logs --tail 20 "$c" >&2; fail "[$n] not blocking after 90 s"; }
            sleep 2
        done
    }
    blocks
    node=$(docker exec "$c" cat /var/lib/strata/identity/node-id)
    nodes+=("$node")
    [ "$(code /)" = 200 ] || fail "[$n] clean request not 200"
    blk=$(docker exec "$c" curl -s --path-as-is -D - -o /dev/null -H 'Host: api.example.test' 'http://127.0.0.1/files/%2e%2e/etc/passwd' |
        tr -d '\r' | sed -n 's/^[Xx]-[Ss]trata-[Bb]lock-[Ii]d: //p')
    t=$SECONDS
    until api "$cp/v1/events/$blk" >/dev/null 2>&1; do
        [ $((SECONDS - t)) -lt 60 ] || fail "[$n] event $blk not in the control plane"
        sleep 2
    done
    step "node $node enrolled, blocks with $blk, event found through the API"

    # restart from the volume: no token, same node
    docker rm -f "$c" >/dev/null
    run
    blocks
    [ "$(docker exec "$c" cat /var/lib/strata/identity/node-id)" = "$node" ] || fail "[$n] a new identity after a restart"
    step "restarted from its volume without a token: same node, blocking"

    # the agent dies: the container stops (no hidden dead agent)
    # shellcheck disable=SC2016
    docker exec "$c" bash -c 'for p in /proc/[0-9]*; do
        if tr "\0" " " < "$p/cmdline" 2>/dev/null | grep -q "^strata-agent run"; then kill -9 "${p#/proc/}"; fi; done' || true  # the exec dies with the container
    t=$SECONDS
    until [ "$(docker inspect -f '{{.State.Running}}' "$c")" = false ]; do
        [ $((SECONDS - t)) -lt 20 ] || fail "[$n] the container runs on without its agent"
        sleep 1
    done
    step "agent killed: the container exited ($(docker inspect -f '{{.State.ExitCode}}' "$c"))"
done
echo "test-image: PASS ($*)"
