#!/usr/bin/env bash
# W13-G1-01: upgrading the agent package on a node under load loses no
# event and changes no bundle. Clean machines as in test-install.sh
# (systemd as init, privileged containers on the lab network), against the
# running lab (make lab-up):
#   1. install the packages of <old> with install.sh, enroll, inspect
#      (policy example-api), and start a steady load with attacks (each a
#      403 with a Block ID and an event);
#   2. upgrade the agent <old> -> <new1> under load: the first upgrade from
#      a package without strata-agent.socket. The agent must run
#      afterwards, enabled, with its socket from systemd (before W13-G1-01
#      an upgrade stopped and disabled it). The one-time move of the socket
#      to systemd may drop the events of about a second: counted, reported;
#   3. upgrade <new1> -> <new2> under load: no event lost. Every Block ID
#      the load got is in ClickHouse, the workers' events-dropped counter
#      does not move, and no worker loads a bundle again (same version, no
#      "bundle version ... active" line in the NGINX log).
#
# Usage: deploy/packaging/test/test-upgrade.sh <old> <new1> <new2> [os:nginx...]
#        each a package directory as deploy/packaging/build.sh makes it;
#        default machines: ubuntu:24.04:1.30.5 rockylinux:9:1.30.5
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
lab="$root/deploy/lab"
work="$root/build/pkgupgrade"
cp=http://127.0.0.1:18090
net=${LAB_NETWORK:-strata-lab_default}
old=$(cd "${1:?usage: test-upgrade.sh <old> <new1> <new2> [os:nginx...]}" && pwd)
new1=$(cd "${2:?}" && pwd)
new2=$(cd "${3:?}" && pwd)
shift 3
[ $# -gt 0 ] || set -- ubuntu:24.04:1.30.5 rockylinux:9:1.30.5
# shellcheck disable=SC1091
. "$lab/.state/env"
fail() { echo "test-upgrade: FAIL: $*" >&2; exit 1; }
step() { echo "test-upgrade $(date -u +%H:%M:%S): [$name] $*"; }

new_token() {
    curl -fsS http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token \
        -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
        -d username=lab-admin --data-urlencode "password=$LAB_ADMIN_PASSWORD" |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
api() { curl -fsS -H "Authorization: Bearer $(new_token)" -H 'Content-Type: application/json' "$@"; }
ch() { docker exec -i strata-lab-clickhouse-1 clickhouse-client --user strata --password "$CLICKHOUSE_PASSWORD" "$@"; }

rm -rf "$work" && mkdir -p "$work"
docker compose -f "$lab/compose.yaml" --env-file "$lab/.state/env" cp control-plane:/state/pki/ca.pem "$work/ca.pem"
chmod 0644 "$work/ca.pem"

containers=() nodes=()
cleanup() {
    [ -z "${PKGTEST_KEEP:-}" ] || { echo "test-upgrade: kept ${containers[*]}" >&2; return 0; }
    for c in "${containers[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
    for n in "${nodes[@]}"; do api -X DELETE "$cp/v1/nodes/$n" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

for spec in "$@"; do
    base=${spec%:*} ngx=${spec##*:}
    name=upgrade-$(tr ':.' '--' <<< "$base")-$ngx
    c=strata-pkgtest-$name
    image=strata-pkgtest:$(tr ':' '-' <<< "$base")
    docker build -q --build-arg "BASE=$base" -t "$image" "$here" >/dev/null
    docker rm -f "$c" >/dev/null 2>&1 || true
    docker run -d --name "$c" --hostname "$name" --privileged --cgroupns=private \
        --cpuset-cpus="${PKGTEST_CPUS:-6-10}" --tmpfs /run --tmpfs /run/lock --network "$net" \
        -v "$old:/old:ro" -v "$new1:/new1:ro" -v "$new2:/new2:ro" -v "$work:/enroll:ro" "$image" >/dev/null
    containers+=("$c")
    x() { docker exec "$c" "$@"; }
    until x systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'; do sleep 1; done
    deb=0; x sh -c 'command -v apt-get >/dev/null' && deb=1

    # 1. the old release, enrolled and inspecting
    api -X POST "$cp/v1/groups/lab/enrollmentTokens" -d '{}' | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' > "$work/token-$name"
    x sh /old/install.sh --packages /old --nginx "$ngx" --server control-plane:8443 \
        --server-name cp.example.test --ca /enroll/ca.pem --token-file "/enroll/token-$name" >/dev/null ||
        fail "[$name] install.sh of the old packages"
    node=$(x cat /var/lib/strata/identity/node-id)
    nodes+=("$node")
    x sed -i 's|^\(\s*location / {\)|\1\n        strata on;\n        strata_policy example-api;|' /etc/nginx/conf.d/default.conf
    x nginx -t -q && x systemctl reload nginx
    code() { x curl -s --path-as-is -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' "http://127.0.0.1$1"; }
    t=$SECONDS
    until [ "$(code '/files/%2e%2e/etc/passwd')" = 403 ]; do
        [ $((SECONDS - t)) -lt 120 ] || fail "[$name] not blocking after 120 s"
        sleep 2
    done
    step "old packages installed ($(x strata-agent version 2>/dev/null || true)), node $node blocks"

    # load: about 20 attacks a second, each Block ID kept, until /tmp/stop
    x sh -c 'rm -f /tmp/stop /tmp/ids; while [ ! -e /tmp/stop ]; do
        curl -s --path-as-is -o /dev/null -D - -H "Host: api.example.test" "http://127.0.0.1/files/%2e%2e/etc/passwd" |
            tr -d "\r" | sed -n "s/^[Xx]-[Ss]trata-[Bb]lock-[Ii]d: //p" >> /tmp/ids
        sleep 0.05; done' &
    loader=$!
    dropped() {
        x curl -s 127.0.0.1:9469/metrics 2>/dev/null | awk '/^strata_events_dropped_total / {print $2; f=1} END {if (!f) print "?"}'
    }
    loads() { x sh -c 'grep -c "strata: bundle version .* active" /var/log/nginx/error.log || true'; }
    pkg() { if [ $deb = 1 ]; then echo "apt-get install -y -qq --allow-downgrades /$1/strata-agent_*_amd64.deb"; else echo "dnf install -y -q /$1/strata-agent-*.x86_64.rpm"; fi; }
    upgrade() { # dir: upgrade the agent under load; prints the dropped events
        local d0 l0 ids0
        sleep 5
        d0=$(dropped) l0=$(loads) ids0=$(x sh -c 'wc -l < /tmp/ids')
        x sh -c "$(pkg "$1")" >/dev/null 2>&1 || fail "[$name] upgrade to $1"
        x systemctl is-active -q strata-agent || fail "[$name] agent not running after the upgrade to $1"
        x systemctl is-enabled -q strata-agent || fail "[$name] agent not enabled after the upgrade to $1"
        x systemctl is-active -q strata-agent.socket || fail "[$name] strata-agent.socket not active after the upgrade to $1"
        until [ "$(dropped)" != "?" ]; do sleep 1; done
        sleep 10
        echo "$d0 $(dropped) $l0 $(loads) $ids0"
    }

    # 2. old -> new1: the agent survives the upgrade
    read -r d0 d1 l0 l1 _ <<< "$(upgrade new1)"
    [ "$l1" = "$l0" ] || fail "[$name] old -> new1: workers loaded a bundle again ($l0 -> $l1)"
    step "old -> new1: agent running and enabled, socket from systemd; events dropped $d0 -> $d1 (one-time move of the socket), no bundle reload"

    # 3. new1 -> new2: nothing lost
    read -r d0 d1 l0 l1 from <<< "$(upgrade new2)"
    [ "$d1" = "$d0" ] || fail "[$name] new1 -> new2: workers dropped $((d1 - d0)) events"
    [ "$l1" = "$l0" ] || fail "[$name] new1 -> new2: workers loaded a bundle again ($l0 -> $l1)"
    x touch /tmp/stop
    wait "$loader" || true
    x sh -c "tail -n +$((from + 1)) /tmp/ids" > "$work/ids-$name"
    sent=$(wc -l < "$work/ids-$name")
    [ "$sent" -gt 100 ] || fail "[$name] only $sent blocked requests from the upgrade on"
    ids=$(sed "s/.*/'&'/" "$work/ids-$name" | paste -sd, -)
    t=$SECONDS
    until got=$(ch -q "SELECT uniqExact(block_id) FROM default.events WHERE block_id IN ($ids)") && [ "$got" = "$sent" ]; do
        [ $((SECONDS - t)) -lt 120 ] || fail "[$name] new1 -> new2: $got of $sent events reached ClickHouse"
        sleep 5
    done
    step "new1 -> new2: $sent blocked requests from the upgrade on, $got events in ClickHouse, events dropped $d0 -> $d1, no bundle reload"
done
echo "test-upgrade: PASS ($*)"
