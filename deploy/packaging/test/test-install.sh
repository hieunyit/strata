#!/usr/bin/env bash
# W10-N-01: installs the packages of build/packages on clean machines with
# the one-command installer, and checks the node works end to end against the
# running lab (make lab-up): it enrolls with the lab control plane, gets the
# lab bundle, blocks an attack with a Block ID the control plane can find.
#
# Usage: deploy/packaging/test/test-install.sh [os:nginx...]
#        default: ubuntu:24.04:1.30.5 debian:12:1.31.6 rockylinux:9:1.30.5
# A clean machine is the distribution's image with systemd as init (no VM on
# this host): containers run --privileged, on the lab's network, and are
# removed at the end; their nodes are revoked.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
lab="$root/deploy/lab"
pkgs="$root/build/packages"
work="$root/build/pkgtest"
cp=http://127.0.0.1:18090
net=${LAB_NETWORK:-strata-lab_default}
[ $# -gt 0 ] || set -- ubuntu:24.04:1.30.5 debian:12:1.31.6 rockylinux:9:1.30.5
# shellcheck disable=SC1091
. "$lab/.state/env"
fail() { echo "test-install: FAIL: $*" >&2; exit 1; }
step() { echo "test-install: [$name] $*"; }
ls "$pkgs"/strata-agent_*.deb >/dev/null || fail "no packages: run deploy/packaging/build.sh"

# a fresh token for every call: an install can outlast the token's lifetime
new_token() {
    curl -fsS http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token \
        -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
        -d username=lab-admin --data-urlencode "password=$LAB_ADMIN_PASSWORD" |
        sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}
[ -n "$(new_token)" ] || fail "no lab-admin token"
api() { curl -fsS -H "Authorization: Bearer $(new_token)" -H 'Content-Type: application/json' "$@"; }

rm -rf "$work" && mkdir -p "$work"
docker compose -f "$lab/compose.yaml" --env-file "$lab/.state/env" cp control-plane:/state/pki/ca.pem "$work/ca.pem"
chmod 0644 "$work/ca.pem"

containers=() nodes=()
cleanup() {
    [ -z "${PKGTEST_KEEP:-}" ] || { echo "test-install: kept ${containers[*]}; revoke ${nodes[*]} when done" >&2; return 0; }
    for c in "${containers[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
    for n in "${nodes[@]}"; do api -X DELETE "$cp/v1/nodes/$n" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

for spec in "$@"; do
    base=${spec%:*} ngx=${spec##*:}
    name=$(tr ':.' '--' <<< "$base")-$ngx
    c=strata-pkgtest-$name
    image=strata-pkgtest:$(tr ':' '-' <<< "$base")
    step "image $image"
    docker build -q --build-arg "BASE=$base" -t "$image" "$here" >/dev/null
    docker rm -f "$c" >/dev/null 2>&1 || true
    docker run -d --name "$c" --hostname "$name" --privileged --cgroupns=private \
        --cpuset-cpus="${PKGTEST_CPUS:-6-10}" --tmpfs /run --tmpfs /run/lock \
        --network "$net" -v "$pkgs:/pkgs:ro" -v "$work:/enroll:ro" "$image" >/dev/null
    containers+=("$c")
    x() { docker exec "$c" "$@"; }
    until x systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'; do sleep 1; done

    api -X POST "$cp/v1/groups/lab/enrollmentTokens" -d '{}' |
        sed -n 's/.*"token":"\([^"]*\)".*/\1/p' > "$work/token-$name"
    [ -s "$work/token-$name" ] || fail "no enrollment token"

    # 1. one command
    step "install.sh (NGINX $ngx)"
    start=$SECONDS
    rc=0
    x sh /pkgs/install.sh --packages /pkgs --nginx "$ngx" --server control-plane:8443 \
        --server-name cp.example.test --ca /enroll/ca.pem --token-file "/enroll/token-$name" || rc=$?
    # revoked at the end even when the install failed after enrolling
    node=$(x cat /var/lib/strata/identity/node-id 2>/dev/null || true)
    [ -z "$node" ] || nodes+=("$node")
    [ $rc = 0 ] || fail "[$name] install.sh"
    step "installed in $((SECONDS - start)) s"

    # 2. what the installer promised
    [ "$(x nginx -v 2>&1 | sed -n 's|.*nginx/||p')" = "$ngx" ] || fail "[$name] NGINX is not $ngx"
    x systemctl is-active -q nginx || fail "[$name] nginx not running"
    x systemctl is-active -q strata-agent || fail "[$name] strata-agent not running"
    x systemctl is-enabled -q strata-agent || fail "[$name] strata-agent not enabled"
    [ "$(x sysctl -n net.unix.max_dgram_qlen)" = 8192 ] || fail "[$name] net.unix.max_dgram_qlen not 8192"
    x id -nG nginx | grep -qw strata || fail "[$name] nginx is not in group strata"
    x nginx -T 2>/dev/null | grep -q '^load_module modules/ngx_http_strata_module.so;' || fail "[$name] module not loaded"
    step "NGINX $ngx + module + agent running, sysctl 8192, node $node"

    # 3. inspection on: the default server gets the lab policy example-api
    x sed -i 's|^\(\s*location / {\)|\1\n        strata on;\n        strata_policy example-api;|' /etc/nginx/conf.d/default.conf
    x nginx -t -q && x systemctl reload nginx
    code() { x curl -s --path-as-is -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' "http://127.0.0.1$1"; }
    t=$SECONDS
    until [ "$(code '/files/%2e%2e/etc/passwd')" = 403 ]; do
        [ $((SECONDS - t)) -lt 120 ] || fail "[$name] not blocking after 120 s (no bundle?)"
        sleep 2
    done
    [ "$(code /)" = 200 ] || fail "[$name] a clean request is not 200"
    blk=$(x curl -s --path-as-is -D - -o /dev/null -H 'Host: api.example.test' 'http://127.0.0.1/files/%2e%2e/etc/passwd' |
        tr -d '\r' | sed -n 's/^[Xx]-[Ss]trata-[Bb]lock-[Ii]d: //p')
    [ -n "$blk" ] || fail "[$name] no Block ID header"
    t=$SECONDS
    until api "$cp/v1/events/$blk" >/dev/null 2>&1; do
        [ $((SECONDS - t)) -lt 180 ] || fail "[$name] event $blk not in the control plane after 180 s"
        sleep 2
    done
    step "blocks with Block ID $blk (bundle after $((SECONDS - start)) s from install), event found through the API"

    # 4. negative: a module built for another NGINX version is refused
    other=1.31.6; [ "$ngx" = 1.31.6 ] && other=1.30.5
    if x sh -c "command -v apt-get >/dev/null"; then
        refuse="apt-get install -y -qq /pkgs/nginx-module-strata_${other}+*_amd64.deb"
    else
        refuse="dnf install -y -q /pkgs/nginx-module-strata-${other}+*.x86_64.rpm"
    fi
    if x sh -c "$refuse" >/dev/null 2>&1; then fail "[$name] the module for NGINX $other was installed on NGINX $ngx"; fi
    x nginx -t -q || fail "[$name] nginx -t after the refused install"
    step "module for NGINX $other refused by the package manager"
    if x sh /pkgs/install.sh --packages /pkgs --nginx 1.29.0 >/dev/null 2>&1; then
        fail "[$name] install.sh accepted another NGINX version than the installed one"
    fi
    step "install.sh refuses an NGINX version other than the installed one"

    # 5. idempotent: run again, same state
    x sh /pkgs/install.sh --packages /pkgs >/dev/null || fail "[$name] second run"
    [ "$(x grep -c ngx_http_strata_module /etc/nginx/nginx.conf)" = 1 ] || fail "[$name] load_module added twice"
    step "second run: no change"
done
echo "test-install: PASS ($*)"
