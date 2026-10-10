#!/usr/bin/env bash
# W04-Q-01 end to end on a running lab (make lab-up): a policy change made
# through the API is compiled, signed, stored, reaches both NGINX nodes, and
# changes what they do with a test request.
#
#   1. example-web is in shadow: a path traversal under /web/ passes (200).
#   2. As lab-operator: PATCH example-web to enforce (with its etag), deploy.
#   3. The bundle goes from MinIO to the nodes (install-bundle.sh stands in
#      for the agent until W05-G1-01) and both NGINX builds answer 403 with
#      a Block ID within 10 s; a clean request still passes.
#   4. Back to shadow, deployed the same way: the request passes again.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
lab="$here/../../deploy/lab"
# shellcheck disable=SC1091
. "$lab/.state/env"
compose=(docker compose -f "$lab/compose.yaml" --env-file "$lab/.state/env")
cp=http://127.0.0.1:18090
attack='/web/files/%2e%2e/etc/passwd'
fail() { echo "lab-chain: FAIL: $*" >&2; exit 1; }
step() { echo "lab-chain: $*"; }

token=$(curl -fsS http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token \
    -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
    -d username=lab-operator --data-urlencode "password=$LAB_OPERATOR_PASSWORD" |
    sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || fail "no token for lab-operator"
api() { curl -fsS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' "$@"; }
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -1; }
code() { curl -s -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' "http://127.0.0.1:$1$2"; }

# expect <status> <seconds>: both nodes answer the attack with status in time.
expect() {
    local want=$1 limit=$2 start=$SECONDS port
    for port in 18080 18081; do
        until [ "$(code $port "$attack")" = "$want" ]; do
            [ $((SECONDS - start)) -lt "$limit" ] || fail "node :$port does not answer $want within ${limit}s"
            sleep 0.2
        done
    done
    step "both nodes answer $want after $((SECONDS - start))s"
}

# set_mode <MODE_...>: edit example-web, deploy, install on the nodes.
set_mode() {
    local etag out key sum version
    etag=$(api "$cp/v1/policies/example-web" | field etag)
    [ -n "$etag" ] || fail "example-web not found (did fleet-init run?)"
    api -X PATCH "$cp/v1/policies/example-web" \
        -d "{\"etag\":\"$etag\",\"spec\":{\"mode\":\"$1\",\"oversize\":\"OVERSIZE_PASS\"}}" >/dev/null
    out=$(api -X POST "$cp/v1/policies/example-web:deploy" -d '{}')
    key=$(field object_key <<<"$out"); sum=$(field sha256 <<<"$out"); version=$(field version <<<"$out")
    [ -n "$key" ] && [ -n "$sum" ] || fail "deploy: $out"
    step "example-web $1 deployed as bundle $version"
    "${compose[@]}" run --rm -T fleet-init /opt/strata/install-bundle.sh "$key" "$sum" "$version"
}

expect 200 10
set_mode MODE_ENFORCE
expect 403 10
for port in 18080 18081; do
    hdr=$(curl -s -o /dev/null -D - -H 'Host: api.example.test' "http://127.0.0.1:$port$attack")
    grep -qiE '^X-Strata-Block-Id: STR-' <<<"$hdr" || fail "node :$port blocks without a Block ID"
    [ "$(code $port /web/ok)" = 200 ] || fail "node :$port blocks a clean request"
done
step "blocks carry a Block ID; clean requests pass"
set_mode MODE_SHADOW
expect 200 10
echo "lab-chain: all steps passed"
