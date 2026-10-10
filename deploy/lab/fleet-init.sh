#!/usr/bin/env bash
# Lab fleet bootstrap (service fleet-init, after the control plane is up):
# as lab-admin, creates the connector group "lab" and one enrollment token
# per agent in /state/enroll/<node>.token. An agent enrolls with its token
# on first start; tokens are single use and expire after 24 h.
set -euo pipefail
cp=http://control-plane:8080
kc=http://keycloak:8080/realms/strata/protocol/openid-connect/token

token=$(curl -fsS "$kc" \
    -d grant_type=password -d client_id=strata-lab-cli -d "client_secret=$LAB_CLI_SECRET" \
    -d username=lab-admin --data-urlencode "password=$LAB_ADMIN_PASSWORD" |
    sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$token" ] || { echo "fleet-init: no admin token" >&2; exit 1; }
auth=(-H "Authorization: Bearer $token" -H 'Content-Type: application/json')

code=$(curl -s -o /tmp/out -w '%{http_code}' "${auth[@]}" -X POST "$cp/v1/groups" -d '{"id":"lab","name":"Lab"}')
case $code in
    200) echo "fleet-init: group lab created" ;;
    409) echo "fleet-init: group lab exists" ;;
    *) echo "fleet-init: create group: $code $(cat /tmp/out)" >&2; exit 1 ;;
esac

umask 077
for node in node-1 node-2; do
    f=/state/enroll/$node.token
    [ -s "$f" ] && continue
    curl -fsS "${auth[@]}" -X POST "$cp/v1/groups/lab/enrollmentTokens" -d '{}' |
        sed -n 's/.*"token":"\([^"]*\)".*/\1/p' > "$f.tmp"
    [ -s "$f.tmp" ] || { echo "fleet-init: no token for $node" >&2; exit 1; }
    mv "$f.tmp" "$f"
    echo "fleet-init: enrollment token for $node"
done

# The first bundle comes from the control plane too, so that its versions
# are the only ones the nodes see: the lab policies, deployed, and put in
# each node's bundle directory so NGINX starts with it. Later bundles reach
# the nodes through their agents (FetchBundle, rollouts).
if [ ! -f /node-1/control ]; then
    ensure() { # id mode oversize
        code=$(curl -s -o /dev/null -w '%{http_code}' "${auth[@]}" "$cp/v1/policies/$1")
        [ "$code" = 200 ] && return 0
        curl -fsS -o /dev/null "${auth[@]}" -X POST "$cp/v1/policies" \
            -d "{\"id\":\"$1\",\"name\":\"$1\",\"spec\":{\"mode\":\"$2\",\"oversize\":\"$3\"}}"
        echo "fleet-init: policy $1 created"
    }
    ensure example-api MODE_ENFORCE OVERSIZE_BLOCK
    ensure example-web MODE_SHADOW OVERSIZE_PASS
    out=$(curl -fsS "${auth[@]}" -X POST "$cp/v1/policies/example-api:deploy" -d '{}')
    field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" <<<"$out"; }
    for d in /node-1 /node-2; do
        cp /bundles/bundle.pub "$d/bundle.pub"
        BUNDLE_DIR=$d /opt/strata/install-bundle.sh "$(field object_key)" "$(field sha256)" "$(field version)"
    done
fi
