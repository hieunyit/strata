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
