#!/usr/bin/env bash
# Bundle signing key rotation on a running lab (make lab-up), the procedure
# of docs/design/control-file.md › "Xoay khóa ký bundle":
#   1 pin the signing version N; 2 rotate in Vault (N+1); 3 give every node
#   and the control plane both public keys; 4 check each node trusts N+1
#   (diagnostics); 5 sign with N+1, deploy (lab-chain); 6 drop key N.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
lab="$here/../../deploy/lab"
C=(docker compose -f "$lab/compose.yaml" --env-file "$lab/.state/env")
. "$lab/.state/env"
say() { printf 'lab-key-rotation: %s\n' "$*"; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

root=$("${C[@]}" run --rm -T --entrypoint sh vault-init -c "tr -d '\n ' < /keys/init.json" 2>/dev/null |
    sed -n 's/.*"root_token":"\([^"]*\)".*/\1/p')
vault() { "${C[@]}" exec -T -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN="$root" vault vault "$@"; }
keys() { vault read -format=json transit/keys/strata-bundles; }
pub() { # version -> raw public key into a file
    keys | python3 -c "import json,sys,base64; sys.stdout.buffer.write(base64.b64decode(json.load(sys.stdin)['data']['keys']['$1']['public_key']))" > "$2"
}
fp() { sha256sum "$1" | cut -c1-16; }

# put file $1 as bundle.pub everywhere: the control plane's trust set, each
# node's NGINX (bundle dir) and agent (identity dir)
distribute() {
    for v in bundles bundles-node-1 bundles-node-2 identity-node-1 identity-node-2; do
        docker run --rm -i -v "strata-lab_$v:/d" alpine:3.20 sh -c 'cat > /d/bundle.pub.new && chown 1001:1001 /d/bundle.pub.new && chmod 0644 /d/bundle.pub.new && mv /d/bundle.pub.new /d/bundle.pub' < "$1"
    done
    for n in nginx-stable nginx-mainline; do
        "${C[@]}" exec -T "$n" sh -c '/opt/nginx/$NGINX_VERSION/nginx -p /tmp/nginx -c /tmp/nginx/nginx.conf -s reload'
    done
    "${C[@]}" restart agent-1 agent-2 >/dev/null
}

cp_at() { # signing version
    LAB_VAULT_KEY_VERSION=$1 "${C[@]}" up -d --wait --wait-timeout 300 control-plane >/dev/null 2>&1
}

token=$(curl -fsS http://127.0.0.1:18180/realms/strata/protocol/openid-connect/token -d grant_type=password -d client_id=strata-lab-cli \
    -d "client_secret=$LAB_CLI_SECRET" -d username=lab-admin --data-urlencode "password=$LAB_ADMIN_PASSWORD" |
    sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
api() { curl -fsS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' "$@"; }
trusts() { # fingerprint -> every node lists it in its diagnostics
    local want=$1 ok=0
    for id in $(api http://127.0.0.1:18090/v1/nodes | python3 -c 'import json,sys; [print(n["id"]) for n in json.load(sys.stdin)["nodes"] if n["online"]]'); do
        cmd=$(api -X POST -d '{}' "http://127.0.0.1:18090/v1/nodes/$id:collectDiagnostics" | python3 -c 'import json,sys; print(json.load(sys.stdin)["command"]["id"])')
        for _ in $(seq 30); do
            out=$(api "http://127.0.0.1:18090/v1/commands/$cmd")
            grep -q '"state":"DONE"' <<<"$out" && break
            sleep 1
        done
        if python3 -c "import json,sys; d=json.loads(json.load(sys.stdin)['command']['output']); sys.exit(0 if '$want' in d['bundle']['trusted_keys'] else 1)" <<<"$out"; then
            ok=$((ok + 1))
        else
            say "FAIL: node $id does not trust $want"; return 1
        fi
    done
    [ "$ok" -ge 2 ]
}

N=$(vault read -field=latest_version transit/keys/strata-bundles)
pub "$N" "$work/old.pub"
say "1. signing with version $N (key $(fp "$work/old.pub")): pinned"
cp_at "$N"

vault write -f transit/keys/strata-bundles/rotate >/dev/null
M=$((N + 1))
pub "$M" "$work/new.pub"
say "2. rotated in Vault: version $M, key $(fp "$work/new.pub")"

cat "$work/old.pub" "$work/new.pub" > "$work/both.pub"
distribute "$work/both.pub"
cp_at "$N"
say "3. nodes and control plane trust both keys"
sleep 5
trusts "$(fp "$work/new.pub")"
say "4. every node trusts version $M"

cp_at "$M"
say "5. signing with version $M"
"$here/lab-chain.sh" | tail -1

distribute "$work/new.pub"
cp_at "$M"
sleep 5
trusts "$(fp "$work/new.pub")"
"$here/lab-chain.sh" | tail -1
say "6. key $N dropped; bundles signed with $M only: all steps passed"
