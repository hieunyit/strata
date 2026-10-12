#!/bin/sh
# One-shot at each lab start (service vault-init): initializes Vault once
# (one unseal key, kept with the root token in the vault-keys volume: lab
# only), unseals it, and makes sure of
#   transit/keys/strata-bundles  ed25519, not exportable: bundles are signed
#                                in Vault, the key never leaves it
#   policy strata-signer         sign with that key and read it, nothing else
#   a token with only that policy, for the control plane, in
#   /signer/token (a volume only the control plane mounts)
# Then writes the key's public key (32 raw bytes) to /bundles/bundle.pub,
# which nodes and NGINX use to verify bundles.
set -eu
flat() { tr -d '\n '; }
if vault status -format=json 2>/dev/null | flat | grep -q '"initialized":false'; then
    umask 077
    vault operator init -key-shares=1 -key-threshold=1 -format=json > /keys/init.json
    echo "vault-init: initialized"
fi
init=$(flat < /keys/init.json)
unseal=$(echo "$init" | sed -n 's/.*"unseal_keys_b64":\["\([^"]*\)".*/\1/p')
root=$(echo "$init" | sed -n 's/.*"root_token":"\([^"]*\)".*/\1/p')
if vault status -format=json 2>/dev/null | flat | grep -q '"sealed":true'; then
    vault operator unseal "$unseal" > /dev/null
fi
export VAULT_TOKEN="$root"
vault secrets list -format=json | flat | grep -q '"transit/"' || vault secrets enable transit
vault read transit/keys/strata-bundles > /dev/null 2>&1 ||
    vault write -f transit/keys/strata-bundles type=ed25519 exportable=false allow_plaintext_backup=false
vault policy write strata-signer - > /dev/null <<'POLICY'
path "transit/sign/strata-bundles" { capabilities = ["update"] }
path "transit/keys/strata-bundles" { capabilities = ["read"] }
POLICY
if [ -s /signer/token ] && vault token renew "$(cat /signer/token)" > /dev/null 2>&1; then
    : # still valid: renewed
else
    umask 077
    vault token create -policy=strata-signer -no-default-policy -orphan -period=720h -field=token > /signer/token.new
    chown 1001:1001 /signer/token.new
    mv /signer/token.new /signer/token
    echo "vault-init: new signer token"
fi
# bundle.pub: written once; later the key rotation procedure owns it
# (docs/design/control-file.md, "Xoay khóa ký bundle")
if [ -s /bundles/bundle.pub ]; then
    echo "vault-init: transit key strata-bundles ready, bundle.pub kept"
    exit 0
fi
vault read -format=json transit/keys/strata-bundles | flat |
    sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p' | base64 -d > /bundles/bundle.pub.new
[ "$(wc -c < /bundles/bundle.pub.new)" -eq 32 ] || { echo "vault-init: bad public key" >&2; exit 1; }
chmod 0644 /bundles/bundle.pub.new && chown 1001:1001 /bundles/bundle.pub.new
mv /bundles/bundle.pub.new /bundles/bundle.pub
echo "vault-init: transit key strata-bundles ready, public key in /bundles/bundle.pub"
