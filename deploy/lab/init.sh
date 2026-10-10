#!/usr/bin/env bash
# One-shot init of the lab (service lab-init, runs as root):
#   /state/pki      lab CA, control plane certificate (cp.example.test) and
#                   node certificates spiffe://strata/node/node-{1,2}
#   /state/signing  bundle signing key (never leaves the volume)
#   /bundles        bundle-1.sbn, bundle.pub and the control file
# Everything is created once and kept across lab restarts.
set -euo pipefail
umask 077
pki=/state/pki sign=/state/signing bundles=/bundles
mkdir -p "$pki" "$sign" "$bundles"

if [ ! -f "$pki/ca.pem" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
        -subj "/CN=strata lab CA" -keyout "$pki/ca-key.pem" -out "$pki/ca.pem" \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
    issue() { # name subject-CN extensions
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$2" \
            -keyout "$pki/$1-key.pem" -out "$pki/$1.csr"
        openssl x509 -req -in "$pki/$1.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca-key.pem" \
            -CAcreateserial -days 30 -out "$pki/$1.pem" -extfile <(printf '%s\n' "$3")
        rm "$pki/$1.csr"
    }
    issue cp cp.example.test "subjectAltName=DNS:cp.example.test
extendedKeyUsage=serverAuth"
    for n in node-1 node-2; do
        issue "$n" "$n" "subjectAltName=URI:spiffe://strata/node/$n
extendedKeyUsage=clientAuth"
    done
    rm -f "$pki/ca.srl"
fi

if [ ! -f "$sign/bundle.key" ]; then
    # A random seed, used once: the key exists only in this volume.
    mkbundle keygen --seed "$(openssl rand -hex 32)" \
        --key-out "$sign/bundle.key" --pub-out "$sign/bundle.pub"
fi

if [ ! -f "$bundles/control" ]; then
    cd /opt/strata
    strata-compile --rules rules.yaml --policies policies.yaml --version 1 \
        --key "$sign/bundle.key" --out "$bundles/bundle-1.sbn"
    cp "$sign/bundle.pub" "$bundles/bundle.pub"
    mkbundle control --out "$bundles/control" --generation 2 --version 1 \
        --name bundle-1.sbn --bundle "$bundles/bundle-1.sbn"
fi

# The CA key and the signing key stay root-only; the services (uid 1001)
# read certificates, their keys and the bundles.
chown -R 1001:1001 "$pki" "$bundles"
chown root:root "$pki/ca-key.pem"
chmod 0755 /state "$pki" "$bundles"
chmod 0644 "$pki"/*.pem "$bundles"/*
chmod 0600 "$pki/ca-key.pem" "$pki"/*-key.pem
chown -R root:root "$sign" && chmod 0700 "$sign"
echo "lab-init: done"
