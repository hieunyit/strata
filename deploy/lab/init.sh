#!/usr/bin/env bash
# One-shot init of the lab (service lab-init, runs as root):
#   /state/pki      lab CA and the control plane certificate (cp.example.test);
#                   node CA, whose key the control plane uses to issue node
#                   certificates at enrollment
#   /state/enroll   enrollment tokens, written by fleet-init.sh
#   /bundles        the bundles and the control file come from the control
#                   plane (fleet-init.sh, install-bundle.sh); bundle.pub is
#                   the public key of the Vault signing key (vault/init.sh)
# Everything is created once and kept across lab restarts.
set -euo pipefail
umask 077
pki=/state/pki bundles=/bundles
mkdir -p "$pki" "$bundles"

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
    rm -f "$pki/ca.srl"
fi

if [ ! -f "$pki/node-ca.pem" ]; then
    # Separate from the lab CA: the control plane holds this key to sign
    # node certificates (24 h) when agents enroll.
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
        -subj "/CN=strata lab node CA" -keyout "$pki/node-ca-key.pem" -out "$pki/node-ca.pem" \
        -addext basicConstraints=critical,CA:TRUE,pathlen:0 -addext keyUsage=critical,keyCertSign,cRLSign
fi
mkdir -p /state/enroll

# Bundles are signed in Vault (vault/init.sh); a file key from an older
# lab is not used any more.
rm -rf /state/signing

# The CA key and the signing key stay root-only; the services (uid 1001)
# read certificates, their keys and the bundles.
# each node's bundle directory: its agent writes it, its NGINX reads it
chown 1001:1001 /node-1 /node-2 && chmod 0755 /node-1 /node-2
chown -R 1001:1001 "$pki" "$bundles" /state/enroll
chmod 0700 /state/enroll
chown root:root "$pki/ca-key.pem"
chmod 0755 /state "$pki" "$bundles"
chmod 0644 "$pki"/*.pem
chmod 0600 "$pki/ca-key.pem" "$pki"/*-key.pem
echo "lab-init: done"
