#!/usr/bin/env bash
# Regenerates the signed test fixtures. Deterministic: fixed seeds and
# timestamps, so a rerun must not change any committed file.
# Usage: make.sh <bin dir with mkbundle and strata-compile>
set -euo pipefail
bin="${1:?usage: make.sh <dir with mkbundle and strata-compile>}"
cd "$(dirname "$0")"
root="$(cd ../../../.. && pwd)"

# test-only keys; never use these seeds anywhere else
"$bin/mkbundle" keygen --seed 0101010101010101010101010101010101010101010101010101010101010101 \
    --key-out test.key --pub-out bundle.pub
"$bin/mkbundle" keygen --seed 0202020202020202020202020202020202020202020202020202020202020202 \
    --key-out other.key --pub-out other.pub

compile() {
    "$bin/strata-compile" --rules "$root/engine/compiler/examples/rules.yaml" \
        --policies policies.yaml --version 1 --created-at 1760000000000 "$@" 2>/dev/null
}

mkdir -p bundle bad empty
compile --key test.key --out bundle/bundle-1.sbn
"$bin/mkbundle" control --out bundle/control --generation 2 --version 1 --name bundle-1.sbn \
    --bundle bundle/bundle-1.sbn

# valid layout, signed with another key
compile --key other.key --out bad/bundle-1.sbn
"$bin/mkbundle" control --out bad/control --generation 2 --version 1 --name bundle-1.sbn \
    --bundle bad/bundle-1.sbn
rm -f other.pub
