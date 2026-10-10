#!/usr/bin/env bash
# Regenerates the signed test fixtures. Deterministic: fixed seeds and
# timestamps, so a rerun must not change any committed file.
# Usage: make.sh <path to mkbundle>
set -euo pipefail
mk="${1:?usage: make.sh <mkbundle>}"
cd "$(dirname "$0")"

# test-only keys; never use these seeds anywhere else
"$mk" keygen --seed 0101010101010101010101010101010101010101010101010101010101010101 \
    --key-out test.key --pub-out bundle.pub
"$mk" keygen --seed 0202020202020202020202020202020202020202020202020202020202020202 \
    --key-out other.key --pub-out other.pub

policies=(--policy example-api --policy example-api-upload --policy example-web)

mkdir -p bundle bad empty
"$mk" build --key test.key --version 1 --created-at 1760000000000 "${policies[@]}" \
    --out bundle/bundle-1.sbn
"$mk" control --out bundle/control --generation 2 --version 1 --name bundle-1.sbn \
    --bundle bundle/bundle-1.sbn

# valid layout, signed with another key
"$mk" build --key other.key --version 1 --created-at 1760000000000 "${policies[@]}" \
    --out bad/bundle-1.sbn
"$mk" control --out bad/control --generation 2 --version 1 --name bundle-1.sbn \
    --bundle bad/bundle-1.sbn
rm -f other.pub
