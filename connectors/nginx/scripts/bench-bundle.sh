#!/usr/bin/env bash
# W09-Q-01: the bundles the benchmarks run with, policy example-api in
# enforce, signed with the test key so connectors/nginx/t/fixtures/bundle.pub
# verifies them (`strata-rules release --policies`):
#   build/bench/pkg/strata-signatures-bench.sbn          every rule of rules/
#   build/bench/pkg-p01/strata-signatures-bench-p01.sbn  phase 0-1 only:
#                                                       rules/protocol, rules/samples
# Usage: bench-bundle.sh  (dev image, after `make rules-tools`)
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
mkdir -p "$root/build/bench"
printf 'policies:\n  - { name: example-api, mode: enforce }\n' > "$root/build/bench/policies.yaml"
p01="$root/build/bench/rules-p01"
rm -rf "$p01" && mkdir -p "$p01"
cp -r "$root/rules/protocol" "$root/rules/samples" "$p01/"
cd "$root/tools/strata-rules"
release() { # version rules-dir out
    go run . release --repo ../.. --version "$1" --rules "$2" --bundle-version 1 \
        --key "$root/connectors/nginx/t/fixtures/test.key" \
        --policies "$root/build/bench/policies.yaml" --out "$3"
}
release bench "$root/rules" "$root/build/bench/pkg"
release bench-p01 "$p01" "$root/build/bench/pkg-p01"
