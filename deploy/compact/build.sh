#!/usr/bin/env bash
# CP-A09: builds the Compact control plane image strata-control-plane:<version>
# from this checkout: the Web UI (in the node image), the binaries (in the
# dev image: control plane with the UI built in, strata-compile,
# strata-replay), the core rule pack (CRS, protocol, virtual patches) and
# the replay corpus, then the runtime image (deploy/compact/Dockerfile).
# Usage: deploy/compact/build.sh [version]   (default: git describe)
# Docker options for the build containers: STRATA_DEV_DOCKER_ARGS
# (e.g. "--cpuset-cpus=6-10").
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
version=${1:-$(git -C "$root" describe --tags --always --dirty 2>/dev/null || echo dev)}
commit=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)
read -r -a extra <<< "${STRATA_DEV_DOCKER_ARGS:-}"

# 1. the Web UI
docker run --rm "${extra[@]}" -u "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_cache=/src/build/npm-cache \
    -v "$root:/src" -w /src/ui node:24.21.0-bookworm-slim \
    sh -ec 'npm ci --no-audit --no-fund && npm run build'

# 2. binaries, rules, corpus
"$root/deploy/dev/run.sh" deploy/compact/build-inner.sh "$version" "$commit" </dev/null

# 3. the image
docker build -q -t "strata-control-plane:$version" -t strata-control-plane:compact "$root/build/compact/dist" >/dev/null
echo "build: strata-control-plane:$version (also :compact)"
