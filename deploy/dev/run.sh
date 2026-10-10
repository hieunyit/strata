#!/usr/bin/env bash
# Run a command inside the Strata dev image with the repo mounted at /src.
# Usage: deploy/dev/run.sh make test
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${STRATA_DEV_IMAGE:-strata-dev:latest}"
if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker build -t "$image" "$root/deploy/dev"
fi
tty=()
[ -t 0 ] && tty=(-it)
# extra docker options, e.g. STRATA_DEV_DOCKER_ARGS="--cap-add SYS_PTRACE"
read -r -a extra <<< "${STRATA_DEV_DOCKER_ARGS:-}"
# Go module and build caches survive runs under build/go.
exec docker run --rm "${tty[@]}" "${extra[@]}" -u "$(id -u):$(id -g)" \
    -e GOMODCACHE=/src/build/go/mod -e GOCACHE=/src/build/go/cache \
    -v "$root:/src" -w /src "$image" "$@"
