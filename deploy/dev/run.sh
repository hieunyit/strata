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
exec docker run --rm "${tty[@]}" -u "$(id -u):$(id -g)" \
    -v "$root:/src" -w /src "$image" "$@"
