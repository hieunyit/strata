#!/usr/bin/env bash
# W10-N-01: builds the node image strata-nginx:<nginx>-<strata> (NGINX +
# module + agent) from the packages of build/packages (deploy/packaging/build.sh).
# Usage: deploy/packaging/build-image.sh [nginx-version...]   (default 1.30.5 1.31.6)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
[ $# -gt 0 ] || set -- 1.30.5 1.31.6
ctx="$root/build/image-ctx"
rm -rf "$ctx" && mkdir -p "$ctx/packages"
cp "$root"/build/packages/*.deb "$ctx/packages/"
cp "$root/deploy/packaging/image/entrypoint.sh" "$ctx/"
ver=$(sed -n 's/^strata-agent_\(.*\)-1_amd64\.deb$/\1/p' <<< "$(cd "$ctx/packages" && ls strata-agent_*.deb)")
[ -n "$ver" ] || { echo "build-image: no strata-agent package: run deploy/packaging/build.sh" >&2; exit 1; }
tagver=${ver//\~/-}
for n in "$@"; do
    docker build -q -f "$root/deploy/packaging/image/Dockerfile" --build-arg "NGINX_VERSION=$n" \
        --label "org.opencontainers.image.version=$ver" -t "strata-nginx:$n-$tagver" -t "strata-nginx:$n" "$ctx" >/dev/null
    echo "build-image: strata-nginx:$n-$tagver"
done
