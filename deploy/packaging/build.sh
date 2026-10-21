#!/usr/bin/env bash
# W10-N-01: builds the Strata packages into build/packages/:
#   nginx-module-strata_<nginx>+<strata>-1_amd64.deb / .x86_64.rpm, one per
#   NGINX version, and strata-agent_<strata>-1_amd64.deb / .x86_64.rpm.
#
# Usage: deploy/packaging/build.sh [nginx-version...]   (default 1.30.5 1.31.6)
# STRATA_VERSION overrides the version (default: git describe, v stripped,
# "-" turned into "~" so a release candidate sorts before the release).
# Runs on a host with Docker: the build in the dev image (deploy/dev/run.sh,
# STRATA_DEV_DOCKER_ARGS applies), the packaging in goreleaser/nfpm.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
[ $# -gt 0 ] || set -- 1.30.5 1.31.6
NFPM_IMAGE=${NFPM_IMAGE:-goreleaser/nfpm:v2.43.1}

if [ -z "${STRATA_VERSION:-}" ]; then
    d=$(git describe --tags --match 'v[0-9]*' 2>/dev/null || echo v0.0.0-dev)
    STRATA_VERSION=$(sed -e 's/^v//' -e 's/-/~/' -e 's/-/./g' <<< "$d")
fi
[[ "$STRATA_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([~.][0-9A-Za-z.~]+)?$ ]] \
    || { echo "packaging: bad STRATA_VERSION $STRATA_VERSION" >&2; exit 1; }
out=build/packages
mkdir -p "$out/bin"
rm -f "$out"/*.deb "$out"/*.rpm

# 1. binaries. The module in the package builder (Rocky 9: glibc 2.34,
# Hyperscan 5.4.2 like the compiler; see builder/Dockerfile), with
# libstrata built without test-hooks (the test needles must not ship) in its
# own target dir, and NGINX configured like nginx.org's (--with-compat, no
# --with-debug). The agent is static Go: built in the dev image.
BUILDER=${BUILDER_IMAGE:-strata-pkg-builder:rocky9}
docker build -q -t "$BUILDER" deploy/packaging/builder >/dev/null
mkdir -p build/cargo-registry
# the module refuses bundles made by another Hyperscan build: the builder's
# must be the compiler's (the dev image)
hsver() { docker run --rm --entrypoint sh "$1" -c "strings $2 | grep -m1 -E '^[0-9]+\.[0-9]+\.[0-9]+ [0-9]{4}-[0-9]{2}-[0-9]{2}\$'"; }
hs_dev=$(hsver "${STRATA_DEV_IMAGE:-strata-dev:latest}" /usr/lib/x86_64-linux-gnu/libhs_runtime.a)
hs_pkg=$(hsver "$BUILDER" /usr/local/lib/libhs_runtime.a)
[ -n "$hs_dev" ] && [ "$hs_dev" = "$hs_pkg" ] \
    || { echo "packaging: Hyperscan of the builder ($hs_pkg) is not the compiler's ($hs_dev)" >&2; exit 1; }
echo "packaging: Hyperscan $hs_pkg, as the compiler"
read -r -a extra <<< "${STRATA_DEV_DOCKER_ARGS:-}"
# the crate cache, unless STRATA_DEV_DOCKER_ARGS mounts one already
cache=(-v "$root/build/cargo-registry:/usr/local/cargo/registry")
[[ " ${extra[*]} " == *":/usr/local/cargo/registry"* ]] && cache=()
docker run --rm "${extra[@]}" "${cache[@]}" -u "$(id -u):$(id -g)" -v "$root:/src" -w /src \
    "$BUILDER" sh -ec '
    # a clean target: nothing linked in another image may leak in
    rm -rf build/pkg-target
    cargo build --release -p libstrata-ffi --target-dir build/pkg-target
    for n in "$@"; do
        STRATA_RELEASE=1 STRATA_LIB=/src/build/pkg-target/release/libstrata.a \
            connectors/nginx/scripts/build.sh "$n" build/pkg-nginx >/dev/null
        cp "build/pkg-nginx/nginx-$n-release/objs/ngx_http_strata_module.so" "build/packages/bin/ngx_http_strata_module-$n.so"
    done
' sh "$@" </dev/null
deploy/dev/run.sh sh -ec 'cd agent && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$1" \
    -o ../build/packages/bin/strata-agent ./cmd/strata-agent' sh "$STRATA_VERSION" </dev/null

# the oldest glibc the module needs (symbol versions)
need=$(docker run --rm -v "$root/build/packages/bin:/b:ro" "$BUILDER" sh -c \
    'objdump -T /b/*.so | grep -o "GLIBC_[0-9.]*" | sort -uV | tail -1')
[ "$need" = GLIBC_2.34 ] || [ "$(printf '%s\nGLIBC_2.34\n' "$need" | sort -V | tail -1)" = GLIBC_2.34 ] \
    || { echo "packaging: the module needs $need, newer than glibc 2.34" >&2; exit 1; }
echo "packaging: the module needs $need at most"

for f in "$out"/bin/*.so; do
    if grep -q 'STRATA-TEST-PANIC' "$f"; then
        echo "packaging: $f carries the test hooks" >&2
        exit 1
    fi
done

# 2. packages (nfpm expands variables in few fields: render the files)
render() { # config, then NAME=value...
    local f=$1; shift
    local args=() kv
    for kv in "$@"; do args+=(-e "s|\${${kv%%=*}}|${kv#*=}|g"); done
    sed "${args[@]}" "$f"
}
nfpm() { # config file under build/, packager
    docker run --rm -u "$(id -u):$(id -g)" -v "$root:/src" -w /src "$NFPM_IMAGE" \
        package -f "$1" -p "$2" -t "$out/"
}
render deploy/packaging/nfpm-agent.yaml "STRATA_VERSION=$STRATA_VERSION" "AGENT_BIN=$out/bin/strata-agent" \
    > "$out/nfpm-agent.yaml"
for n in "$@"; do
    python3 deploy/packaging/module_manifest.py --root "$root" --binary "$out/bin/ngx_http_strata_module-$n.so" \
        --module-path /usr/lib/nginx/modules/ngx_http_strata_module.so > "$out/bin/module-deb-$n.json"
    python3 deploy/packaging/module_manifest.py --root "$root" --binary "$out/bin/ngx_http_strata_module-$n.so" \
        --module-path /usr/lib64/nginx/modules/ngx_http_strata_module.so > "$out/bin/module-rpm-$n.json"
    render deploy/packaging/nfpm-module.yaml "STRATA_VERSION=$STRATA_VERSION" "NGINX_VERSION=$n" \
        "MODULE_SO=$out/bin/ngx_http_strata_module-$n.so" "MODULE_MANIFEST_DEB=$out/bin/module-deb-$n.json" "MODULE_MANIFEST_RPM=$out/bin/module-rpm-$n.json" > "$out/nfpm-module-$n.yaml"
done
for p in deb rpm; do
    nfpm "$out/nfpm-agent.yaml" "$p"
    for n in "$@"; do nfpm "$out/nfpm-module-$n.yaml" "$p"; done
done
cp deploy/packaging/install.sh deploy/packaging/install-standalone.sh "$out/"
(cd "$out" && sha256sum ./*.deb ./*.rpm install.sh install-standalone.sh > SHA256SUMS)
echo "packaging: $STRATA_VERSION"
ls -l "$out"/*.deb "$out"/*.rpm
