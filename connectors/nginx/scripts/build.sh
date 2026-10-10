#!/usr/bin/env bash
# Builds NGINX <version> with ngx_http_strata_module as a dynamic module.
# Usage: connectors/nginx/scripts/build.sh <nginx-version> [build-dir]
# Output: <build-dir>/nginx-<version>[-asan]/objs/{nginx,ngx_http_strata_module.so}
#
# STRATA_SANITIZE=1 builds an ASan + UBSan variant in nginx-<version>-asan.
set -euo pipefail

version="${1:?usage: build.sh <nginx-version> [build-dir]}"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
build="$(mkdir -p "${2:-$root/build}" && cd "${2:-$root/build}" && pwd)"

# The module must build warning-free with hardening flags. They apply to the
# whole tree because NGINX has no per-module CFLAGS.
if [ "${STRATA_SANITIZE:-}" = 1 ]; then
    src="$build/nginx-$version-asan"
    # _FORTIFY_SOURCE is left out: it hides overflows from ASan.
    san="-fsanitize=address,undefined -fno-sanitize-recover=undefined"
    cc_opt="-O1 -g -fno-omit-frame-pointer $san -Wall -Wextra -Werror -fstack-protector-strong"
    ld_opt="$san -Wl,-z,relro -Wl,-z,now"
else
    src="$build/nginx-$version"
    cc_opt="-O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2"
    ld_opt="-Wl,-z,relro -Wl,-z,now"
fi

if [ ! -d "$src" ]; then
    mkdir -p "$build/dl" "$src.tmp"
    tarball="$build/dl/nginx-$version.tar.gz"
    [ -f "$tarball" ] || curl -fsSL -o "$tarball" "https://nginx.org/download/nginx-$version.tar.gz"
    tar -xzf "$tarball" -C "$src.tmp" --strip-components=1
    mv "$src.tmp" "$src"
fi

cd "$src"

stamp="$cc_opt|$ld_opt|$root"
if [ ! -f objs/Makefile ] || [ "$(cat objs/.strata-configure 2>/dev/null)" != "$stamp" ]; then
    ./configure \
        --with-compat --with-threads --with-debug \
        --with-http_v2_module --with-http_auth_request_module \
        --with-cc-opt="$cc_opt" --with-ld-opt="$ld_opt" \
        --add-dynamic-module="$root/connectors/nginx"
    echo "$stamp" > objs/.strata-configure
fi

make -j"$(nproc)"
make modules
ls -l objs/nginx objs/ngx_http_strata_module.so
