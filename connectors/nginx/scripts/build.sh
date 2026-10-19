#!/usr/bin/env bash
# Builds NGINX <version> with ngx_http_strata_module as a dynamic module.
# Usage: connectors/nginx/scripts/build.sh <nginx-version> [build-dir]
# Output: <build-dir>/nginx-<version>[-asan]/objs/{nginx,ngx_http_strata_module.so}
#
# STRATA_SANITIZE=1 builds an ASan + UBSan variant in nginx-<version>-asan.
# STRATA_RELEASE=1 builds the module the packages ship, in
# nginx-<version>-release: no --with-debug, like nginx.org's own builds
# (deploy/packaging, W10-N-01).
set -euo pipefail

version="${1:?usage: build.sh <nginx-version> [build-dir]}"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
build="$(mkdir -p "${2:-$root/build}" && cd "${2:-$root/build}" && pwd)"

# The module must build warning-free with hardening flags. They apply to the
# whole tree because NGINX has no per-module CFLAGS.
if [ "${STRATA_SANITIZE:-}" = 1 ]; then
    src="$build/nginx-$version-asan"
    # _FORTIFY_SOURCE is left out: it hides overflows from ASan.
    # Excluded UBSan checks, both triggered by NGINX core by design and
    # stopping the server before any module code runs:
    #   nonnull-attribute  memcpy(dst, NULL, 0) in ngx_cpystrn and friends
    #   alignment          unaligned uint32 stores in the HTTP/2 framing code
    san="-fsanitize=address,undefined -fno-sanitize=nonnull-attribute,alignment"
    san="$san -fno-sanitize-recover=undefined"
    cc_opt="-O1 -g -fno-omit-frame-pointer $san -Wall -Wextra -Werror -fstack-protector-strong"
    ld_opt="$san -Wl,-z,relro -Wl,-z,now"
elif [ "${STRATA_HTTP3:-}" = 1 ]; then
    # HTTP/3 needs a QUIC-capable TLS library; the dev image's OpenSSL 3.0 has
    # none, so link a static quictls (built here or baked into the image at
    # /opt/quictls). A separate build dir keeps the plain/asan builds on the
    # system OpenSSL.
    quic="${STRATA_QUIC_SSL:-}"
    if [ -z "$quic" ]; then
        if [ -f /opt/quictls/lib/libssl.a ]; then
            quic=/opt/quictls
        else
            quic="$build/quic/quictls"
            [ -f "$quic/lib/libssl.a" ] || "$root/connectors/nginx/scripts/build-quic.sh" "$quic"
        fi
    fi
    src="$build/nginx-$version-h3"
    cc_opt="-O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -I$quic/include"
    ld_opt="-L$quic/lib -Wl,-z,relro -Wl,-z,now"
    v3="--with-http_v3_module"
elif [ "${STRATA_RELEASE:-}" = 1 ]; then
    src="$build/nginx-$version-release"
    cc_opt="-O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2"
    ld_opt="-Wl,-z,relro -Wl,-z,now"
    debug=""
else
    src="$build/nginx-$version"
    cc_opt="-O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2"
    ld_opt="-Wl,-z,relro -Wl,-z,now"
fi
: "${v3:=}"
debug="${debug---with-debug}"

if [ ! -d "$src" ]; then
    mkdir -p "$build/dl" "$src.tmp"
    tarball="$build/dl/nginx-$version.tar.gz"
    [ -f "$tarball" ] || curl -fsSL -o "$tarball" "https://nginx.org/download/nginx-$version.tar.gz"
    tar -xzf "$tarball" -C "$src.tmp" --strip-components=1
    mv "$src.tmp" "$src"
fi

cd "$src"

# --with-http_ssl_module: like nginx.org's builds, so the module's TLS code
# (STRATA_TXF_TLS, JA4) is compiled in; without it the module ignored TLS.
lib="${STRATA_LIB:-$root/target/release/libstrata.a}"
modules="--with-compat --with-threads $debug --with-http_ssl_module"
modules="$modules --with-http_v2_module --with-http_auth_request_module $v3"
# the configure options are part of the stamp: changing them reconfigures
stamp="$modules|$cc_opt|$ld_opt|$root|$lib|$(cksum < "$root/connectors/nginx/config")"
if [ ! -f objs/Makefile ] || [ "$(cat objs/.strata-configure 2>/dev/null)" != "$stamp" ]; then
    # shellcheck disable=SC2086 # $modules is a list of options
    ./configure $modules \
        --with-cc-opt="$cc_opt" --with-ld-opt="$ld_opt" \
        --add-dynamic-module="$root/connectors/nginx"
    echo "$stamp" > objs/.strata-configure
fi

# NGINX's link rule for the module does not depend on libstrata.a: force a
# relink when the archive is newer, or Rust changes would silently be lost.
if [ -f objs/ngx_http_strata_module.so ] && [ "$lib" -nt objs/ngx_http_strata_module.so ]; then
    rm -f objs/ngx_http_strata_module.so
fi

make -j"$(nproc)"
make modules
ls -l objs/nginx objs/ngx_http_strata_module.so
