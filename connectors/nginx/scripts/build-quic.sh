#!/usr/bin/env bash
# Builds quictls (the OpenSSL QUIC fork) into <prefix>, for the NGINX
# --with-http_v3_module variant that build.sh produces (W08-N-01). NGINX
# needs a QUIC-capable TLS library for HTTP/3; the stock OpenSSL 3.0 in the
# dev image has no QUIC API. The pure-Perl HTTP/3 client used by the tests
# (connectors/nginx/t/lib/Test/Strata/HTTP3.pm) needs no native library.
#
# Usage: build-quic.sh <prefix>
# Output: <prefix>/lib/{libssl.a,libcrypto.a} and <prefix>/include/openssl.
set -euo pipefail

prefix="${1:?usage: build-quic.sh <prefix>}"
tag="${QUICTLS_TAG:-openssl-3.1.7+quic}"
mkdir -p "$prefix"
prefix="$(cd "$prefix" && pwd)"

if [ -f "$prefix/lib/libssl.a" ] && [ -f "$prefix/lib/libcrypto.a" ]; then
    echo "quictls already built at $prefix"
    exit 0
fi

src="$prefix/src"
if [ ! -d "$src" ]; then
    git clone --depth 1 -b "$tag" https://github.com/quictls/openssl "$src.tmp"
    mv "$src.tmp" "$src"
fi

cd "$src"
# Static libs only, in lib/ (not lib64), no tests/docs: just what NGINX links.
./config --prefix="$prefix" --libdir=lib no-shared no-tests
make -j"$(nproc)"
make install_sw
ls -l "$prefix/lib/libssl.a" "$prefix/lib/libcrypto.a"
