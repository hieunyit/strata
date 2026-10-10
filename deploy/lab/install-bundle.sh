#!/usr/bin/env bash
# Installs a deployed bundle on the lab nodes: install-bundle.sh <object key>
# <sha256> <version>. It downloads the bundle from MinIO, checks its hash,
# writes it next to the others under a new name, and points the control
# file at it (in place, seqlock generation +2), so every NGINX worker loads
# it within a second. Until the agent fetches bundles itself (W05-G1-01),
# this script plays its part.
set -euo pipefail
key=$1 sum=$2 version=$3
dir=/bundles
name=bundle-$version.sbn
tmp=$(mktemp "$dir/.download.XXXXXX")
trap 'rm -f "$tmp"' EXIT
curl -fsS --aws-sigv4 "aws:amz:us-east-1:s3" --user "strata:$MINIO_ROOT_PASSWORD" \
    -o "$tmp" "http://minio:9000/strata-bundles/$key"
echo "$sum  $tmp" | sha256sum -c --quiet -
chmod 0644 "$tmp"
mv "$tmp" "$dir/$name"
if [ -f "$dir/control" ]; then
    gen=$(od -An -t u8 -j 16 -N 8 "$dir/control" | tr -d ' ')
    [ $((gen % 2)) = 0 ] || { echo "install-bundle: control file is being written" >&2; exit 1; }
    mkbundle control --out "$dir/control" --in-place --generation $((gen + 2)) \
        --version "$version" --name "$name" --bundle "$dir/$name"
else
    mkbundle control --out "$dir/control" --generation 2 --version "$version" --name "$name" --bundle "$dir/$name"
    chmod 0644 "$dir/control"
fi
echo "install-bundle: bundle $version installed"
