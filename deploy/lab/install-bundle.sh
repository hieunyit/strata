#!/usr/bin/env bash
# Puts the lab's first bundle in a node's bundle directory before NGINX and
# the agent start: install-bundle.sh <object key> <sha256> <version>, with
# BUNDLE_DIR (default /bundles). It downloads the bundle from MinIO, checks
# its hash, writes it under its name and creates or updates the control
# file (in place, seqlock). Every later bundle is installed by the agent.
set -euo pipefail
key=$1 sum=$2 version=$3
dir=${BUNDLE_DIR:-/bundles}
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
