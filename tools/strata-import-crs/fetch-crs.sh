#!/usr/bin/env bash
# Downloads the CRS release pinned in crs.lock into build/crs/ and checks
# its sha256. Prints the directory. Does nothing when it is already there.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
version=$(sed -n 's/^version=//p' "$here/crs.lock")
url=$(sed -n 's/^url=//p' "$here/crs.lock")
sum=$(sed -n 's/^sha256=//p' "$here/crs.lock")
dest="$root/build/crs/coreruleset-$version"
if [ ! -f "$dest/.verified" ]; then
    mkdir -p "$root/build/crs"
    tmp=$(mktemp "$root/build/crs/.download.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    curl -fsSL --retry 3 -o "$tmp" "$url"
    echo "$sum  $tmp" | sha256sum -c --quiet -
    rm -rf "$dest"
    tar -xzf "$tmp" -C "$root/build/crs"
    touch "$dest/.verified"
fi
echo "$dest"
