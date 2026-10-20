#!/usr/bin/env bash
# Downloads the CRS rule exclusion plugins pinned in crs-plugins.lock into
# build/crs-plugins/<name>-<version>/ and checks each sha256. Prints the
# directory. Does nothing for a plugin already there.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
base="$root/build/crs-plugins"
mkdir -p "$base"
grep -v '^#' "$here/crs-plugins.lock" | while read -r name version sum; do
    [ -n "$name" ] || continue
    dest="$base/$name-$version"
    if [ ! -f "$dest/.verified" ]; then
        tmp=$(mktemp "$base/.download.XXXXXX")
        curl -fsSL --retry 3 -o "$tmp" \
            "https://github.com/coreruleset/$name-rule-exclusions-plugin/archive/refs/tags/$version.tar.gz"
        if ! echo "$sum  $tmp" | sha256sum -c --quiet -; then
            rm -f "$tmp"
            exit 1
        fi
        rm -rf "$dest"
        mkdir -p "$dest"
        tar -xzf "$tmp" -C "$dest" --strip-components=1
        rm -f "$tmp"
        touch "$dest/.verified"
    fi
done
echo "$base"
