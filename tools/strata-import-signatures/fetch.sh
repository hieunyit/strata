#!/usr/bin/env bash
# Downloads the signature sources pinned in sources.lock into
# build/signatures/ and checks their sha256: fetch.sh <sigma|et|bots>
# prints the path to pass as --src. Reuses and verifies a content-addressed archive cache.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
src=${1:?usage: fetch.sh sigma|et|bots}
get() { sed -n "s/^${src}_$1=//p" "$here/sources.lock"; }
url=$(get url) sum=$(get sha256)
[ -n "$url" ] || { echo "fetch.sh: no $src in sources.lock" >&2; exit 2; }
dest="$root/build/signatures/$src-$sum"
# Keep the original pinned bytes: upstream ET's URL changes in place.
# An offline mirror can pre-populate CACHE/<sha256>. Never trust a marker
# file in an extracted tree as a substitute for checking the archive.
cache=${STRATA_SIGNATURE_CACHE:-$root/build/signatures/cache}
mkdir -p "$root/build/signatures" "$cache"
exec 9>"$root/build/signatures/.lock-$src-$sum"
flock 9
archive="$cache/$sum"
if [ ! -f "$archive" ]; then
    tmp=$(mktemp "$cache/.download.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    curl -fsSL --retry 3 -o "$tmp" "$url"
    if ! echo "$sum  $tmp" | sha256sum -c --quiet - >&2; then
        echo "fetch.sh: $src differs from sources.lock; restore the pinned archive from an immutable mirror or review a source update" >&2
        exit 1
    fi
    mv "$tmp" "$archive"
    trap - EXIT
fi
if ! echo "$sum  $archive" | sha256sum -c --quiet - >&2; then
    echo "fetch.sh: corrupt pinned archive: $archive" >&2
    exit 1
fi
extract=$(mktemp -d "$root/build/signatures/.extract.XXXXXX")
trap 'rm -rf "$extract"' EXIT
case "$src" in
    sigma) tar -xzf "$archive" -C "$extract" --strip-components=1 ;;
    et) tar -xzf "$archive" -C "$extract" ;;
    bots) cp "$archive" "$extract/crawler-user-agents.json" ;;
esac
printf '%s\n' "$sum" > "$extract/.verified"
rm -rf "$dest"
mv "$extract" "$dest"
trap - EXIT

case "$src" in
    sigma) echo "$dest" ;;
    et) echo "$dest/rules" ;;
    bots) echo "$dest/crawler-user-agents.json" ;;
esac
