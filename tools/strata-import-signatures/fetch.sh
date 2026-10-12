#!/usr/bin/env bash
# Downloads the signature sources pinned in sources.lock into
# build/signatures/ and checks their sha256: fetch.sh <sigma|et|bots>
# prints the path to pass as --src. Does nothing when it is already there.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
src=${1:?usage: fetch.sh sigma|et|bots}
get() { sed -n "s/^${src}_$1=//p" "$here/sources.lock"; }
url=$(get url) sum=$(get sha256)
[ -n "$url" ] || { echo "fetch.sh: no $src in sources.lock" >&2; exit 2; }
dest="$root/build/signatures/$src-$sum"
if [ ! -f "$dest/.verified" ]; then
    mkdir -p "$root/build/signatures"
    tmp=$(mktemp "$root/build/signatures/.download.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    curl -fsSL --retry 3 -o "$tmp" "$url"
    if ! echo "$sum  $tmp" | sha256sum -c --quiet -; then
        echo "fetch.sh: $src at $url is not the pinned version (sha256 differs); bump sources.lock" >&2
        exit 1
    fi
    rm -rf "$dest" && mkdir -p "$dest"
    case "$src" in
        sigma) tar -xzf "$tmp" -C "$dest" --strip-components=1 ;;
        et) tar -xzf "$tmp" -C "$dest" ;;
        bots) cp "$tmp" "$dest/crawler-user-agents.json" ;;
    esac
    touch "$dest/.verified"
fi
case "$src" in
    sigma) echo "$dest" ;;
    et) echo "$dest/rules" ;;
    bots) echo "$dest/crawler-user-agents.json" ;;
esac
