#!/usr/bin/env bash
# Real lines of the C connector (CLAUDE.md): connectors/nginx/src/*.c and
# *.h without blank lines and comments. count-lines.sh [max]: fails over max.
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
n=$(cat "$root"/connectors/nginx/src/*.c "$root"/connectors/nginx/src/*.h |
    perl -0777 -pe 's{/\*.*?\*/}{}gs; s{//[^\n]*}{}g' | grep -cv '^\s*$')
echo "C connector: $n real lines${1:+, budget $1}"
[ -z "${1:-}" ] || [ "$n" -le "$1" ]
