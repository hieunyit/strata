#!/usr/bin/env bash
# Writes compile_commands.json for the module's sources from an NGINX build
# tree (connectors/nginx/scripts/build.sh): the exact commands `make
# modules` runs, so clang-tidy sees the flags, includes and macros NGINX
# uses. Usage: compile-commands.sh <nginx build dir> > compile_commands.json
set -euo pipefail
dir="$(cd "${1:?usage: compile-commands.sh <nginx build dir>}" && pwd)"
make -s -n -B -C "$dir" -f objs/Makefile modules 2>/dev/null |
    sed -e ':a' -e '/\\$/N; s/\\\n//; ta' |
    tr -s '\t' ' ' |
    grep -E '^ *cc (.* )?-c .*connectors/nginx/src/[a-z_]+\.c *$' |
    sed 's/^ *//; s/ *$//' |
    awk -v dir="$dir" 'BEGIN { print "[" } {
        file = $NF
        gsub(/\\/, "\\\\"); gsub(/"/, "\\\"")
        printf "%s{\"directory\": \"%s\", \"file\": \"%s\", \"command\": \"%s\"}\n", (NR > 1 ? "," : ""), dir, file, $0
    } END { print "]" }'
