#!/usr/bin/env bash
# Installs (or replaces) the crontab line of deploy/nightly/nightly.sh:
# 19:00 UTC, 02:00 in Vietnam, as in .github/workflows/nightly.yml.
# --remove takes it out.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tag="# strata-nightly"
current=$(crontab -l 2>/dev/null | grep -v -- "$tag" || true)
if [ "${1:-}" = "--remove" ]; then
    printf '%s\n' "$current" | sed '/^$/d' | crontab -
    echo "nightly: cron line removed"
    exit 0
fi
{ printf '%s\n' "$current" | sed '/^$/d'; echo "0 19 * * * $here/nightly.sh >/dev/null 2>&1 $tag"; } | crontab -
crontab -l | grep -- "$tag"
