#!/usr/bin/env bash
# Restores Strata Compact (CP-A09) from an archive of backup.sh: stops the
# control plane, replaces the database, keys, PKI, configuration and
# artifacts (keeping this machine's database and ClickHouse passwords),
# then starts it again. On a new machine run install.sh first.
# Usage: deploy/compact/restore.sh <archive> <passphrase-file> [-yes]
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
[ $# -ge 2 ] || die "usage: restore.sh <archive> <passphrase-file> [-yes]"
archive=$(realpath "$1") pass=$(realpath "$2")
shift 2
if [ ! -f "$archive" ] || [ ! -f "$pass" ]; then die "archive or passphrase file missing"; fi
load_env
"${compose[@]}" stop control-plane
tty=(); [ -t 0 ] || tty=(-T)
"${compose[@]}" run --rm --no-deps "${tty[@]}" -e STRATA_POSTGRES_DSN \
    -v "$archive:/run/strata/archive:ro" -v "$pass:/run/strata/passphrase:ro" control-plane \
    restore -data-dir /var/lib/strata -in /run/strata/archive -passphrase-file /run/strata/passphrase -overwrite "$@"
"${compose[@]}" up -d --wait control-plane
echo "restore: done; the next deploy carries the restored policies to the nodes"
