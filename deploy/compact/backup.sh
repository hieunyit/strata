#!/usr/bin/env bash
# Backs up Strata Compact (CP-A09) while it runs: the PostgreSQL dump, then
# keys, PKI, secrets, configuration and artifacts, in one archive encrypted
# with the passphrase of <passphrase-file> (age, scrypt). ClickHouse (event
# history) is not in it.
# Usage: deploy/compact/backup.sh <passphrase-file> [archive name]
#   archive in $STRATA_BACKUP_DIR (default deploy/compact/backups)
set -euo pipefail
source "$(dirname "$0")/lib.sh"
[ $# -ge 1 ] || die "usage: backup.sh <passphrase-file> [archive name]"
pass=$(realpath "$1")
out=${2:-strata-$(date -u +%Y%m%dT%H%M%SZ).tar.age}
[ -f "$pass" ] || die "no passphrase file $pass"
load_env
"${compose[@]}" run --rm --no-deps -T -v "$pass:/run/strata/passphrase:ro" control-plane \
    backup -data-dir /var/lib/strata -out "/var/backups/strata/$out" -passphrase-file /run/strata/passphrase
echo "backup: ${STRATA_BACKUP_DIR:-$here/backups}/$out"
