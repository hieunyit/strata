# shellcheck shell=bash
# Shared by install.sh, backup.sh and restore.sh.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
state=${STRATA_COMPACT_STATE:-$here/.state}
compose=(docker compose -f "$here/compose.yaml")
[ -n "${STRATA_COMPACT_OVERLAY:-}" ] && compose+=(-f "$STRATA_COMPACT_OVERLAY")
compose+=(--env-file "$state/env")
die() { echo "$(basename "$0"): $*" >&2; exit 1; }

# load the passwords into this shell only (they reach a container's
# environment for one-off init and restore, never a command line)
load_env() {
    [ -f "$state/env" ] || die "no $state/env: run install.sh first"
    set -a
    # shellcheck disable=SC1091
    . "$state/env"
    set +a
    export STRATA_POSTGRES_DSN="postgres://strata:${POSTGRES_PASSWORD}@postgres:5432/strata?sslmode=disable"
    export STRATA_CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD"
}
