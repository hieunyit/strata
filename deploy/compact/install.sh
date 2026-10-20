#!/usr/bin/env bash
# Installs Strata Compact (CP-A09) on this machine: passwords, the database
# services, then strata-control-plane init (PKI, bundle signing key, first
# admin, config.yaml in the strata-data volume), then the control plane.
# Run again: changes nothing that exists (init creates only what is missing).
# Usage: deploy/compact/install.sh -name <host or IP the nodes reach>[,more]
#            [-admin-password-file <file>]   (default: asked twice)
set -euo pipefail
source "$(dirname "$0")/lib.sh"
name="" pwfile=""
while [ $# -gt 0 ]; do
    case $1 in
        -name) name=$2; shift 2 ;;
        -admin-password-file) pwfile=$2; shift 2 ;;
        *) die "unknown argument $1" ;;
    esac
done
[ -n "$name" ] || die "give -name: the DNS name or IP address agents use to reach Fleet"
docker image inspect "strata-control-plane:${STRATA_VERSION:-compact}" >/dev/null 2>&1 ||
    die "no image strata-control-plane:${STRATA_VERSION:-compact}: run deploy/compact/build.sh"

# 1. passwords of the services, made once (0600, outside any volume)
umask 077
mkdir -p "$state" "${STRATA_BACKUP_DIR:-$here/backups}"
if [ ! -f "$state/env" ]; then
    gen() { head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32; }
    {
        echo "POSTGRES_PASSWORD=$(gen)"
        echo "CLICKHOUSE_PASSWORD=$(gen)"
        echo "KEYCLOAK_ADMIN_PASSWORD=$(gen)"
        echo "STRATA_UID=$(id -u)"
        echo "STRATA_GID=$(id -g)"
    } > "$state/env"
    echo "install: passwords in $state/env (keep it with your backups' passphrase, not in them)"
fi
load_env

# 2. databases
"${compose[@]}" up -d --wait postgres clickhouse

# 3. the data volume belongs to the installing user (see compose.yaml)
"${compose[@]}" run --rm --no-deps --user root --entrypoint chown control-plane "$STRATA_UID:$STRATA_GID" /var/lib/strata /var/backups/strata

# 4. init: the first admin's password through stdin, never a command line
if [ -z "$pwfile" ]; then
    read -r -s -p "password of the first admin (12+ characters): " pw1; echo >&2
    read -r -s -p "again: " pw2; echo >&2
    [ "$pw1" = "$pw2" ] || die "the two passwords differ"
    exec 3<<<"$pw1"
    unset pw1 pw2
else
    exec 3<"$pwfile"
fi
"${compose[@]}" run --rm --no-deps -T -e STRATA_POSTGRES_DSN -e STRATA_CLICKHOUSE_PASSWORD control-plane \
    init -data-dir /var/lib/strata -name "$name" -clickhouse clickhouse:9000 -admin-password-file /dev/stdin <&3
exec 3<&-

# 5. the control plane (and the overlay's services)
"${compose[@]}" up -d --wait
echo "install: Strata is up on http://${STRATA_HTTP_BIND:-127.0.0.1}:${STRATA_HTTP_PORT:-8080} (user admin); Fleet on :${STRATA_FLEET_PORT:-8443}"
