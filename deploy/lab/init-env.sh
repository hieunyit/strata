#!/usr/bin/env bash
# Creates deploy/lab/.state/env with random lab passwords, once. The file is
# git-ignored; delete it (make lab-clean) to start over.
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)/.state"
mkdir -p "$dir"
env="$dir/env"
pw() { head -c 18 /dev/urandom | base64 | tr -d '/+='; }
umask 077
# Added later: appended to an existing file too.
if [ -f "$env" ]; then
    grep -q '^LAB_LOCAL_ADMIN_PASSWORD=' "$env" || echo "LAB_LOCAL_ADMIN_PASSWORD=$(pw)" >> "$env"
    exit 0
fi
cat > "$env" <<EOT
CLICKHOUSE_PASSWORD=$(pw)
POSTGRES_PASSWORD=$(pw)
KEYCLOAK_ADMIN_PASSWORD=$(pw)
MINIO_ROOT_PASSWORD=$(pw)
GRAFANA_ADMIN_PASSWORD=$(pw)
LAB_CLI_SECRET=$(pw)
LAB_VIEWER_PASSWORD=$(pw)
LAB_OPERATOR_PASSWORD=$(pw)
LAB_APPROVER_PASSWORD=$(pw)
LAB_ADMIN_PASSWORD=$(pw)
LAB_LOCAL_ADMIN_PASSWORD=$(pw)
EOT
echo "lab passwords written to $env"
