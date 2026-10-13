#!/usr/bin/env bash
# Tests migrate.sh on a throwaway Compose project (strata-migtest), shaped
# like staging: a tree with deploy/lab/compose.yaml, a .state, an image
# built here, kept and skipped volumes. Export, remove everything, import,
# then check the data, its owners and modes, the volume labels, the release
# key; and what import must refuse (volumes already there, altered copy).
# Needs Docker; leaves nothing behind.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$root/build/migrate-test"
p=strata-migtest
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
refuses() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }

cleanup() {
    docker compose -p $p down -v >/dev/null 2>&1 || true
    docker rmi -f $p-app:t >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
cleanup

tree="$work/tree" state="$work/state" keys="$work/keys"
mkdir -p "$tree/deploy/lab" "$state" "$keys"
printf 'FROM alpine:3.20\nRUN echo built-here > /built\n' > "$tree/deploy/lab/Dockerfile"
cat > "$tree/deploy/lab/compose.yaml" <<'EOF'
name: strata-migtest
services:
  app:
    build: .
    image: strata-migtest-app:t
    command: ["sleep", "infinity"]
    init: true
    environment: { SECRET: "${MIGTEST_SECRET}" }
    volumes: [data:/data, clickhouse:/ch, spool-node-1:/spool, run-node-1:/run/x]
    healthcheck: { test: ["CMD", "test", "-f", "/built"], interval: 1s }
volumes: { data: {}, clickhouse: {}, spool-node-1: {}, run-node-1: {} }
EOF
echo "MIGTEST_SECRET=s3cret" > "$state/env" && chmod 600 "$state/env"
echo "release-key" > "$keys/signatures-release.key" && chmod 600 "$keys/signatures-release.key"
export MIGRATE_PROJECTS="$p|$tree/deploy/lab/compose.yaml|$state|$tree" MIGRATE_KEYS_DIR="$keys"
compose=(docker compose -p "$p" -f "$tree/deploy/lab/compose.yaml" --env-file "$state/env")

"${compose[@]}" up -d --build --wait >/dev/null 2>&1
"${compose[@]}" exec -T app sh -ec '
    mkdir -p /data/pki && echo payload > /data/pki/key.pem
    chown -R 1001:1001 /data/pki && chmod 0600 /data/pki/key.pem && chmod 0750 /data/pki
    echo event > /ch/e && echo spooled > /spool/s'
labels_before=$(docker volume inspect -f '{{json .Labels}}' ${p}_data)

# export
"$here/migrate.sh" export "$work/out" > "$work/export.log" 2>&1 || { cat "$work/export.log"; bad "export"; exit 1; }
check "export: data volume" test -f "$work/out/volumes/${p}_data.tgz"
refuses "export: no clickhouse, spool or run volume" sh -c "ls '$work/out/volumes' | grep -E 'clickhouse|spool|run-'"
check "export: .state and tree" test -f "$work/out/states/$p.tgz" -a -f "$work/out/trees/$p.tgz"
check "export: image built here saved" sh -c "gunzip -c '$work/out/images.tar.gz' | tar -xO manifest.json | grep -q $p-app:t"
check "export: project running again" sh -c "docker ps --filter label=com.docker.compose.project=$p -q | grep -q ."
refuses "export: into a directory not empty" "$here/migrate.sh" export "$work/out"

# what the new machine looks like: nothing of the project
refuses "import: volumes already there" "$here/migrate.sh" import --no-up "$work/out"
"${compose[@]}" down -v >/dev/null 2>&1
docker rmi -f $p-app:t >/dev/null
rm -rf "$tree" "$state" "$keys"

cp -a "$work/out" "$work/bad"
echo x >> "$work/bad/states/$p.tgz"
refuses "import: altered copy (checksums)" "$here/migrate.sh" import --no-up "$work/bad"
refuses "import: altered copy leaves no volume" docker volume inspect ${p}_data

"$here/migrate.sh" import "$work/out" > "$work/import.log" 2>&1 || { cat "$work/import.log"; bad "import"; exit 1; }
check "import: project healthy, from the loaded image" "${compose[@]}" exec -T app test -f /built
check "import: data back" sh -c "${compose[*]} exec -T app cat /data/pki/key.pem | grep -qx payload"
check "import: owner and mode kept" sh -c "${compose[*]} exec -T app stat -c '%u:%g %a' /data/pki/key.pem /data/pki | tr '\n' ' ' | grep -qx '1001:1001 600 1001:1001 750 '"
check "import: events not carried" sh -c "! ${compose[*]} exec -T app test -e /ch/e && ! ${compose[*]} exec -T app test -e /spool/s"
check "import: .state back (passwords)" sh -c "${compose[*]} exec -T app printenv SECRET | grep -qx s3cret"
check "import: .state link in the tree" test "$(readlink "$tree/deploy/lab/.state")" = "$state"
check "import: volume labels kept" test "$(docker volume inspect -f '{{json .Labels}}' ${p}_data)" = "$labels_before"
check "import: release key back, 0600" test "$(stat -c %a "$keys/signatures-release.key")" = 600
refuses "import: twice" "$here/migrate.sh" import --no-up "$work/out"

if [ "$fail" = 0 ]; then echo "migrate: all checks passed"; else echo "migrate: failures"; exit 1; fi
