#!/usr/bin/env bash
# CP-A09 restore drill on Strata Compact (deploy/compact), required before
# Compact Stable: install, a policy deployed with four eyes, backup, more
# work, then everything wiped (volumes, passwords) and installed again, and
# the backup restored into the clean install. Checks: the old admin
# password works, the policy and its bundle are back, the bundle signing
# key is the old one (nodes keep trusting it), a deploy works, /readyz ok.
# Its own compose project and ports; leaves nothing behind.
# Needs the image strata-control-plane:compact (deploy/compact/build.sh).
# Usage: tests/e2e/compact-drill.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
work=$(mktemp -d)
export STRATA_COMPACT_STATE=$work/state STRATA_BACKUP_DIR=$work/backups
export STRATA_COMPACT_PROJECT=strata-compact-drill STRATA_HTTP_PORT=${DRILL_HTTP_PORT:-47080} STRATA_FLEET_PORT=${DRILL_FLEET_PORT:-47443}
cp=http://127.0.0.1:$STRATA_HTTP_PORT
compact=$root/deploy/compact
c() { docker compose -p "$STRATA_COMPACT_PROJECT" -f "$compact/compose.yaml" --env-file "$STRATA_COMPACT_STATE/env" "$@"; }
cleanup() {
    if [ -f "$STRATA_COMPACT_STATE/env" ]; then c down -v >/dev/null 2>&1 || true; fi
    rm -rf "$work"
}
trap cleanup EXIT
step() { echo "drill: $*"; }
fail() { echo "drill: FAIL: $*" >&2; exit 1; }
umask 077
mkdir -p "$STRATA_BACKUP_DIR"
head -c 24 /dev/urandom | base64 > "$work/admin.pw"
head -c 24 /dev/urandom | base64 > "$work/approver.pw"
head -c 32 /dev/urandom | base64 > "$work/backup.pass"

api() { # api <user> <method> <path> [json]: prints the body, fails on HTTP >= 400
    python3 -I - "$cp" "$work" "$@" <<'EOF'
import json, sys, urllib.request
cp, work, user, method, path = sys.argv[1:6]
body = sys.argv[6] if len(sys.argv) > 6 else None
def call(method, path, body=None, token=None):
    h = {"Content-Type": "application/json"}
    if token: h["Authorization"] = "Bearer " + token
    r = urllib.request.Request(cp + path, method=method, data=body.encode() if body else None, headers=h)
    with urllib.request.urlopen(r) as resp:
        return json.loads(resp.read() or b"{}")
import os
cache = f"{work}/{user}.tok"  # one session per account: logins are throttled
def login():
    pw = open(f"{work}/{user}.pw").read().strip()
    tok = call("POST", "/v1/auth/login", json.dumps({"username": user, "password": pw}))["token"]
    fd = os.open(cache, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, tok.encode()); os.close(fd)
    return tok
tok = open(cache).read() if os.path.exists(cache) else login()
try:
    try:
        out = call(method, path, body, tok)
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise
        out = call(method, path, body, login())  # the session ended (restore, new install)
    print(json.dumps(out))
except urllib.error.HTTPError as e:
    sys.exit(f"{method} {path}: HTTP {e.code} {e.read()[:300]!r}")
EOF
}
field() { python3 -I -c "import json,sys; d=json.load(sys.stdin); [d:=d[k] if not k.isdigit() else d[int(k)] for k in sys.argv[1].split('.')]; print(d)" "$1"; }
pubkey() { c run --rm --no-deps -T --entrypoint sha256sum control-plane /var/lib/strata/keys/bundle.pub | cut -d' ' -f1; }

# a policy version: create or edit, submit, wait for its replay, approve as
# the second account (four eyes), deploy; prints the bundle version
deploy_mode() {
    local mode=$1 etag v op state
    # absent the first time: created instead
    if etag=$(api admin GET /v1/policies/example-api 2>/dev/null | field policy.etag 2>/dev/null); then
        api admin PATCH /v1/policies/example-api "{\"etag\":\"$etag\",\"spec\":{\"mode\":\"$mode\"}}" >/dev/null
    else
        api admin POST /v1/policies "{\"id\":\"example-api\",\"name\":\"example-api\",\"spec\":{\"mode\":\"$mode\"}}" >/dev/null
    fi
    v=$(api admin POST /v1/policies/example-api:submit '{}' | field version.version)
    for _ in $(seq 300); do
        op=$(api admin GET "/v1/policies/example-api/versions/$v/replay")
        state=$(field operation.state <<<"$op")
        [ "$state" = DONE ] && break
        [ "$state" = FAILED ] && fail "replay of version $v: $op"
        sleep 2
    done
    [ "$state" = DONE ] || fail "replay of version $v not done"
    api approver POST /v1/policies/example-api:approve "{\"version\":$v,\"comment\":\"drill\",\"expected_replay_id\":\"$(field operation.id <<<"$op")\"}" >/dev/null
    api admin POST /v1/policies/example-api:deploy '{}' | field bundle.version
}

# 1. install, the second account, a policy deployed
"$compact/install.sh" -name 127.0.0.1 -admin-password-file "$work/admin.pw" >/dev/null
step "installed: $(curl -fsS "$cp/readyz")"
curl -fsS "$cp/" | grep -q '<div id="root">' || fail "no Web UI on $cp"
api admin POST /v1/users "{\"username\":\"approver\",\"password\":\"$(cat "$work/approver.pw")\",\"roles\":[\"approver\"]}" >/dev/null
b1=$(deploy_mode MODE_SHADOW)
[ "$b1" = 1 ] || fail "first bundle is $b1"
step "example-api deployed as bundle $b1 with the core rule pack"
key_before=$(pubkey)

# 2. backup, then the system moves on
"$compact/backup.sh" "$work/backup.pass" drill.tar.age >/dev/null
[ -s "$STRATA_BACKUP_DIR/drill.tar.age" ] || fail "no archive"
grep -q PGDMP "$STRATA_BACKUP_DIR/drill.tar.age" && fail "archive not encrypted"
step "backup: $(du -h "$STRATA_BACKUP_DIR/drill.tar.age" | cut -f1)"
b2=$(deploy_mode MODE_ENFORCE)
step "after the backup: bundle $b2"

# 3. everything wiped, a clean install with new passwords and keys
c down -v >/dev/null 2>&1
rm -f "$STRATA_COMPACT_STATE/env"
head -c 24 /dev/urandom | base64 > "$work/fresh.pw"
"$compact/install.sh" -name 127.0.0.1 -admin-password-file "$work/fresh.pw" >/dev/null
[ "$(pubkey)" != "$key_before" ] || fail "a clean install made the same key"
step "clean install up, new signing key"

# 4. restore into it
"$compact/restore.sh" "$STRATA_BACKUP_DIR/drill.tar.age" "$work/backup.pass" -yes
ready=$(curl -fsS "$cp/readyz")
grep -q '"ready":true' <<<"$ready" || fail "not ready after the restore: $ready"
[ "$(pubkey)" = "$key_before" ] || fail "the signing key is not the backup's"
mode=$(api admin GET /v1/policies/example-api | field policy.spec.mode)
[ "$mode" = MODE_SHADOW ] || fail "example-api is $mode, the backup had MODE_SHADOW"
bundles=$(api admin GET /v1/bundles | python3 -I -c "import json,sys; print(sorted(int(b['version']) for b in json.load(sys.stdin)['bundles']))")
[ "$bundles" = "[1]" ] || fail "bundles after the restore: $bundles"
step "restored: old admin password works, example-api MODE_SHADOW, bundles $bundles, the backup's signing key"
b3=$(deploy_mode MODE_ENFORCE)
[ "$b3" -gt 1 ] || fail "deploy after the restore made bundle $b3"
step "deploy after the restore: bundle $b3"
echo "drill: PASS"
