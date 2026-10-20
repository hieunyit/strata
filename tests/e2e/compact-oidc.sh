#!/usr/bin/env bash
# CP-A06 acceptance on Strata Compact with the Keycloak overlay: local
# accounts only, then local + OIDC, then OIDC only, then Keycloak off again,
# each by editing config.yaml and restarting (no rebuild). Turning local
# accounts off is refused until an OIDC admin has signed in. A browser signs
# in through the Web UI the control plane serves (CSP on) when the
# Playwright image and ui/node_modules are there (STRATA_OIDC_BROWSER=0
# skips it). Its own compose project and ports; leaves nothing behind.
# Needs the image strata-control-plane:compact (deploy/compact/build.sh).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
work=$(mktemp -d)
http=${OIDC_HTTP_PORT:-47080} idp=${OIDC_IDP_PORT:-47180}
export STRATA_COMPACT_STATE=$work/state STRATA_BACKUP_DIR=$work/backups
export STRATA_COMPACT_PROJECT=strata-compact-oidc STRATA_HTTP_PORT=$http STRATA_FLEET_PORT=${OIDC_FLEET_PORT:-47443}
export STRATA_IDP_PORT=$idp STRATA_IDP_URL=http://127.0.0.1:$idp STRATA_UI_URL=http://127.0.0.1:$http
export STRATA_COMPACT_OVERLAY=$root/deploy/compact/compose.keycloak.yaml
cp=http://127.0.0.1:$http
c() { docker compose -p "$STRATA_COMPACT_PROJECT" -f "$root/deploy/compact/compose.yaml" -f "$STRATA_COMPACT_OVERLAY" --env-file "$STRATA_COMPACT_STATE/env" "$@"; }
cleanup() {
    if [ -f "$STRATA_COMPACT_STATE/env" ]; then c down -v >/dev/null 2>&1 || true; fi
    rm -rf "$work"
}
trap cleanup EXIT
step() { echo "oidc: $*"; }
fail() { echo "oidc: FAIL: $*" >&2; exit 1; }
umask 077
mkdir -p "$STRATA_BACKUP_DIR"
head -c 24 /dev/urandom | base64 > "$work/admin.pw"
for u in kc-admin kc-operator; do head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' > "$work/$u.pw"; done
head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' > "$work/cli.secret"

# py <script> [args]: python with the work directory and URLs
py() { python3 -I - "$work" "$cp" "$STRATA_IDP_URL" "$STRATA_COMPACT_STATE/env" "$@"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {
    for _ in $(seq 120); do [ "$(code "$cp/healthz")" = 204 ] && return 0; sleep 1; done
    fail "control plane not up: $(c logs --tail 20 control-plane 2>&1)"
}
config() { # config <python expression on text s>: edits config.yaml, restarts
    c cp control-plane:/var/lib/strata/config.yaml "$work/config.yaml"
    python3 -I -c "import sys; s=open(sys.argv[1]).read(); s=$1; open(sys.argv[1],'w').write(s)" "$work/config.yaml"
    c cp "$work/config.yaml" control-plane:/var/lib/strata/config.yaml
    c restart control-plane >/dev/null 2>&1
}
oidc_block="'  oidc:\n    issuer: $STRATA_IDP_URL/realms/strata\n    discovery_url: http://keycloak:8080/realms/strata\n    audience: strata-api\n'"
methods() { curl -fsS "$cp/v1/auth/methods"; }
local_login() { # prints the HTTP status of the local admin's login
    curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -X POST "$cp/v1/auth/login" \
        --data-binary @<(python3 -I -c 'import json,sys; print(json.dumps({"username":"admin","password":open(sys.argv[1]).read().strip()}))' "$work/admin.pw")
}
me() { # me <keycloak user>: /v1/auth/me with a token of that user
    py "$1" <<'EOF'
import json, sys, urllib.request, urllib.parse
work, cp, idp, env, user = sys.argv[1:6]
data = urllib.parse.urlencode({"grant_type": "password", "client_id": "drill-cli", "client_secret": open(f"{work}/cli.secret").read(),
                               "username": user, "password": open(f"{work}/{user}.pw").read()}).encode()
tok = json.load(urllib.request.urlopen(idp + "/realms/strata/protocol/openid-connect/token", data))["access_token"]
r = urllib.request.Request(cp + "/v1/auth/me", headers={"Authorization": "Bearer " + tok})
try:
    print(urllib.request.urlopen(r).read().decode())
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}")
EOF
}

# 0. install with the overlay (Keycloak runs, the control plane does not use it yet)
"$root/deploy/compact/install.sh" -name 127.0.0.1 -admin-password-file "$work/admin.pw" >/dev/null
wait_up

# Keycloak: two users and a test client with password grants (the UI's
# client has none), through the admin API
py <<'EOF'
import json, sys, urllib.request, urllib.parse
work, cp, idp, env = sys.argv[1:5]
pw = dict(l.strip().split("=", 1) for l in open(env) if "=" in l)["KEYCLOAK_ADMIN_PASSWORD"]
tok = json.load(urllib.request.urlopen(idp + "/realms/master/protocol/openid-connect/token",
    urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": pw}).encode()))["access_token"]
H = {"Authorization": "Bearer " + tok, "Content-Type": "application/json"}
def call(method, path, body=None):
    r = urllib.request.Request(idp + "/admin/realms/strata" + path, method=method, data=json.dumps(body).encode() if body is not None else None, headers=H)
    with urllib.request.urlopen(r) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None
call("POST", "/clients", {"clientId": "drill-cli", "enabled": True, "publicClient": False, "secret": open(f"{work}/cli.secret").read(),
    "standardFlowEnabled": False, "directAccessGrantsEnabled": True, "defaultClientScopes": ["profile", "email", "roles", "basic", "strata-api"]})
for user, role in (("kc-admin", "admin"), ("kc-operator", "operator")):
    call("POST", "/users", {"username": user, "enabled": True, "emailVerified": True, "email": f"{user}@example.test", "firstName": user, "lastName": "test",
        "credentials": [{"type": "password", "value": open(f"{work}/{user}.pw").read(), "temporary": False}]})
    uid = call("GET", "/users?exact=true&username=" + user)[0]["id"]
    rep = call("GET", "/roles/" + role)
    call("POST", f"/users/{uid}/role-mappings/realm", [rep])
EOF

# 1. local accounts only
m=$(methods); cfg=$(curl -fsS "$cp/config.json")
[ "$m" = '{"local":true,"oidc":false}' ] || fail "methods: $m"
[ "$cfg" = '{}' ] || fail "config.json without OIDC: $cfg"
[ "$(local_login)" = 200 ] || fail "local login"
[ "$(me kc-operator)" = "HTTP 401" ] || fail "an OIDC token accepted with OIDC off"
step "1. local only: methods $m, config.json {}, local login 200, OIDC token 401"

# 2. local + OIDC, by configuration
config "s.replace('auth:\n  local:\n    enabled: true\n', 'auth:\n  local:\n    enabled: true\n' + $oidc_block)"
wait_up
m=$(methods)
[ "$m" = '{"local":true,"oidc":true}' ] || fail "methods: $m"
curl -fsS "$cp/config.json" | grep -q "\"oidcAuthority\":\"$STRATA_IDP_URL/realms/strata\"" || fail "config.json: $(curl -fsS "$cp/config.json")"
[ "$(local_login)" = 200 ] || fail "local login with OIDC on"
op=$(me kc-operator)
if ! grep -q '"roles":\["operator"\]' <<<"$op" || ! grep -q '"local":false' <<<"$op"; then fail "OIDC operator: $op"; fi
step "2. local + OIDC: methods $m, local login 200, OIDC operator $op"

# 3. OIDC only: refused until an OIDC admin signed in
config "s.replace('  local:\n    enabled: true\n', '  local:\n    enabled: false\n')"
sleep 10
logs=$(c logs --since 30s control-plane 2>&1)
grep -q 'refusing to turn local accounts off' <<<"$logs" || fail "local accounts turned off before any OIDC admin signed in: $(tail -3 <<<"$logs")"
[ "$(code "$cp/healthz")" != 204 ] || fail "control plane up with an unsafe configuration"
step "3a. local off refused: no OIDC admin has signed in"
config "s.replace('  local:\n    enabled: false\n', '  local:\n    enabled: true\n')"
wait_up
me kc-admin | grep -q '"roles":\["admin"\]' || fail "OIDC admin"
sleep 2 # the sign-in is noted in the background
config "s.replace('  local:\n    enabled: true\n', '  local:\n    enabled: false\n')"
wait_up
m=$(methods)
[ "$m" = '{"local":false,"oidc":true}' ] || fail "methods: $m"
lc=$(local_login)
[ "$lc" != 200 ] || fail "local login with local accounts off"
me kc-operator | grep -q '"roles":\["operator"\]' || fail "OIDC operator with local off"
step "3b. OIDC only after an OIDC admin signed in: methods $m, local login $lc, OIDC works"

# 4. a browser through the embedded UI (CSP on), OIDC code flow with PKCE
if [ "${STRATA_OIDC_BROWSER:-1}" = 1 ] && [ -d "$root/ui/node_modules/@playwright/test" ]; then
    cat > "$work/browser.cjs" <<'EOF'
const { chromium } = require('@playwright/test');
(async () => {
  const [cp, user, pw] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const violations = [];
  page.on('console', (m) => { if (/Content Security Policy/i.test(m.text())) violations.push(m.text()); });
  await page.goto(cp + '/');
  await page.getByTestId('login-btn').click();
  await page.locator('#username').fill(user);
  await page.locator('#password').fill(pw);
  await page.locator('#kc-login').click();
  await page.getByTestId('current-user').waitFor({ timeout: 30000 });
  const who = await page.getByTestId('current-user').textContent();
  await browser.close();
  if (!who.includes(user)) throw new Error('signed in as ' + who);
  if (violations.length) throw new Error('CSP violations: ' + violations.join(' | '));
  console.log('signed in as ' + who.trim() + ', no CSP violation');
})().catch((e) => { console.error(e); process.exit(1); });
EOF
    out=$(docker run --rm --network host ${STRATA_CPUSET:+--cpuset-cpus=$STRATA_CPUSET} -u "$(id -u):$(id -g)" -e HOME=/tmp \
        -e NODE_PATH=/src/ui/node_modules -v "$root:/src:ro" -v "$work:/work:ro" mcr.microsoft.com/playwright:v1.64.0-noble \
        node /work/browser.cjs "$cp" kc-operator "$(cat "$work/kc-operator.pw")") || fail "browser: $out"
    step "4. browser through the embedded UI: $out"
fi

# 5. Keycloak off again, by configuration (local back on first: never left without a way in)
config "s.replace('  local:\n    enabled: false\n', '  local:\n    enabled: true\n').replace($oidc_block, '')"
wait_up
m=$(methods); cfg=$(curl -fsS "$cp/config.json")
if [ "$m" != '{"local":true,"oidc":false}' ] || [ "$cfg" != '{}' ]; then fail "after removing OIDC: $m $cfg"; fi
[ "$(local_login)" = 200 ] || fail "local login after removing OIDC"
step "5. Keycloak off again: methods $m, config.json {}, local login 200; no rebuild at any step"
echo "oidc: PASS"
