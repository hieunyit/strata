#!/usr/bin/env bash
# Isolated loopback fixture. Requires locally built NGINX/module/mkbundle and dev image.
# No ports published; only Header placements from the pinned official SQLi/XSS cases.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
bundle=${1:?usage: run-header-gotestwaf.sh BUNDLE OUTDIR}
out=${2:?output directory required}
image=wallarm/gotestwaf@sha256:ff7184da90029a98c87bfdbadcee544c979b999593175d17b2d38f642ee29977
docker image inspect "$image" >/dev/null
mkdir -p "$out"
out=$(realpath "$out")
case "$out" in "$root"/build/*) ;; *) echo 'output must be under repo build/' >&2; exit 2;; esac
inspect=$(docker create "$image")
trap 'docker rm "$inspect" >/dev/null 2>&1 || true' EXIT
docker cp "$inspect:/app/testcases" "$out/upstream"
docker rm "$inspect" >/dev/null
trap - EXIT
python3 - "$out" <<'PY'
import hashlib,json,sys
from pathlib import Path
out=Path(sys.argv[1]); rows={}
for group, names in [('owasp', ['sql-injection.yml', 'xss-scripting.yml']), ('false-pos', ['texts.yml'])]:
    dest=out/'cases'/group;dest.mkdir(parents=True,exist_ok=True)
    for name in names:
        source=out/'upstream'/group/name
        raw=source.read_bytes();s=raw.decode()
        start=s.index('placeholder:');end=s.find('type:',start)
        selected=s[:start]+'placeholder:\n  - Header\n'+(s[end:] if end!=-1 else '')
        (dest/name).write_text(selected)
        rows[group+'/'+name]={'upstream_sha256':hashlib.sha256(raw).hexdigest(),'selected_sha256':hashlib.sha256(selected.encode()).hexdigest()}
(out/'case-hashes.json').write_text(json.dumps(rows,indent=2)+'\n')
PY
relative_out=${out#"$root"/}
# Match the host owner for report output. Keep the scanner in the dev fixture's network.
probe_name=strata-header-probe-$$
export STRATA_DEV_DOCKER_ARGS="${STRATA_DEV_DOCKER_ARGS:-} --name $probe_name --group-add $(stat -c %g /var/run/docker.sock) -v /usr/bin/docker:/usr/local/bin/docker:ro -v /var/run/docker.sock:/var/run/docker.sock"
deploy/dev/run.sh python3 tests/security/header_probe.py \
  --nginx build/nginx-1.30.5/objs/nginx \
  --module build/nginx-1.30.5/objs/ngx_http_strata_module.so \
  --mkbundle target/release/mkbundle --bundle "$bundle" \
  --pubkey connectors/nginx/t/fixtures/bundle.pub --out "$relative_out/probe" \
  --http-check-command docker run --rm --pull never \
  --user "$(id -u):$(id -g)" --network "container:$probe_name" \
  -v "$out/cases:/cases:ro" -v "$out:/reports" "$image" \
  --url '{url}' --noEmailReport --reportFormat json --reportPath /reports \
  --reportName headers --testCasesPath /cases --sendDelay 1 --randomDelay 1 \
  --workers 1 --addDebugHeader --blockStatusCodes 403 --passStatusCodes 200,404 --tlsVerify
