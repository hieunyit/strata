#!/bin/sh
# Run inside the dev image with a private target mount. Never use package builds
# with test-hooks in production. Every invocation owns a fresh output directory.
set -eu
cd "$(dirname "$0")/../.."
version=${1:?usage: run-native-faults.sh VERSION build/NEW_OUTPUT}
out=${2:?usage: run-native-faults.sh VERSION build/NEW_OUTPUT}
case "$version" in 1.30.5|1.31.6) ;; *) echo 'unsupported pinned NGINX version' >&2; exit 2 ;; esac
case "$out" in build/*) ;; *) echo 'output must be under repo build/' >&2; exit 2 ;; esac
case "$out" in *..*|*[!a-zA-Z0-9_./-]*) echo 'invalid output path' >&2; exit 2 ;; esac
mkdir "$out"
# Required even when the prior native executable exists: make asks Cargo and
# build.sh relinks the module when libstrata.a changed.
make nginx-asan "NGINX_VERSION=$version" > "$out/build.log" 2>&1
export PATH="$PWD/build/nginx-$version-asan/objs:$PATH"
export TEST_NGINX_LOAD_MODULES="$PWD/build/nginx-$version-asan/objs/ngx_http_strata_module.so"
export TEST_NGINX_STRATA_MKBUNDLE="$PWD/target/release/mkbundle"
export TEST_NGINX_STRATA_COMPILE="$PWD/target/release/strata-compile"
export ASAN_OPTIONS="detect_leaks=0:detect_odr_violation=0:abort_on_error=1:log_path=$PWD/$out/asan"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:log_path=$PWD/$out/ubsan"
if ! prove -v connectors/nginx/t/004-reload.t connectors/nginx/t/060-fail-mode-events.t connectors/nginx/t/090-breaker.t > "$out/prove.log" 2>&1; then
    tail -60 "$out/prove.log"
    exit 1
fi
python3 - "$out" "$version" <<'PY'
import hashlib, json, pathlib, re, sys
out, version = pathlib.Path(sys.argv[1]), sys.argv[2]
log = (out / 'prove.log').read_text()
if not re.search(r'Files=3, Tests=[1-9][0-9]*,', log) or 'Result: PASS' not in log:
    raise SystemExit('FAIL: missing successful three-file TAP summary')
if re.search(r'(?im)^(?:ok[^\n]*|1\.\.0[^\n]*)#\s*skip\b', log):
    raise SystemExit('FAIL: skipped native coverage')
reports = [str(p) for pattern in ('asan.*', 'ubsan.*') for p in out.glob(pattern)]
if reports:
    raise SystemExit('FAIL: sanitizer reports: ' + ', '.join(reports))
paths = ['target/release/libstrata.a', 'target/release/mkbundle', 'target/release/strata-compile',
         f'build/nginx-{version}-asan/objs/nginx', f'build/nginx-{version}-asan/objs/ngx_http_strata_module.so',
         'engine/ffi/src/ffi.rs', 'engine/src/tx.rs', 'connectors/nginx/src/ngx_http_strata_breaker.c',
         'connectors/nginx/src/ngx_http_strata_bundle.c', 'tests/security/run-native-faults.sh',
         'connectors/nginx/t/004-reload.t', 'connectors/nginx/t/060-fail-mode-events.t', 'connectors/nginx/t/090-breaker.t']
metadata = {'nginx': version, 'hashes': {p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in paths},
            'scope': 'existing native panic/fail-mode/breaker and signed-bundle rejection tests; no real agent/ClickHouse in this suite',
            'test_hooks': True, 'sanitizer_reports': reports, 'leak_sanitizer': False,
            'limits': ['not production binary or traffic', 'not CPU-budget performance SLO', 'not a complete staging game day']}
(out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
print('PASS: native fault suites; no ASan/UBSan report; test-hooks lab build, LSan disabled')
PY
tail -5 "$out/prove.log"
