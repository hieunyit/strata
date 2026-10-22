#!/usr/bin/env bash
# GoTestWAF against NGINX + Strata (whole signature package, policy
# example-api enforce with signatures enforce), on the host's docker:
# thresholds on the scores, and the bypasses as regression seed candidates
# (tests/security/gotestwaf_report.py) to triage into corpus/regression.
#
#   tests/security/gotestwaf.sh [outdir]       (after make nginx rules-tools)
#
# GTW_PORT (19380), GTW_NGINX_CPUS (0,1), GTW_SCANNER_CPUS (2-5),
# GTW_MIN_TP (91), GTW_MIN_TN (100), GTW_BUDGET (10ms). Loopback only.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
out=${1:-build/gotestwaf}
port=${GTW_PORT:-19380}
ncpus=${GTW_NGINX_CPUS:-0,1}
scpus=${GTW_SCANNER_CPUS:-2-5}
image=wallarm/gotestwaf@sha256:ff7184da90029a98c87bfdbadcee544c979b999593175d17b2d38f642ee29977
dev=${STRATA_DEV_IMAGE:-strata-dev:latest}
case "$out" in build/*) ;; *) echo "output must be under build/" >&2; exit 2;; esac
for f in build/nginx-1.30.5/objs/nginx build/nginx-1.30.5/objs/ngx_http_strata_module.so; do
    [ -e "$f" ] || { echo "missing $f (make nginx NGINX_VERSION=1.30.5)" >&2; exit 2; }
done
rm -rf "$out" && mkdir -p "$out/conf" "$out/logs" "$out/bundles" "$out/report"
chmod 777 "$out/report"
printf 'policies:\n  - { name: example-api, mode: enforce, signatures: enforce }\n' > "$out/policies.yaml"
# the release and the control file in the dev image (rules tools, mkbundle)
STRATA_DEV_IMAGE=$dev deploy/dev/run.sh bash -c "make -s rules-tools && cargo build --release -q -p mkbundle && \
    (cd tools/strata-rules && go run . release --repo ../.. --version gotestwaf --key ../../connectors/nginx/t/fixtures/test.key \
        --policies ../../$out/policies.yaml --out ../../$out/pkg) && \
    cp $out/pkg/strata-signatures-gotestwaf.sbn $out/bundles/bundle-1.sbn && \
    target/release/mkbundle control --out $out/control --generation 2 --version 1 --name bundle-1.sbn" >"$out/release.log" 2>&1
cat > "$out/conf/nginx.conf" <<CONF
load_module /src/build/nginx-1.30.5/objs/ngx_http_strata_module.so;
worker_processes 2;
pid logs/nginx.pid;
error_log logs/error.log warn;
events { worker_connections 1024; }
http {
    strata_control_file /src/$out/control;
    strata_bundle_dir /src/$out/bundles;
    strata_bundle_pubkey /src/connectors/nginx/t/fixtures/bundle.pub;
    strata_node_id gotestwaf-01;
    strata_metrics_file /src/$out/logs/metrics;
    log_format strata '\$status \$strata_action [\$strata_rules] \$strata_score \$request_method "\$request_uri"';
    access_log logs/access.log strata;
    client_max_body_size 4m;
    client_body_buffer_size 2m;
    server {
        listen 127.0.0.1:$port;
        location / {
            strata on;
            strata_policy example-api;
            strata_cpu_budget ${GTW_BUDGET:-10ms};
            strata_request_body_limit 2m;
            proxy_pass http://127.0.0.1:$((port + 1));
        }
    }
    server {
        listen 127.0.0.1:$((port + 1));
        location / { return 200 "ok"; }
    }
}
CONF
name=strata-gotestwaf-$$
docker run -d --rm --name "$name" --cpuset-cpus="$ncpus" --network host -u "$(id -u):$(id -g)" \
    -v "$root:/src" -w /src "$dev" build/nginx-1.30.5/objs/nginx -p "/src/$out/" -c conf/nginx.conf -g 'daemon off;' >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 50); do
    curl -s -o /dev/null "http://127.0.0.1:$port/" && break
    sleep 0.2
done
# a host name, as clients send: a numeric Host is itself a CRS signal (920350)
docker run --rm --network host --add-host api.example.test:127.0.0.1 --cpuset-cpus="$scpus" \
    -v "$root/$out/report:/app/reports" "$image" \
    --url "http://api.example.test:$port/" --noEmailReport --reportFormat json --reportName gotestwaf >"$out/gotestwaf.log" 2>&1 || true
# GoTestWAF writes the CSV next to the JSON: the JSON report carries the
# scores, the CSV one the bypasses' placeholders
python3 tests/security/gotestwaf_report.py "$out/report/gotestwaf.json" --csv "$out/report/gotestwaf.csv" \
    --candidates "$out/candidates.jsonl" --min-tp "${GTW_MIN_TP:-91}" --min-tn "${GTW_MIN_TN:-100}"
