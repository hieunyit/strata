#!/usr/bin/env bash
# W05-N-01: publish N bundles while wrk keeps load on NGINX; measure, for
# every swap, the time until every worker runs the new bundle, and count
# failed requests. Default strata_bundle_check (1s).
# Usage: reload-under-load.sh <nginx-version> [workers] [swaps]  (dev image)
set -euo pipefail
version="${1:?usage: reload-under-load.sh <nginx-version> [workers] [swaps]}"
workers="${2:-8}"
swaps="${3:-100}"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
bin="$root/target/release"
objs="$root/build/nginx-$version/objs"
fx="$root/connectors/nginx/t/fixtures"
work="$(mktemp -d)"
trap 'kill -QUIT "$(cat "$work"/logs/nginx.pid 2>/dev/null)" 2>/dev/null || true; sleep 1; rm -rf "$work"' EXIT
mkdir -p "$work/conf" "$work/logs" "$work/bundles"
port=$((20000 + RANDOM % 20000))

# bundles prepared up front (the sample rules, versions 1..swaps+1)
printf 'policies: [{ name: example-api, mode: shadow }]\n' > "$work/policies.yaml"
for v in $(seq 1 $((swaps + 1))); do
    "$bin/strata-compile" --rules "$root/engine/compiler/examples/rules.yaml" \
        --policies "$work/policies.yaml" --key "$fx/test.key" --version "$v" \
        --out "$work/bundles/bundle-$v.sbn" 2>/dev/null
done
"$bin/mkbundle" control --out "$work/control" --generation 2 --version 1 --name bundle-1.sbn

cat > "$work/conf/nginx.conf" <<CONF
load_module $objs/ngx_http_strata_module.so;
worker_processes $workers;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 1024; }
thread_pool default threads=2;
http {
    access_log off;
    strata_control_file  $work/control;
    strata_bundle_dir    $work/bundles;
    strata_bundle_pubkey $fx/bundle.pub;
    upstream backend { server 127.0.0.1:$port; keepalive 64; }
    server {
        listen 127.0.0.1:$port reuseport;
        location /t {
            strata on;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://backend/backend/;
        }
        location /backend/ { strata off; return 200 "ok"; }
    }
}
CONF
"$objs/nginx" -p "$work/" -c conf/nginx.conf
sleep 1

duration=$(( swaps * 13 / 10 + 10 ))
wrk -t4 -c64 -d"${duration}s" "http://127.0.0.1:$port/t?q=hello&page=2" > "$work/wrk.txt" 2>&1 &
wrk_pid=$!
sleep 2

count() { grep -c "$1" "$work/logs/error.log" || true; }
gen=2
lat=()
for v in $(seq 2 $((swaps + 1))); do
    gen=$((gen + 2))
    start=$(date +%s%N)
    "$bin/mkbundle" control --in-place --out "$work/control" --generation "$gen" \
        --version "$v" --name "bundle-$v.sbn"
    while [ "$(count "bundle version $v active")" -lt "$workers" ]; do
        if [ $(( ($(date +%s%N) - start) / 1000000 )) -gt 10000 ]; then
            echo "swap to v$v: not every worker switched within 10 s"; break
        fi
        sleep 0.01
    done
    lat+=($(( ($(date +%s%N) - start) / 1000000 )))
done
wait "$wrk_pid" || true

sorted=$(printf '%s\n' "${lat[@]}" | sort -n)
n=${#lat[@]}
p50=$(echo "$sorted" | sed -n "$(( (n + 1) / 2 ))p")
p95=$(echo "$sorted" | sed -n "$(( (n * 95 + 99) / 100 ))p")
max=$(echo "$sorted" | tail -1)
echo "swaps=$n workers=$workers switch_ms p50=$p50 p95=$p95 max=$max"
grep -E "requests in|Requests/sec|Latency|Non-2xx|Socket errors" "$work/wrk.txt" | sed 's/^ */wrk: /'
grep -q "Non-2xx" "$work/wrk.txt" && echo "FAIL: non-2xx responses" || echo "non-2xx responses: 0"
echo "released: $(count 'released, unmapping'), alerts: $(grep -cE '\[(alert|crit|emerg)\]' "$work/logs/error.log" || true), crashes: $(count 'exited on signal')"

fail=0
[ "$max" -le 2000 ] || { echo "FAIL: a swap took more than 2 s"; fail=1; }
grep -qE "Non-2xx|Socket errors" "$work/wrk.txt" && { echo "FAIL: failed requests"; fail=1; }
grep -qE '\[(alert|crit|emerg)\]|exited on signal' "$work/logs/error.log" && { echo "FAIL: alert or crash"; fail=1; }
[ "$(count 'released, unmapping')" -eq $((swaps * workers)) ] || { echo "FAIL: old bundles not all released"; fail=1; }
exit $fail
