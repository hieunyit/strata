#!/usr/bin/env bash
# W05-Q-01: request latency percentiles while bundles are swapped, against
# the same load without swaps. Two phases of <seconds> each on one NGINX:
#   steady  wrk only
#   swaps   wrk while a new bundle is published every <interval> ms
# Prints wrk's latency distribution (p50 p75 p90 p99) for both.
# Usage: latency-during-reload.sh <nginx-version> [workers] [seconds] [interval-ms]  (dev image)
set -euo pipefail
version="${1:?usage: latency-during-reload.sh <nginx-version> [workers] [seconds] [interval-ms]}"
workers="${2:-4}"
seconds="${3:-30}"
interval="${4:-300}"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
bin="$root/target/release"
objs="$root/build/nginx-$version/objs"
fx="$root/connectors/nginx/t/fixtures"
work="$(mktemp -d)"
trap 'kill -QUIT "$(cat "$work"/logs/nginx.pid 2>/dev/null)" 2>/dev/null || true; sleep 1; rm -rf "$work"' EXIT
mkdir -p "$work/conf" "$work/logs" "$work/bundles"
port=$((20000 + RANDOM % 20000))
swaps=$(( seconds * 1000 / interval + 5 ))

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
    upstream backend { server 127.0.0.1:$port; keepalive 32; }
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
url="http://127.0.0.1:$port/t?q=hello&page=2"
wrk -t2 -c32 -d5s "$url" >/dev/null 2>&1 # warm up: Hyperscan scratch, connections

report() { # phase file
    awk -v phase="$1" '
        /Latency Distribution/ { d = 1; next }
        d && /%/ { p[$1] = $2 }
        /requests in/ { req = $1 }
        /Non-2xx/ { bad = $NF }
        END { printf "%s requests=%s p50=%s p75=%s p90=%s p99=%s non2xx=%s\n", phase, req, p["50%"], p["75%"], p["90%"], p["99%"], bad + 0 }
    ' "$2"
}

wrk -t2 -c32 -d"${seconds}s" --latency "$url" > "$work/steady.txt" 2>&1
report steady "$work/steady.txt"

wrk -t2 -c32 -d"${seconds}s" --latency "$url" > "$work/swaps.txt" 2>&1 &
wrk_pid=$!
gen=2 n=0
end=$(( $(date +%s) + seconds - 1 ))
for v in $(seq 2 $((swaps + 1))); do
    [ "$(date +%s)" -lt "$end" ] || break
    gen=$((gen + 2))
    "$bin/mkbundle" control --in-place --out "$work/control" --generation "$gen" --version "$v" --name "bundle-$v.sbn"
    n=$((n + 1))
    sleep "$(awk -v ms="$interval" 'BEGIN { printf "%.3f", ms / 1000 }')"
done
wait "$wrk_pid" || true
report "swaps($n)" "$work/swaps.txt"
echo "alerts: $(grep -cE '\[(alert|crit|emerg)\]' "$work/logs/error.log" || true), crashes: $(grep -c 'exited on signal' "$work/logs/error.log" || true)"
grep -qE "Non-2xx|Socket errors" "$work/steady.txt" "$work/swaps.txt" && { echo "FAIL: failed requests"; exit 1; }
grep -qE '\[(alert|crit|emerg)\]|exited on signal' "$work/logs/error.log" && { echo "FAIL: alert or crash"; exit 1; }
exit 0
