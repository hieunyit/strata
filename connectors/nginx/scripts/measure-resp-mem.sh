#!/usr/bin/env bash
# W06-N-01: worker memory while the response data guard inspects large
# responses. One worker serves a 50 MB body (static file with sendfile, and
# proxied) N times; its RSS must not grow with the response size or with
# the number of requests, only with strata_response_body_limit.
# Usage: measure-resp-mem.sh <nginx-version> [requests]   (in the dev image)
set -euo pipefail
version="${1:?usage: measure-resp-mem.sh <nginx-version> [requests]}"
reqs="${2:-20}"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
objs="$root/build/nginx-$version/objs"
fx="$root/connectors/nginx/t/fixtures"
work="$(mktemp -d)"
trap 'kill -QUIT "$(cat "$work"/logs/nginx.pid 2>/dev/null)" 2>/dev/null || true; sleep 1; rm -rf "$work"' EXIT
mkdir -p "$work/conf" "$work/logs" "$work/html"

# 50 MB: 800 blocks of 64 KB, each with the test needle at its start
perl -e 'my $b = "STRATA-TEST-MASK" . ("x" x (65536 - 17)) . "\n"; print $b x 800' \
    > "$work/html/big.txt"
size=$(stat -c %s "$work/html/big.txt")
port=$((20000 + RANDOM % 20000))

rss() { awk '/^VmRSS:/ { print $2 }' "/proc/$1/status"; }
hwm() { awk '/^VmHWM:/ { print $2 }' "/proc/$1/status"; }

run() {   # $1 label, $2 strata_response_body_limit, $3 url path
    cat > "$work/conf/nginx.conf" <<CONF
load_module $objs/ngx_http_strata_module.so;
worker_processes 1;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 64; }
http {
    access_log off;
    sendfile on;
    strata_control_file  $fx/bundle/control;
    strata_bundle_dir    $fx/bundle;
    strata_bundle_pubkey $fx/bundle.pub;
    server {
        listen 127.0.0.1:$port;
        strata_response_body_limit $2;
        location /static/ { strata on; alias $work/html/; }
        location /proxy/ { strata on; proxy_pass http://127.0.0.1:$port/origin/; }
        location /origin/ { strata off; alias $work/html/; }
    }
}
CONF
    "$objs/nginx" -p "$work/" -c conf/nginx.conf
    sleep 1
    local master w before after peak got masked i
    master=$(cat "$work/logs/nginx.pid")
    w=$(ps -o pid= --ppid "$master" | tr -d ' ' | head -1)
    curl -s -o /dev/null "http://127.0.0.1:$port$3big.txt"   # warm-up
    before=$(rss "$w")
    for i in $(seq 1 "$reqs"); do
        curl -s -o "$work/out" "http://127.0.0.1:$port$3big.txt"
    done
    after=$(rss "$w"); peak=$(hwm "$w")
    got=$(stat -c %s "$work/out")
    masked=$(grep -c '^\*\{16\}' "$work/out" || true)
    echo "$1: limit=$2 body=$got/$size masked_blocks=$masked rss_kb before=$before after=$after peak=$peak"
    [ "$got" = "$size" ] || { echo "FAIL: body size"; exit 1; }
    kill -QUIT "$master"; sleep 1
}

echo "requests per case: $reqs, body $size bytes"
run static-default 512k /static/
run proxy-default  512k /proxy/
run static-1m      1m   /static/
run static-64m     64m  /static/
run static-off     0    /static/
