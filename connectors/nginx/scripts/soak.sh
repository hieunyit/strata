#!/usr/bin/env bash
# W09-Q-02: soak of NGINX with the module: steady load for <hours>, a new
# bundle every <interval> seconds, memory and file descriptors sampled every
# minute. soak-check.py decides from the samples (no steady growth).
#
#   load     wrk, 4 connections paced to ~100 req/s each (clean GET, a GET
#            the protocol layer blocks, a 64 KB POST), HTTP/2 GETs and
#            clients that drop a body upload halfway, through curl
#   bundles  version N every <interval> s: the phase 0-1 rules (compiled
#            when needed), and at every hundredth version the whole
#            signature package (built before the start); at every
#            hundredth + 50 a corrupt bundle (one byte flipped), which the
#            workers must refuse while keeping the bundle they run
#   samples  build/soak/<run>/samples.csv: time, swaps, pid, role (master,
#            worker), RSS, PSS, open fds; plus the error log and counters
#
# Usage: soak.sh <nginx-version> [hours] [interval-s] [run-dir]   (dev image)
#   e.g. docker run -d --name strata-soak ... strata-dev connectors/nginx/scripts/soak.sh 1.30.5 24 86
set -euo pipefail
version="${1:?usage: soak.sh <nginx-version> [hours] [interval-s] [run-dir]}"
hours="${2:-24}"
interval="${3:-86}"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
run="${4:-$root/build/soak/$(date -u +%Y%m%dT%H%M%SZ)}"
objs="$root/build/nginx-$version/objs"
fx="$root/connectors/nginx/t/fixtures"
mkdir -p "$run/conf" "$run/logs" "$run/bundles" "$run/full"
run="$(cd "$run" && pwd)"
# the binaries of this run, copied: later builds in build/ and target/ must
# not change what a 24-hour run executes
mkdir -p "$run/bin"
cp "$objs/nginx" "$objs/ngx_http_strata_module.so" "$root/target/release/mkbundle" \
    "$root/target/release/strata-compile" "$root/target/release/strata-eval" "$run/bin/"
objs="$run/bin"
export STRATA_COMPILE="$run/bin/strata-compile" STRATA_EVAL="$run/bin/strata-eval"
chmod 755 "$run"
log() { echo "$(date -u +%FT%TZ) $*" | tee -a "$run/soak.log"; }

# --- bundles ------------------------------------------------------------
(cd "$root/tools/strata-rules" && go build -o "$run/strata-rules" .)
printf 'policies:\n  - { name: example-api, mode: enforce }\n' > "$run/policies.yaml"
p01="$run/rules-p01"
rm -rf "$p01" && mkdir -p "$p01" && cp -r "$root/rules/protocol" "$root/rules/samples" "$p01/"
release() { # rules-dir version out-dir
    (cd "$root/tools/strata-rules" && "$run/strata-rules" release --repo ../.. --rules "$1" \
        --version "soak-$2" --bundle-version "$2" --key "$fx/test.key" \
        --policies "$run/policies.yaml" --out "$3") >/dev/null 2>>"$run/build.log"
}
# SOAK_SECONDS: a shorter run (a try of the script), instead of hours
duration=${SOAK_SECONDS:-$(( hours * 3600 ))}
swaps=$(( duration / interval ))
log "soak: NGINX $version, ${duration} s, a bundle every ${interval} s ($swaps swaps)"
for v in $(seq 100 100 $(( (swaps / 100 + 1) * 100 ))); do
    release "$root/rules" "$v" "$run/full/$v"
done
log "full packages built: $(ls "$run/full" | wc -l)"
release "$p01" 1 "$run/p01-1"
cp "$run/p01-1/strata-signatures-soak-1.sbn" "$run/bundles/bundle-1.sbn"
"$run/bin/mkbundle" control --out "$run/control" --generation 2 --version 1 --name bundle-1.sbn

# --- NGINX ----------------------------------------------------------------
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
bport=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
cat > "$run/conf/nginx.conf" <<CONF
load_module $objs/ngx_http_strata_module.so;
worker_processes 2;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 1024; }
http {
    access_log off;
    client_max_body_size 4m;
    client_body_buffer_size 128k;   # the 64 KB bodies stay in memory
    strata_control_file $run/control;
    strata_bundle_dir $run/bundles;
    strata_bundle_pubkey $fx/bundle.pub;
    strata_node_id soak-01;
    strata_metrics_file $run/logs/metrics;
    strata_event_socket unix:$run/events.sock;
    upstream backend { server 127.0.0.1:$bport; keepalive 16; }
    server {
        listen 127.0.0.1:$port;
        http2 on;
        location /t {
            strata on;
            strata_policy example-api;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://backend/backend/;
        }
    }
    server {
        listen 127.0.0.1:$bport;
        location /backend/ { return 200 "ok"; }
    }
}
CONF
"$objs/nginx" -p "$run/" -c conf/nginx.conf
sleep 1
master=$(cat "$run/logs/nginx.pid")
pids=()
cleanup() {
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
    kill -QUIT "$master" 2>/dev/null || true
}
trap cleanup EXIT

# --- load -----------------------------------------------------------------
python3 -c "import sys; sys.stdout.write('a=' + 'x' * 65534)" > "$run/body64k"
cat > "$run/load.lua" <<LUA
local f = io.open("$run/body64k", "rb"); local body = f:read("*a"); f:close()
local n = 0
request = function()
    n = n + 1
    if n % 10 == 0 then
        return wrk.format("POST", "/t/upload", { ["Content-Type"] = "application/x-www-form-urlencoded" }, body)
    elseif n % 10 == 5 then
        return wrk.format("GET", "/t/a?x=1%00")      -- blocked by the protocol layer
    end
    return wrk.format("GET", "/t/items?id=" .. n .. "&sort=price")
end
delay = function() return 10 end                     -- ~100 req/s per connection
LUA
wrk -t2 -c4 -d"$(( duration + 120 ))s" -s "$run/load.lua" "http://127.0.0.1:$port" > "$run/wrk.txt" 2>&1 &
pids+=($!)
( while :; do
      curl -s -o /dev/null --http2-prior-knowledge "http://127.0.0.1:$port/t/h2?q=1" || true
      # a client that goes away halfway through its body
      curl -s -o /dev/null -m 0.2 --limit-rate 50k -H 'Content-Type: application/x-www-form-urlencoded' \
          --data-binary "@$run/body64k" "http://127.0.0.1:$port/t/upload" || true
      sleep 0.2
  done ) &
pids+=($!)

# --- samples ----------------------------------------------------------------
echo "time,swaps,pid,role,rss_kb,pss_kb,fds" > "$run/samples.csv"
sample() { # swaps
    local t; t=$(date +%s)
    for p in $master $(pgrep -P "$master"); do
        local role=worker; [ "$p" = "$master" ] && role=master
        local rss pss fds
        rss=$(awk '/^VmRSS:/ { print $2 }' "/proc/$p/status" 2>/dev/null || echo 0)
        pss=$(awk '/^Pss:/ { print $2 }' "/proc/$p/smaps_rollup" 2>/dev/null || echo 0)
        fds=$(ls "/proc/$p/fd" 2>/dev/null | wc -l)
        echo "$t,$1,$p,$role,$rss,$pss,$fds" >> "$run/samples.csv"
    done
}

# --- the soak ---------------------------------------------------------------
gen=2 v=1 done_swaps=0 refused=0
end=$(( $(date +%s) + duration ))
next_sample=0 next_swap=$(( $(date +%s) + interval ))
while [ "$(date +%s)" -lt "$end" ]; do
    now=$(date +%s)
    if [ "$now" -ge "$next_sample" ]; then sample "$done_swaps"; next_sample=$(( now + 60 )); fi
    if [ "$now" -ge "$next_swap" ]; then
        v=$(( v + 1 )); gen=$(( gen + 2 ))
        name="bundle-$v.sbn"
        if [ $(( v % 100 )) -eq 0 ] && [ -f "$run/full/$v/strata-signatures-soak-$v.sbn" ]; then
            cp "$run/full/$v/strata-signatures-soak-$v.sbn" "$run/bundles/$name"
        elif [ $(( v % 100 )) -eq 50 ]; then
            # corrupt: the previous bundle with one byte flipped
            prev=$(ls -t "$run/bundles" | head -1)
            cp "$run/bundles/$prev" "$run/bundles/$name"
            printf '\xff' | dd of="$run/bundles/$name" bs=1 seek=4000 conv=notrunc 2>/dev/null
            refused=$(( refused + 1 ))
        else
            release "$p01" "$v" "$run/p01-$v" && mv "$run/p01-$v/strata-signatures-soak-$v.sbn" "$run/bundles/$name"
            rm -rf "$run/p01-$v"
        fi
        "$run/bin/mkbundle" control --in-place --out "$run/control" \
            --generation "$gen" --version "$v" --name "$name"
        done_swaps=$(( done_swaps + 1 ))
        # keep the last few bundle files, as the agent does
        ls -t "$run/bundles" | tail -n +6 | while read -r f; do rm -f "$run/bundles/$f"; done
        next_swap=$(( now + interval ))
        [ $(( done_swaps % 50 )) -eq 0 ] && log "swaps: $done_swaps (corrupt: $refused)"
    fi
    sleep 1
done
sample "$done_swaps"
log "done: $done_swaps swaps, $refused corrupt"
echo "$done_swaps $refused" > "$run/swaps"
grep -cE '\[(alert|crit|emerg)\]' "$run/logs/error.log" > "$run/alerts" || true
grep -c 'exited on signal' "$run/logs/error.log" > "$run/crashes" || true
python3 "$root/connectors/nginx/scripts/soak-check.py" "$run" ${SOAK_CHECK_ARGS:-} | tee "$run/verdict.txt"
