#!/usr/bin/env bash
# W09-Q-01: one benchmark run of NGINX with and without the Strata module.
# Prints one JSON line: scenario, mode, requests/s, latency p50/p90/p99 (µs),
# non-2xx count, and for mode "events" the events received and dropped.
#
#   scenario  small  GET with a short query, HTTP/1.1 keep-alive
#             64k    POST of a 64 KB urlencoded body
#             1m     POST of a 1 MB (1,000,000 bytes) urlencoded body
#             h2     GET over HTTP/2 (h2c, prior knowledge), h2load
#   mode      off    module not loaded (the baseline)
#             p01    module, the phase 0-1 bundle (rules/protocol, rules/samples):
#                    what the module's targets are defined for
#                    (docs/design/nginx-module.md, "Mục tiêu đo được")
#             full   module, the whole signature package (phase 2: CRS, ET
#                    Open, Sigma, bots, virtual patches)
#             events "p01" in shadow (strata_mode shadow); every request
#                    crosses the threshold (100013), is served, and its event
#                    goes to an event socket drained by a reader
#   policy example-api in enforce for every bundle
#
# NGINX: 2 workers pinned to cores BENCH_NGINX_CPUS (default 2,3); the client
# runs on BENCH_CLIENT_CPUS (default 4-6), the event reader on
# BENCH_READER_CPU (default 7). The backend is a second server of
# the same NGINX ("strata off") so both modes pay the same proxying cost.
# The full bundle comes from `strata-rules release --policies` (bench-bundle.sh).
#
# Usage: bench.sh <nginx-version> <scenario> <mode> [seconds] [connections]  (dev image)
set -euo pipefail
version="${1:?usage: bench.sh <nginx-version> <scenario> <mode> [seconds] [connections]}"
scenario="${2:?scenario: small|64k|1m|h2}"
mode="${3:?mode: off|p01|full|events}"
seconds="${4:-30}"
conns="${5:-64}"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
objs="$root/build/nginx-$version/objs"
fx="$root/connectors/nginx/t/fixtures"
# BENCH_KEEP=<dir>: keep NGINX's logs (error.log: engine errors) there.
# BENCH_FULL_BUNDLE / BENCH_P01_BUNDLE: another build of the same rules,
# e.g. with the block-mode Hyperscan section (strata-rules release --hs-block)
case "$mode" in
    full) bundle="${BENCH_FULL_BUNDLE:-$root/build/bench/pkg/strata-signatures-bench.sbn}" ;;
    *) bundle="${BENCH_P01_BUNDLE:-$root/build/bench/pkg-p01/strata-signatures-bench-p01.sbn}" ;;
esac
ncpus="${BENCH_NGINX_CPUS:-2,3}"
ccpus="${BENCH_CLIENT_CPUS:-4-6}"
rcpu="${BENCH_READER_CPU:-7}"
[ -x "$objs/nginx" ] || { echo "nginx not built: $objs/nginx (make nginx NGINX_VERSION=$version)" >&2; exit 2; }
[ "$mode" = off ] || [ -f "$bundle" ] || { echo "no bundle: $bundle (run bench-bundle.sh)" >&2; exit 2; }

work="$(mktemp -d)"
reader=""
cleanup() {
    kill -QUIT "$(cat "$work/logs/nginx.pid" 2>/dev/null)" 2>/dev/null || true
    [ -n "$reader" ] && kill "$reader" 2>/dev/null || true
    sleep 0.5
    [ -n "${BENCH_KEEP:-}" ] && cp -r "$work/logs" "$BENCH_KEEP" 2>/dev/null; rm -rf "$work"
}
trap cleanup EXIT
chmod 755 "$work" # workers (another user when run as root) reach the event socket
mkdir -p "$work/conf" "$work/logs" "$work/bundles"
# three consecutive free ports: front, backend, HTTP/2
port=$(python3 - <<'PY'
import random, socket
for _ in range(200):
    p = random.randint(20000, 60000)
    try:
        for q in (p, p + 1, p + 2):
            s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", q)); s.close()
        print(p); break
    except OSError:
        continue
PY
)
bport=$((port + 1))

# worker_cpu_affinity masks for the listed cores
masks=""
IFS=, read -r -a cores <<< "$ncpus"
for c in "${cores[@]}"; do
    masks="$masks $(python3 -c "print(format(1 << $c, '016b'))")"
done

module="" strata="" http_strata=""
if [ "$mode" != off ]; then
    cp "$bundle" "$work/bundles/bundle-1.sbn"
    "$root/target/release/mkbundle" control --out "$work/control" --generation 2 --version 1 --name bundle-1.sbn
    module="load_module $objs/ngx_http_strata_module.so;"
    http_strata="strata_control_file $work/control;
    strata_bundle_dir $work/bundles;
    strata_bundle_pubkey $fx/bundle.pub;
    strata_node_id bench-01;
    strata_metrics_file $work/logs/metrics;
    strata_event_socket unix:$work/events.sock;"
    shadow=""
    if [ "$mode" = events ]; then shadow="strata_mode shadow;"; fi
    strata="strata on;
            strata_policy example-api;
            $shadow
            strata_request_body_limit 2m;"
fi

if [ "$mode" = events ]; then
    # the agent's own listener and decoder drain the socket
    # (agent/cmd/strata-eventsink, built by `make bench`)
    sink="${BENCH_EVENT_SINK:-$root/build/bench/strata-eventsink}"
    [ -x "$sink" ] || { echo "no event sink: $sink" >&2; exit 2; }
    taskset -c "$rcpu" "$sink" -socket "$work/events.sock" > "$work/events.json" &
    reader=$!
    for _ in $(seq 50); do [ -S "$work/events.sock" ] && break; sleep 0.1; done
fi

# HTTP/2 without TLS (h2c, prior knowledge): the module's HTTP/2 path is
# measured; TLS costs the same with and without the module and the test
# build of NGINX has no ssl module
ssl=""
if [ "$scenario" = h2 ]; then ssl="http2 on;"; fi

cat > "$work/conf/nginx.conf" <<CONF
$module
worker_processes ${#cores[@]};
worker_cpu_affinity$masks;
worker_rlimit_nofile 65536;
pid logs/nginx.pid;
error_log logs/error.log warn;
events { worker_connections 4096; }
http {
    access_log off;
    client_max_body_size 4m;
    # clients keep their connections for the whole run (h2load does not
    # reconnect after the default 1000 requests)
    keepalive_requests 10000000;
    client_body_buffer_size 2m;
    $http_strata
    upstream backend { server 127.0.0.1:$bport; keepalive 64; }
    server {
        listen 127.0.0.1:$port reuseport;
        $ssl
        location /t {
            $strata
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://backend/backend/;
        }
    }
    server {
        listen 127.0.0.1:$bport reuseport;
        location /backend/ { return 200 "ok"; }
    }
}
CONF
"$objs/nginx" -p "$work/" -c conf/nginx.conf
sleep 0.5

query="q=hello&page=2&sort=price"
# events: the location is in shadow and the query crosses the threshold
# (a NUL byte, 100013): each request is logged with an Event ID, and served
if [ "$mode" = events ]; then query="$query&x=1%00"; fi
url="http://127.0.0.1:$port/t?$query"

# POST bodies: urlencoded fields of benign text, exact sizes
body_size=0
case "$scenario" in
    64k) body_size=65536 ;;
    1m) body_size=1000000 ;;
esac
lua=()
if [ "$body_size" -gt 0 ]; then
    python3 - "$body_size" "$work/body" <<'PY'
import sys
n = int(sys.argv[1]); out = []; size = 0; i = 0
while size < n:
    f = "field%d=some+ordinary+text+value+%d&" % (i, i)
    out.append(f); size += len(f); i += 1
open(sys.argv[2], "w").write("".join(out)[:n])
PY
    cat > "$work/post.lua" <<LUA
local f = io.open("$work/body", "rb")
wrk.method = "POST"
wrk.body = f:read("*a")
f:close()
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
LUA
    lua=(-s "$work/post.lua")
fi

run_wrk() { # seconds
    taskset -c "$ccpus" wrk -t4 -c"$conns" -d"$1s" --latency "${lua[@]}" "$url"
}

# other processes on the NGINX CPUs during the measured part (cpu-noise.py)
noise() { python3 "$root/connectors/nginx/scripts/cpu-noise.py" "$@"; }
if [ "$scenario" = h2 ]; then
    noise snap "$ncpus" "$(cat "$work/logs/nginx.pid")" "$work/noise0.json"
    h2url="http://127.0.0.1:$port/t?$query"
    taskset -c "$ccpus" h2load -t4 -c"$conns" -m10 --warm-up-time=5 -D "$seconds" "$h2url" > "$work/out.txt" 2>&1
    noise snap "$ncpus" "$(cat "$work/logs/nginx.pid")" "$work/noise1.json"
    cp "$work/out.txt" "${BENCH_RAW:-/dev/null}" 2>/dev/null || true
    python3 - "$scenario" "$mode" "$work/out.txt" <<'PY'
import json, re, sys
t = open(sys.argv[3]).read()
rps = float(re.search(r"finished in .*?, ([\d.]+) req/s", t).group(1))
lat = re.search(r"time for request:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", t)
def us(v):
    m = re.match(r"([\d.]+)(us|ms|s)", v); x = float(m.group(1))
    return x * {"us": 1, "ms": 1e3, "s": 1e6}[m.group(2)]
st = re.search(r"status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx", t)
# h2load reports min/max/mean/sd per request, not percentiles: p50/p99 are
# taken from wrk-style runs of the HTTP/1 scenarios; here mean and max
print(json.dumps({"scenario": sys.argv[1], "mode": sys.argv[2], "rps": rps,
                  "mean_us": us(lat.group(3)), "max_us": us(lat.group(2)),
                  "non2xx": int(st.group(3)) + int(st.group(4))}))
PY
else
    run_wrk 5 >/dev/null 2>&1 || true # warm-up: connections, Hyperscan scratch
    noise snap "$ncpus" "$(cat "$work/logs/nginx.pid")" "$work/noise0.json"
    run_wrk "$seconds" > "$work/out.txt" 2>&1
    noise snap "$ncpus" "$(cat "$work/logs/nginx.pid")" "$work/noise1.json"
    cp "$work/out.txt" "${BENCH_RAW:-/dev/null}" 2>/dev/null || true
    python3 - "$scenario" "$mode" "$work/out.txt" <<'PY'
import json, re, sys
t = open(sys.argv[3]).read()
def us(v):
    m = re.match(r"([\d.]+)(us|ms|s)$", v); x = float(m.group(1))
    return round(x * {"us": 1, "ms": 1e3, "s": 1e6}[m.group(2)], 1)
p = dict(re.findall(r"^\s+(50|90|99)(?:\.\d+)?%\s+(\S+)\s*$", t, re.M))
m = re.search(r"Requests/sec:\s+([\d.]+)", t)
if not m or len(p) < 3:
    sys.exit("bench.sh: unexpected wrk output:\n" + t)
rps = float(m.group(1))
bad = re.search(r"Non-2xx or 3xx responses: (\d+)", t)
err = re.search(r"Socket errors: (.*)", t)
print(json.dumps({"scenario": sys.argv[1], "mode": sys.argv[2], "rps": rps,
                  "p50_us": us(p["50"]), "p90_us": us(p["90"]), "p99_us": us(p["99"]),
                  "non2xx": int(bad.group(1)) if bad else 0,
                  "socket_errors": err.group(1) if err else ""}))
PY
fi > "$work/result.json"
# the noise of the run joins its result
python3 - "$work/result.json" "$(noise diff "$work/noise0.json" "$work/noise1.json")" <<'PY'
import json, sys
r = json.load(open(sys.argv[1])); r.update(json.loads(sys.argv[2]))
json.dump(r, open(sys.argv[1], "w"))
PY

if [ "$mode" = events ]; then
    kill -TERM "$reader"; wait "$reader" 2>/dev/null || true; reader=""
fi
if [ "$mode" = off ]; then
    cat "$work/result.json"
else
    # the module's own counters (metrics file, docs/design/control-file.md),
    # summed over the workers' slots
    python3 - "$work/result.json" "$work/logs/metrics" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["events"])' "$work/events.json" 2>/dev/null || echo)" <<'PY'
import json, struct, sys
r = json.load(open(sys.argv[1]))
b = open(sys.argv[2], "rb").read()
magic, layout, slots, size, n = struct.unpack_from("<8sIIII", b, 0)
assert magic == b"STRMET1\0", magic
tot = [0] * n
for s in range(slots):
    c = struct.unpack_from("<%dQ" % n, b, 64 + s * size)
    if c[0]:
        tot = [a + x for a, x in zip(tot, c)]
reqs = sum(tot[2:6])
r["inspected"] = reqs
r["blocked"] = tot[5]
r["fail_open"] = tot[7]
r["budget_exceeded"] = tot[10]
r["engine_mean_us"] = round(tot[11] / reqs / 1000, 1) if reqs else 0
r["engine_hist"] = tot[12:21]
if sys.argv[3]:
    r["events_received"] = int(sys.argv[3])
    r["events_dropped"] = tot[9]
print(json.dumps(r))
PY
fi
if grep -qE '\[(alert|crit|emerg)\]|exited on signal' "$work/logs/error.log"; then
    echo "FAIL: alert or crash" >&2
    grep -E '\[(alert|crit|emerg)\]|exited on signal' "$work/logs/error.log" | head -5 >&2
    exit 1
fi
