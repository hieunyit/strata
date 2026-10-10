#!/usr/bin/env bash
# W05-N-01: the worker's event loop makes no I/O syscall while no new bundle
# is published (the timer only reads the control file's generation from
# memory); when one is, the file syscalls run in thread-pool threads only.
# Needs ptrace: STRATA_DEV_DOCKER_ARGS="--cap-add SYS_PTRACE" deploy/dev/run.sh ...
# Usage: strace-idle.sh <nginx-version> [idle seconds]
set -euo pipefail
version="${1:?usage: strace-idle.sh <nginx-version> [idle seconds]}"
idle="${2:-5}"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
bin="$root/target/release"
objs="$root/build/nginx-$version/objs"
fx="$root/connectors/nginx/t/fixtures"
work="$(mktemp -d)"
trap 'kill -QUIT "$(cat "$work"/logs/nginx.pid 2>/dev/null)" 2>/dev/null || true; sleep 1; rm -rf "$work"' EXIT
mkdir -p "$work/conf" "$work/logs" "$work/bundles"
port=$((20000 + RANDOM % 20000))

printf 'policies: [{ name: example-api, mode: shadow }]\n' > "$work/policies.yaml"
for v in 1 2; do
    "$bin/strata-compile" --rules "$root/engine/compiler/examples/rules.yaml" --policies "$work/policies.yaml" \
        --key "$fx/test.key" --version "$v" --out "$work/bundles/bundle-$v.sbn" 2>/dev/null
done
"$bin/mkbundle" control --out "$work/control" --generation 2 --version 1 --name bundle-1.sbn
cat > "$work/conf/nginx.conf" <<CONF
load_module $objs/ngx_http_strata_module.so;
worker_processes 1;
pid logs/nginx.pid;
error_log logs/error.log notice;
events { worker_connections 64; }
thread_pool default threads=2;
http {
    access_log off;
    strata_control_file  $work/control;
    strata_bundle_dir    $work/bundles;
    strata_bundle_pubkey $fx/bundle.pub;
    strata_bundle_check  100ms;
    server {
        listen 127.0.0.1:$port;
        location /t { strata on; return 200; }
    }
}
CONF
# nginx runs under strace from the start (tracing a child needs no extra
# privilege); phases are told apart by time
strace -f -qq -ttt -e trace=%file,%desc,%memory,%net -o "$work/trace.txt" \
    "$objs/nginx" -p "$work/" -c conf/nginx.conf -g "daemon off;" &
tracer=$!
for _ in $(seq 1 50); do [ -s "$work/logs/nginx.pid" ] && break; sleep 0.1; done
sleep 2
master=$(cat "$work/logs/nginx.pid")
worker=$(ps -o pid= --ppid "$master" | tr -d ' ' | head -1)
[ -n "$worker" ] || { echo "FAIL: no worker"; exit 1; }

t0=$(date +%s.%N); sleep "$idle"; t1=$(date +%s.%N)
"$bin/mkbundle" control --in-place --out "$work/control" --generation 4 --version 2 --name bundle-2.sbn
for _ in $(seq 1 50); do grep -q "bundle version 2 active" "$work/logs/error.log" && break; sleep 0.1; done
sleep 0.3; t2=$(date +%s.%N)
kill -QUIT "$master"; wait "$tracer" 2>/dev/null || true

window() { awk -v a="$1" -v b="$2" '$2 >= a && $2 < b' "$work/trace.txt"; }
all=$(grep -c . "$work/trace.txt")
[ "$all" -gt 0 ] || { echo "FAIL: empty trace"; exit 1; }
loop_idle=$(window "$t0" "$t1" | awk -v w="$worker" '$1 == w' | grep -vcE "epoll_wait|epoll_pwait" || true)
echo "trace: $all syscalls in total, worker pid $worker"
echo "idle ${idle}s with strata_bundle_check 100ms (~$((idle * 10)) ticks): event-loop syscalls other than epoll_wait = $loop_idle"
window "$t0" "$t1" | awk -v w="$worker" '$1 == w' | grep -vE "epoll_wait|epoll_pwait" | head -5 | sed 's/^/  /' || true
grep -q "bundle version 2 active" "$work/logs/error.log" && echo "bundle 2 active" || echo "FAIL: bundle 2 not active"
echo "reload: syscalls on bundle-2.sbn, by thread:"
window "$t1" "$t2" | grep "bundle-2.sbn" | awk -v w="$worker" '{ split($3, c, "("); print ($1 == w ? "event loop" : "thread " $1), c[1] }' | sort | uniq -c | sed 's/^/  /' || true
echo "reload: every syscall during the swap, by thread:"
window "$t1" "$t2" | awk -v w="$worker" -v m="$master" '$1 != m { split($3, c, "("); print ($1 == w ? "event loop" : "thread " $1), c[1] }' | sort | uniq -c | sed 's/^/  /' || true
echo "reload: event-loop syscalls other than epoll/eventfd/log writes:"
window "$t1" "$t2" | awk -v w="$worker" '$1 == w' | grep -vE "epoll_wait|epoll_pwait|epoll_ctl|eventfd|read\([0-9]+, \"\\\\[0-9]|write\([0-9]+, \"20[0-9][0-9]/" | head -10 | sed 's/^/  /' || true

fail=0
[ "$loop_idle" -eq 0 ] || { echo "FAIL: I/O in the event loop while idle"; fail=1; }
grep -q "bundle version 2 active" "$work/logs/error.log" || fail=1
if window "$t1" "$t2" | awk -v w="$worker" '$1 == w' | grep -q "bundle-2.sbn"; then
    echo "FAIL: the bundle file is opened in the event loop"; fail=1
fi
exit $fail
