#!/usr/bin/env bash
# W09-Q-01: the event socket alone at a given total rate. <senders> processes
# (the NGINX workers, on BENCH_NGINX_CPUS) send as the module does (sendto,
# MSG_DONTWAIT, an event of the module's size) to the agent's listener and
# decoder (strata-eventsink, on BENCH_READER_CPU). Prints one JSON line per
# rate: events sent, dropped by the senders (socket full), received by the
# sink, CPU per event on the sending side.
# Usage: bench-events.sh [seconds] [senders] [rates...]  (dev image; `make bench` builds the sink)
set -euo pipefail
seconds="${1:-20}"
senders="${2:-2}"
shift 2 || true
rates=("${@:-10000 25000 50000 100000}")
read -r -a rates <<< "${rates[*]}"
root="$(cd "$(dirname "$0")/../../.." && pwd)"
sink="${BENCH_EVENT_SINK:-$root/build/bench/strata-eventsink}"
ncpus="${BENCH_NGINX_CPUS:-2,3}"
rcpu="${BENCH_READER_CPU:-7}"
IFS=, read -r -a cores <<< "$ncpus"
for rate in "${rates[@]}"; do
    work="$(mktemp -d)"
    taskset -c "$rcpu" "$sink" -socket "$work/events.sock" > "$work/sink.json" &
    sp=$!
    for _ in $(seq 50); do [ -S "$work/events.sock" ] && break; sleep 0.1; done
    pids=()
    for i in $(seq 0 $((senders - 1))); do
        taskset -c "${cores[$((i % ${#cores[@]}))]}" "$sink" -send "$work/events.sock" \
            -rate $((rate / senders)) -seconds "$seconds" > "$work/send-$i.json" &
        pids+=($!)
    done
    wait "${pids[@]}"
    sleep 0.5
    kill -TERM "$sp"; wait "$sp" || true
    python3 - "$rate" "$work" "$senders" <<'PY'
import glob, json, sys
rate, work, n = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
s = [json.load(open(f)) for f in sorted(glob.glob(work + "/send-*.json"))]
k = json.load(open(work + "/sink.json"))
sent, dropped = sum(x["sent"] for x in s), sum(x["dropped"] for x in s)
print(json.dumps({"target_rate": rate, "senders": n, "rate": round(sum(x["rate"] for x in s)),
                  "bytes": s[0]["bytes"], "sent": sent, "dropped_by_sender": dropped,
                  "received": k["events"], "lost": sent - k["events"],
                  "drop_pct": round(100 * (dropped + sent - k["events"]) / max(sent + dropped, 1), 3),
                  "cpu_us_per_event": round(sum(x["cpu_us_per_event"] for x in s) / n, 2)}))
PY
    rm -rf "$work"
done
