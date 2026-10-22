#!/usr/bin/env python3
"""W09-Q-01: Markdown tables from bench-all.sh's JSON lines.

Each cell is the median of its runs (min-max in brackets). Throughput comes
from the 64-connection runs, latency overhead from the 4-connection runs
(no queueing). Usage: bench-report.py <nginx-version> <file.jsonl>
"""
import json
import statistics
import sys
from collections import defaultdict

version, path = sys.argv[1], sys.argv[2]
cells = defaultdict(list)
for line in open(path):
    line = line.strip()
    if line:
        r = json.loads(line)
        cells[(r["scenario"], r["mode"], r.get("conns", 64))].append(r)


def med(rs, k):
    v = [r[k] for r in rs if k in r]
    return round(statistics.median(v), 1) if v else None


def rng(rs, k):
    v = [r[k] for r in rs if k in r]
    return f"{min(v):.0f}–{max(v):.0f}" if v else ""


print(f"### NGINX {version}\n")
print("Throughput (64 connections, keep-alive); Δ against off:\n")
print("| Scenario | req/s off | req/s phase 0-1 | Δ | req/s full | Δ | engine mean µs (p01 / full) | fail-open (p01 / full) |")
print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
for sc in ("small", "64k", "1m", "h2"):
    off = cells.get((sc, "off", 64))
    p01, full = cells.get((sc, "p01", 64)), cells.get((sc, "full", 64))
    if not off or not p01 or not full:
        continue
    a, b, c = med(off, "rps"), med(p01, "rps"), med(full, "rps")
    print(f"| {sc} | {a:,.0f} | {b:,.0f} | {(b - a) / a * 100:+.1f}% | {c:,.0f} | {(c - a) / a * 100:+.1f}% | "
          f"{med(p01, 'engine_mean_us')} / {med(full, 'engine_mean_us')} | {med(p01, 'fail_open'):.0f} / {med(full, 'fail_open'):.0f} |")

print("\nLatency (4 connections, no queueing), µs; overhead = on - off:\n")
print("| Scenario | p50 off | p99 off | p50 p01 | p99 p01 | overhead p50 / p99 (p01) | p50 full | p99 full | overhead p50 / p99 (full) |")
print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
for sc in ("small", "64k", "1m"):
    off, p01, full = cells.get((sc, "off", 4)), cells.get((sc, "p01", 4)), cells.get((sc, "full", 4))
    if not off or not p01 or not full:
        continue
    a50, a99 = med(off, "p50_us"), med(off, "p99_us")
    b50, b99 = med(p01, "p50_us"), med(p01, "p99_us")
    c50, c99 = med(full, "p50_us"), med(full, "p99_us")
    print(f"| {sc} | {a50:.0f} | {a99:.0f} | {b50:.0f} | {b99:.0f} | {b50 - a50:+.0f} / {b99 - a99:+.0f} | "
          f"{c50:.0f} | {c99:.0f} | {c50 - a50:+.0f} / {c99 - a99:+.0f} |")

ev = cells.get(("small", "events", 64))
on = cells.get(("small", "p01", 64))
if ev and on:
    print("\nEvent socket (phase 0-1 bundle; every request sends an event, 64 connections):\n")
    print("| req/s p01 | req/s p01 + events | Δ | events received | events dropped | drop % | events/s |")
    print("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    a, b = med(on, "rps"), med(ev, "rps")
    recv, drop = med(ev, "events_received"), med(ev, "events_dropped")
    pct = drop / (recv + drop) * 100 if recv + drop else 0
    secs = ev[0].get("seconds") or 0
    rate = f"{(recv + drop) / secs:,.0f}" if secs else ""
    print(f"| {a:,.0f} | {b:,.0f} | {(b - a) / a * 100:+.1f}% | {recv:,.0f} | {drop:,.0f} | {pct:.2f}% | {rate} |")

# 22/10/2026: other processes on the NGINX CPUs during the runs. Above a few
# percent the numbers of a run are not comparable with another run's.
noisy = sorted(
    ((r.get("cpu_noise_pct", 0), k) for k, rs in cells.items() for r in rs),
    reverse=True,
)
if noisy and "cpu_noise_pct" in next(iter(cells.values()))[0]:
    worst, key = noisy[0]
    print(f"\nCPU noise on the NGINX CPUs (time used by other processes): max {worst}% "
          f"({key[0]} {key[1]}, {key[2]} connections)", end="")
    over = [n for n, _ in noisy if n > 5]
    print(f"; {len(over)} of {len(noisy)} runs over 5%: isolate the CPUs and run again" if over else "; all runs under 5%.")
