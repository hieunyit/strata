#!/usr/bin/env python3
"""CPU noise on the benchmark's NGINX CPUs (22/10/2026).

  cpu-noise.py snap <cpus> <master-pid> <out.json>
  cpu-noise.py diff <before.json> <after.json>     -> {"cpu_noise_pct": x}

The share of the NGINX CPUs' time used by other processes during a run:
busy time of those CPUs (/proc/stat) minus the CPU time of NGINX's master
and workers (/proc/<pid>/stat), over the run's length. Other work on the
same CPUs slows NGINX and skews every number of the run (the engine time,
and the requests over budget when the budget counted wall time).
"""
import json
import os
import sys
import time


def cpus(spec):
    out = set()
    for part in spec.split(","):
        a, _, b = part.partition("-")
        out.update(range(int(a), int(b or a) + 1))
    return sorted(out)


def busy(cpu_ids):
    total = 0
    for line in open("/proc/stat"):
        name, *v = line.split()
        if name.startswith("cpu") and name[3:].isdigit() and int(name[3:]) in cpu_ids:
            # user nice system idle iowait irq softirq steal
            v = [int(x) for x in v[:8]]
            total += v[0] + v[1] + v[2] + v[5] + v[6] + v[7]
    return total


def tree_ticks(master):
    pids = [master]
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                f = open(f"/proc/{d}/stat").read()
            except OSError:
                continue
            if int(f.rsplit(")", 1)[1].split()[1]) == master:
                pids.append(int(d))
    total = 0
    for p in pids:
        try:
            f = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        total += int(f[11]) + int(f[12])  # utime stime
    return total


def main():
    if sys.argv[1] == "snap":
        ids = cpus(sys.argv[2])
        snap = {"t": time.monotonic(), "cpus": ids, "busy": busy(ids), "nginx": tree_ticks(int(sys.argv[3]))}
        json.dump(snap, open(sys.argv[4], "w"))
        return
    a, b = (json.load(open(p)) for p in sys.argv[2:4])
    hz = os.sysconf("SC_CLK_TCK")
    span = (b["t"] - a["t"]) * hz * len(a["cpus"])
    other = (b["busy"] - a["busy"]) - (b["nginx"] - a["nginx"])
    print(json.dumps({"cpu_noise_pct": round(max(other, 0) * 100 / span, 1) if span > 0 else 0}))


if __name__ == "__main__":
    main()
