#!/usr/bin/env python3
"""W09-Q-02: the verdict of a soak run (soak.sh).

Pass when, after the first hour (warm-up: Hyperscan scratch, regexes
compiled on first use, allocator pools):
  - no process grows steadily: the least-squares slope of RSS is under
    --max-mb-per-hour (1 MB/h) for the master and for each worker;
  - file descriptors do not grow either: their slope is under
    --max-fds-per-hour (0.5) for each process (the count moves with the
    connections open at the moment of a sample, so it is a trend, not an
    end-equals-start, that tells a leak);
  - the workers are the same processes from start to end (no crash and
    respawn), and the error log has no alert and no "exited on signal";
  - at least --min-swaps bundles were swapped, and every corrupt bundle was
    refused (one "strata:" refusal in the error log per corrupt bundle).

Usage: soak-check.py <run-dir> [--max-mb-per-hour 1] [--min-swaps 1000]
       soak-check.py --self-test
"""
import argparse
import csv
import os
import re
import sys
import tempfile
from collections import defaultdict


def slope(points):
    """Least-squares slope of (x, y) points; 0 for fewer than 2."""
    n = len(points)
    if n < 2:
        return 0.0
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    den = sum((x - mx) ** 2 for x, _ in points)
    return sum((x - mx) * (y - my) for x, y in points) / den if den else 0.0


def check(run, max_mb_per_hour=1.0, min_swaps=1000, warmup_s=3600, max_fds_per_hour=0.5):
    rows = list(csv.DictReader(open(os.path.join(run, "samples.csv"))))
    if not rows:
        return False, ["no samples"]
    t0 = int(rows[0]["time"])
    by = defaultdict(list)
    for r in rows:
        by[(r["role"], r["pid"])].append(r)
    problems, lines = [], []
    workers_first = {p for (role, p), rs in by.items() if role == "worker" and int(rs[0]["time"]) - t0 < 120}
    workers_last = {p for (role, p), rs in by.items() if role == "worker" and int(rs[-1]["time"]) >= int(rows[-1]["time"]) - 120}
    if workers_first != workers_last:
        problems.append(f"workers changed: {sorted(workers_first)} -> {sorted(workers_last)} (a crash and respawn)")
    for (role, pid), rs in sorted(by.items()):
        steady = [r for r in rs if int(r["time"]) - t0 >= warmup_s]
        if len(steady) < 2:
            continue
        pts = [((int(r["time"]) - t0) / 3600, int(r["rss_kb"]) / 1024) for r in steady]
        s = slope(pts)
        fds = [int(r["fds"]) for r in steady]
        fs = slope([((int(r["time"]) - t0) / 3600, int(r["fds"])) for r in steady])
        lines.append(f"{role} {pid}: RSS {pts[0][1]:.1f} -> {pts[-1][1]:.1f} MB, slope {s:+.3f} MB/h; "
                     f"PSS {int(steady[-1]['pss_kb']) / 1024:.1f} MB; fds {min(fds)}..{max(fds)}, slope {fs:+.3f}/h")
        if s > max_mb_per_hour:
            problems.append(f"{role} {pid}: RSS grows {s:.2f} MB/h (max {max_mb_per_hour})")
        if fs > max_fds_per_hour:
            problems.append(f"{role} {pid}: fds grow {fs:.2f}/h (max {max_fds_per_hour})")
    swaps, corrupt = 0, 0
    if os.path.exists(os.path.join(run, "swaps")):
        swaps, corrupt = map(int, open(os.path.join(run, "swaps")).read().split())
    if swaps < min_swaps:
        problems.append(f"{swaps} bundle swaps (min {min_swaps})")
    errlog = os.path.join(run, "logs", "error.log")
    text = open(errlog, errors="replace").read() if os.path.exists(errlog) else ""
    alerts = len(re.findall(r"\[(alert|crit|emerg)\]", text))
    crashes = text.count("exited on signal")
    # every worker logs the refusal of a bundle it was told to load
    refused = len(re.findall(r'strata: bundle "[^"]*" rejected', text))
    if alerts or crashes:
        problems.append(f"error log: {alerts} alert/crit/emerg, {crashes} worker crashes")
    if corrupt and refused < corrupt:
        problems.append(f"{corrupt} corrupt bundles, only {refused} refusals logged")
    hours = (int(rows[-1]["time"]) - t0) / 3600
    lines.insert(0, f"{hours:.1f} h, {swaps} swaps ({corrupt} corrupt, {refused} refusals logged), "
                    f"{alerts} alerts, {crashes} crashes")
    return not problems, lines + [("FAIL: " + p) for p in problems]


def self_test():
    """A flat run passes; a leaking worker, a fd leak and a respawn fail."""
    def run_dir(leak_kb_per_h=0, fd_leak=0, respawn=False, swaps=1200):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "logs"))
        open(os.path.join(d, "logs", "error.log"), "w").write("")
        open(os.path.join(d, "swaps"), "w").write(f"{swaps} 0")
        with open(os.path.join(d, "samples.csv"), "w") as f:
            f.write("time,swaps,pid,role,rss_kb,pss_kb,fds\n")
            for m in range(0, 25 * 60, 1):
                t = 1000 + m * 60
                f.write(f"{t},{m},10,master,9000,3000,20\n")
                wpid = 12 if respawn and m > 600 else 11
                rss = 40000 + int(leak_kb_per_h * m / 60) + (m % 7) * 30
                fds = 30 + (fd_leak * m // (25 * 60))
                f.write(f"{t},{m},{wpid},worker,{rss},{rss // 2},{fds}\n")
        return d
    ok, _ = check(run_dir())
    assert ok, "a flat run must pass"
    ok, out = check(run_dir(leak_kb_per_h=3 * 1024))
    assert not ok and any("grows" in l for l in out), out
    ok, out = check(run_dir(fd_leak=40))
    assert not ok and any("fds" in l for l in out), out
    ok, out = check(run_dir(respawn=True))
    assert not ok and any("workers changed" in l for l in out), out
    # fds that move with open connections, without a trend, pass
    d = run_dir()
    rows = open(os.path.join(d, "samples.csv")).read().splitlines()
    noisy = [rows[0]] + [l.rsplit(",", 1)[0] + "," + str(30 + (i * 7) % 9) if ",worker," in l else l
                         for i, l in enumerate(rows[1:])]
    open(os.path.join(d, "samples.csv"), "w").write("\n".join(noisy) + "\n")
    ok, out = check(d)
    assert ok, out
    ok, out = check(run_dir(swaps=900))
    assert not ok and any("swaps" in l for l in out), out
    print("soak-check self-test: ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run", nargs="?")
    ap.add_argument("--max-mb-per-hour", type=float, default=1.0)
    ap.add_argument("--min-swaps", type=int, default=1000)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        self_test()
        return
    ok, lines = check(a.run, a.max_mb_per_hour, a.min_swaps)
    print("\n".join(lines))
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
