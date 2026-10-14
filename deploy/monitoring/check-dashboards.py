#!/usr/bin/env python3
"""Checks the Grafana dashboards and alert rules (make test-alerts, W10-Q-01).

- the dashboard files are what gen-dashboards.py writes;
- every dashboard has a unique uid, unique panel ids, the datasource
  variable (PromQL panels), and a query in each panel; ClickHouse panels
  read default.events only (all the Grafana user may read);
- every strata_* metric a dashboard or an alert queries is exported by the
  code (agent, shared-memory collector, control plane), so a renamed metric
  cannot leave an empty panel or an alert that never fires.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SOURCES = {
    "agent/internal/agent/metrics.go": "strata_agent_",
    "agent/internal/shmmetrics/collector.go": "",
    "control-plane/metrics/metrics.go": "",
}
HIST = ("_bucket", "_sum", "_count")


def exported():
    names = set()
    for rel, prefix in SOURCES.items():
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            src = f.read()
        names.update(re.findall(r'"(strata_[a-z0-9_]+)"', src))
        if prefix:
            names.update(prefix + n for n in re.findall(r'desc\("([a-z0-9_]+)"', src))
    names.discard("strata_agent_")
    return names


def used(expr):
    return set(re.findall(r"\b(strata_[a-z0-9_]+)", expr))


def known(name, names):
    return name in names or any(name.endswith(s) and name[: -len(s)] in names for s in HIST)


def main(dash_dir):
    errors = []
    gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gen-dashboards.py")
    r = subprocess.run([sys.executable, gen, "--check"], capture_output=True, text=True)
    if r.returncode:
        errors.append(r.stderr.strip() or r.stdout.strip())
    names = exported()
    uids = set()
    files = sorted(f for f in os.listdir(dash_dir) if f.endswith(".json"))
    if not files:
        errors.append(f"no dashboards in {dash_dir}")
    for fn in files:
        with open(os.path.join(dash_dir, fn), encoding="utf-8") as f:
            d = json.load(f)
        if d["uid"] in uids:
            errors.append(f"{fn}: uid {d['uid']} used twice")
        uids.add(d["uid"])
        promql = [p for p in d["panels"] if p["type"] != "row" and p.get("datasource", {}).get("uid") != "clickhouse"]
        if promql and not any(v["name"] == "datasource" for v in d["templating"]["list"]):
            errors.append(f"{fn}: no datasource variable")
        ids = [p["id"] for p in d["panels"]]
        if len(ids) != len(set(ids)):
            errors.append(f"{fn}: panel ids repeat")
        for p in d["panels"]:
            if p["type"] == "row":
                continue
            if p.get("datasource", {}).get("uid") == "clickhouse":
                # the Grafana user may read default.events only
                for t in p.get("targets", []):
                    sql = t.get("rawSql", "")
                    tables = set(re.findall(r"\bFROM\s+([A-Za-z0-9_.]+)", sql, re.I))
                    depth = 0
                    for ch in re.sub(r"'[^']*'", "''", sql):
                        depth += {"(": 1, ")": -1}.get(ch, 0)
                        if depth < 0:
                            break
                    if depth != 0:
                        errors.append(f"{fn}: panel {p['title']!r}: unbalanced parentheses in the SQL")
                    if not sql or tables != {"default.events"}:
                        errors.append(f"{fn}: panel {p['title']!r}: SQL must read default.events only ({tables or 'no SQL'})")
                continue
            if not p.get("targets") or not all(t.get("expr") for t in p["targets"]):
                errors.append(f"{fn}: panel {p['title']!r} has no query")
            for t in p.get("targets", []):
                for m in used(t["expr"]):
                    if not known(m, names):
                        errors.append(f"{fn}: panel {p['title']!r} queries {m}, which no code exports")
    with open(os.path.join(ROOT, "deploy/monitoring/alerts.yml"), encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if line.lstrip().startswith("#"):
                continue
            for m in used(line):
                if not known(m, names):
                    errors.append(f"alerts.yml:{n}: {m} is not exported by the code")
    for e in errors:
        print("check-dashboards:", e, file=sys.stderr)
    if errors:
        sys.exit(1)
    print(f"check-dashboards: {len(files)} dashboards, {len(names)} exported metrics, OK")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "deploy/monitoring/dashboards"))
