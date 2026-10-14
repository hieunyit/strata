#!/usr/bin/env python3
"""Writes the Grafana dashboards of deploy/monitoring/dashboards (W10-Q-01).

The JSON files are generated: edit this script, run it, commit both.
`make test-alerts` checks that the files are what this script writes and
that every metric they query exists in the code (check-dashboards.py).
"""
import json
import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboards")


def panel(title, exprs, unit="short", kind="timeseries", w=12, h=8, desc=""):
    """exprs: list of (expr, legend)."""
    return {
        "type": kind,
        "title": title,
        "description": desc,
        "datasource": {"uid": "${datasource}"},
        "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
        "targets": [{"expr": e, "legendFormat": l, "refId": chr(65 + i)} for i, (e, l) in enumerate(exprs)],
        "_w": w,
        "_h": h,
    }


def row(title):
    return {"type": "row", "title": title, "collapsed": False, "panels": [], "_w": 24, "_h": 1}


def dashboard(uid, title, var_query, panels, desc):
    x = y = 0
    rowh = 0
    out = []
    for i, p in enumerate(panels, start=1):
        w, h = p.pop("_w"), p.pop("_h")
        if x + w > 24 or p["type"] == "row":
            x, y = 0, y + rowh
            rowh = 0
        p["id"] = i
        p["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
        out.append(p)
        x += w
        rowh = max(rowh, h)
        if p["type"] == "row":
            x, y, rowh = 0, y + h, 0
    return {
        "uid": uid,
        "title": title,
        "description": desc,
        "tags": ["strata"],
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "time": {"from": "now-6h", "to": "now"},
        "refresh": "30s",
        "annotations": {"list": []},
        "templating": {"list": [
            {"name": "datasource", "type": "datasource", "query": "prometheus"},
            {"name": "instance", "type": "query", "datasource": {"uid": "${datasource}"},
             "query": var_query, "refresh": 2, "multi": True, "includeAll": True,
             "current": {"text": "All", "value": "$__all"}},
        ]},
        "panels": out,
    }


I = '{instance=~"$instance"}'


def sel(extra=""):
    return '{instance=~"$instance"%s}' % extra


module = dashboard("strata-module", "Strata module", "label_values(strata_metrics_file_up, instance)", [
    row("Traffic"),
    panel("Requests by action", [(f"sum by (action) (rate(strata_requests_total{I}[5m]))", "{{action}}")], "reqps"),
    panel("Engine time p50 / p99", [
        (f"histogram_quantile(0.5, sum by (le) (rate(strata_engine_seconds_bucket{I}[5m])))", "p50"),
        (f"histogram_quantile(0.99, sum by (le) (rate(strata_engine_seconds_bucket{I}[5m])))", "p99"),
    ], "s", desc="Time in libstrata per request. Target: overhead p99 below 1 ms (nginx-module.md)."),
    panel("Body inspected", [(f"sum (rate(strata_body_inspected_bytes_total{I}[5m]))", "bytes/s")], "Bps"),
    panel("Fail mode and CPU budget (share of requests)", [
        (f"sum by (mode) (rate(strata_fail_mode_total{I}[5m])) / scalar(clamp_min(sum (rate(strata_requests_total{I}[5m])), 1e-9))", "fail {{mode}}"),
        (f"sum (rate(strata_budget_exceeded_total{I}[5m])) / clamp_min(sum (rate(strata_requests_total{I}[5m])), 1e-9)", "over budget"),
    ], "percentunit", desc="Alerts StrataFailModeHigh, StrataBudgetExceeded above 1%."),
    row("Bundles and events"),
    panel("Bundle version per worker", [(f"strata_bundle_version{I}", "{{instance}} w{{worker}}")], "none",
          desc="All workers should run the version the agent installed (alert StrataWorkersOnOldBundle)."),
    panel("Workers and metrics file", [
        (f"strata_workers{I}", "workers {{instance}}"),
        (f"strata_metrics_file_up{I}", "metrics file up {{instance}}"),
    ], "none"),
    panel("Events dropped at the socket (share)", [
        (f"sum by (instance) (rate(strata_events_dropped_total{I}[5m])) / clamp_min(sum by (instance) (rate(strata_events_dropped_total{I}[5m]) + rate(strata_agent_events_received_total{I}[5m])), 1e-9)", "{{instance}}"),
    ], "percentunit", w=24, desc="Alert StrataEventsDropped above 0.1%; net.unix.max_dgram_qlen must be 8192."),
], "NGINX module: traffic, engine time, fail mode, bundles, events. Source: the metrics file, exported by strata-agent.")

agent = dashboard("strata-agent", "Strata agent", "label_values(strata_agent_spool_bytes, instance)", [
    row("Control plane link"),
    panel("Control stream", [(f"strata_agent_control_connected{I}", "{{instance}}")], "bool_yes_no", w=8,
          desc="1 while the Connect stream is open (alert StrataAgentDisconnected)."),
    panel("Certificate time left", [(f"strata_agent_cert_not_after_seconds{I} - time()", "{{instance}}")], "s", w=8,
          desc="24 h certificates, renewed 8 h before expiry (alert StrataAgentCertExpiring under 4 h)."),
    panel("ForceShadow", [(f"strata_agent_force_shadow_active{I}", "{{instance}}")], "bool_yes_no", w=8),
    panel("Installed bundle", [(f"strata_agent_bundle_active_version{I}", "{{instance}}")], "none", w=8),
    panel("net.unix.max_dgram_qlen", [(f"strata_agent_unix_max_dgram_qlen{I}", "{{instance}}")], "none", w=8,
          desc="Needs 8192 (alert StrataDgramQueueTooShort); 0 means unknown."),
    panel("Stream reconnects / throttled", [
        (f"sum by (instance) (rate(strata_agent_push_reconnects_total{I}[5m]))", "reconnects {{instance}}"),
        (f"sum by (instance) (rate(strata_agent_push_throttled_total{I}[5m]))", "throttled {{instance}}"),
    ], "ops", w=8),
    row("Events"),
    panel("Events received / invalid", [
        (f"sum by (instance) (rate(strata_agent_events_received_total{I}[5m]))", "received {{instance}}"),
        (f"sum by (instance) (rate(strata_agent_events_invalid_total{I}[5m]) + rate(strata_agent_events_truncated_total{I}[5m]))", "invalid {{instance}}"),
    ], "ops"),
    panel("Events lost", [
        (f"sum by (instance) (rate(strata_events_dropped_total{I}[5m]))", "socket full {{instance}}"),
        (f"sum by (instance) (rate(strata_agent_spool_dropped_events_total{I}[5m]))", "spool full {{instance}}"),
    ], "ops"),
    panel("Spool", [(f"strata_agent_spool_bytes{I}", "{{instance}}")], "bytes"),
    panel("Unacked batches", [(f"strata_agent_spool_unacked_batches{I}", "{{instance}}")], "none"),
], "strata-agent: control stream, certificate, ForceShadow, bundle, event spool.")

C = sel()
cp = dashboard("strata-control-plane", "Strata control plane", "label_values(strata_cp_build_info, instance)", [
    row("Service"),
    panel("Up / build", [(f'up{{job="strata-control-plane",instance=~"$instance"}}', "up {{instance}}"),
                         (f"strata_cp_store_up{C}", "PostgreSQL {{instance}}")], "bool_yes_no", w=8),
    panel("Nodes", [(f"strata_cp_nodes_enrolled{C}", "enrolled"), (f"strata_cp_nodes_connected{C}", "connected")],
          "none", w=8, desc="Alert StrataNodesOffline when enrolled > connected for 10 min."),
    panel("Rollouts", [(f"strata_cp_rollouts_active{C}", "active"), (f"strata_cp_rollout_oldest_seconds{C}", "oldest (s)")],
          "none", w=8, desc="Alert StrataRolloutStuck after 30 min."),
    panel("REST requests by status", [(f"sum by (code) (rate(strata_cp_http_requests_total{C}[5m]))", "{{code}}")], "reqps"),
    panel("REST p99 by route", [
        (f"histogram_quantile(0.99, sum by (le, route) (rate(strata_cp_http_request_seconds_bucket{C}[5m])))", "{{route}}")], "s",
          desc="Block ID lookup target < 1 s, 24 h search < 2 s (W09-G2-01)."),
    panel("Deploys", [(f"sum by (result) (increase(strata_cp_deploys_total{C}[1h]))", "{{result}}")], "none",
          desc="Compile, sign, store, start a rollout (alert StrataDeployFailed)."),
    panel("Deploy time p95", [
        (f"histogram_quantile(0.95, sum by (le) (rate(strata_cp_deploy_seconds_bucket{C}[1h])))", "p95")], "s"),
    row("Event ingest"),
    panel("Events from agents", [(f"sum by (result) (rate(strata_cp_ingest_events_total{C}[5m]))", "{{result}}"),
                                 (f"sum (rate(strata_cp_ingest_events_stored_total{C}[5m]))", "stored")], "ops"),
    panel("Batches", [(f"sum by (result) (rate(strata_cp_ingest_batches_total{C}[5m]))", "{{result}}")], "ops"),
    panel("Queue and ClickHouse errors", [(f"strata_cp_ingest_queue{C}", "queue"),
                                          (f"increase(strata_cp_ingest_store_errors_total{C}[10m])", "write errors (10 min)")], "none"),
    panel("Firing alerts", [('count by (alertname, severity) (ALERTS{alertstate="firing"})', "{{alertname}} ({{severity}})")],
          "none", desc="Alerts of deploy/monitoring/alerts.yml that fire now, every component (vmalert writes ALERTS)."),
    panel("Memory / goroutines", [(f"process_resident_memory_bytes{{job=\"strata-control-plane\",instance=~\"$instance\"}}", "RSS"),
                                  (f"go_goroutines{{job=\"strata-control-plane\",instance=~\"$instance\"}}", "goroutines")], "short"),
], "Control plane: API, nodes, rollouts, deploys, event ingest.")


CH = {"type": "grafana-clickhouse-datasource", "uid": "clickhouse"}
# shadow events of the selected policies, attack sources excluded (the same
# rules as strata-rules fp-report, W10-S-01)
FP_WHERE = ("$__timeFilter(timestamp) AND action = 'shadow' AND policy_id IN (${policy:singlequote})"
            " AND NOT ((isIPv4String(client_ip) OR isIPv6String(client_ip)) AND arrayExists("
            "c -> isIPAddressInRange(client_ip, c), arrayFilter(x -> x != '', splitByChar(',', '${exclude:raw}'))))")


def chpanel(title, sql, kind="table", w=24, h=10, desc="", unit="none"):
    fmt = 1 if kind == "table" else 0
    return {
        "type": kind, "title": title, "description": desc, "datasource": CH,
        "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
        "targets": [{"refId": "A", "datasource": CH, "editorType": "sql", "format": fmt,
                     "queryType": "table" if kind == "table" else "timeseries", "rawSql": sql}],
        "_w": w, "_h": h,
    }


fp = dashboard("strata-shadow-fp", "Strata shadow FP", "", [
    chpanel("Suspected false positives by day and rule (shadow)",
            "SELECT toDate(timestamp) AS day, rule_id, uniqExact(block_id) AS events, uniqExact(client_ip) AS sources, "
            "topK(1)(policy_id)[1] AS top_policy FROM default.events ARRAY JOIN arrayDistinct(matched_rules) AS rule_id "
            "WHERE " + FP_WHERE + " GROUP BY day, rule_id ORDER BY day DESC, events DESC, rule_id LIMIT 500",
            h=12, desc="Shadow events of the selected policies, attack sources (exclude) left out: every row is a rule "
                       "that would have blocked this traffic. Same query as strata-rules fp-report."),
    chpanel("Shadow events per hour, by policy",
            "SELECT toStartOfHour(timestamp) AS time, policy_id, uniqExact(block_id) AS events FROM default.events "
            "WHERE " + FP_WHERE + " GROUP BY time, policy_id ORDER BY time",
            kind="timeseries", w=12, h=9),
    chpanel("Requests not fully inspected (fail mode), by policy",
            "SELECT toStartOfHour(timestamp) AS time, policy_id, count() AS events FROM default.events "
            "WHERE $__timeFilter(timestamp) AND action = 'error' AND policy_id IN (${policy:singlequote}) "
            "GROUP BY time, policy_id ORDER BY time",
            kind="timeseries", w=12, h=9,
            desc="Engine errors and CPU budget overruns handled by the fail mode: these requests were not inspected (#28, #49)."),
], "Shadow events per rule and day for the false-positive review (W10-S-01), from ClickHouse.")
fp["templating"]["list"] = [
    {"name": "policy", "type": "query", "datasource": CH, "label": "Policy", "multi": True, "includeAll": False,
     "query": "SELECT DISTINCT policy_id FROM default.events WHERE timestamp > now() - INTERVAL 30 DAY ORDER BY policy_id",
     "refresh": 2, "current": {"text": ["pilot-verify", "pilot-upload"], "value": ["pilot-verify", "pilot-upload"]}},
    {"name": "exclude", "type": "textbox", "label": "Exclude IPs/CIDRs (comma)", "query": "",
     "current": {"text": "", "value": ""}},
]
fp["time"] = {"from": "now-7d", "to": "now"}


def main():
    os.makedirs(OUT, exist_ok=True)
    for d in (module, agent, cp, fp):
        text = json.dumps(d, indent=1, ensure_ascii=False) + "\n"
        path = os.path.join(OUT, d["uid"] + ".json")
        if "--check" in sys.argv:
            with open(path, encoding="utf-8") as f:
                if f.read() != text:
                    sys.exit(f"{path} is not what gen-dashboards.py writes: run it and commit")
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)


if __name__ == "__main__":
    main()
