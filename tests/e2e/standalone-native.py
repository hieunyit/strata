#!/usr/bin/env python3
"""Local standalone acceptance with real signed bundles, agent and NGINX.

Run in the dev image after rebuilding nginx-asan. This is a process lab,
not a clean VM/package installation or a production acceptance test.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def eventually(check, description, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return
        time.sleep(0.05)
    raise AssertionError(description)


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("nginx", "module", "compiler", "agent", "output"):
        ap.add_argument("--" + name, required=True, type=Path)
    args = ap.parse_args()
    started = time.monotonic()
    args.output.mkdir(parents=True, exist_ok=False)
    out = args.output.resolve()
    root = Path(__file__).resolve().parents[2]
    work = Path(tempfile.mkdtemp(prefix="standalone-native-", dir=root / "build"))
    (work / "logs").mkdir()
    processes = []
    logs = []

    class Backend(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"example backend\n")

        def log_message(self, *_):
            pass

    backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    backend_thread = threading.Thread(target=backend.serve_forever)
    backend_thread.start()
    try:
        policies = work / "policies.json"
        policies.write_text(json.dumps({"policies": [{"name": "example-api", "mode": "enforce"}]}))
        # Use the repository's reviewed sample rule IR, including detect_sqli.
        # The YAML parser lives in the compiler, so append the added rule there.
        rules = (root / "engine/compiler/examples/rules.yaml").read_text()
        # The sample IR scores SQLi at 5 against a threshold of 100. Enable
        # block_alone only in this generated detector transport fixture;
        # this lab does not alter or certify the shipped rule pack.
        rules = rules.replace("  - id: 942100\n", "  - id: 942100\n    action_mode: block_alone\n", 1)
        rule_path = work / "rules.yaml"
        rule_path.write_text(rules)

        def compile_bundle(version):
            dest = work / f"version-{version}.sbn"
            subprocess.run([str(args.compiler.resolve()), "--policies", str(policies),
                            "--rules", str(rule_path), "--key", str(root / "connectors/nginx/t/fixtures/test.key"),
                            "--version", str(version), "--out", str(dest)], check=True,
                           stdout=subprocess.DEVNULL)
            return dest.read_bytes()

        first = compile_bundle(1)
        rule_path.write_text(rules + """
  - id: 100099
    name: Standalone reload fixture
    layer: protocol
    stage: request_headers
    action_mode: block_alone
    match:
      all:
        - targets: [{var: uri_raw}]
          operator: {type: contains, value: '/after-reload'}
    score: 100
    severity: critical
    metadata: {source: strata, license: Apache-2.0, author: test-fixture}
""")
        second = compile_bundle(2)
        source, control = work / "source.sbn", work / "control"
        source.write_bytes(first)
        event_file = work / "events.jsonl"
        metrics_port, nginx_port = port(), port()
        agent_log = (out / "agent.log").open("wb")
        logs.append(agent_log)
        agent = subprocess.Popen([str(args.agent.resolve()), "run", "--standalone",
                                  "--bundle-file=" + str(source), "--bundle-dir=" + str(work),
                                  "--bundle-pubkey=" + str(root / "connectors/nginx/t/fixtures/bundle.pub"),
                                  "--control-file=" + str(control), "--event-socket=" + str(work / "events.sock"),
                                  "--events-jsonl=" + str(event_file), "--node-id=example-node",
                                  "--metrics-addr=127.0.0.1:" + str(metrics_port), "--metrics-file=",
                                  "--bundle-poll-interval=50ms"], stdout=agent_log, stderr=agent_log, start_new_session=True)
        processes.append(agent)

        def version():
            if not control.exists():
                return 0
            return struct.unpack_from("<Q", control.read_bytes(), 24)[0]

        eventually(lambda: version() == 1, "agent failed to install initial signed bundle")
        conf = work / "nginx.conf"
        conf.write_text(f"""load_module {args.module.resolve()};
daemon off;
worker_processes 1;
pid {work}/nginx.pid;
error_log {out}/nginx-error.log notice;
events {{ worker_connections 128; }}
http {{
 access_log off;
 strata_control_file {control};
 strata_bundle_dir {work};
 strata_bundle_pubkey {root}/connectors/nginx/t/fixtures/bundle.pub;
 strata_event_socket unix:{work}/events.sock;
 strata_node_id example-node;
 strata_metrics_file {work}/metrics;
 server {{ listen 127.0.0.1:{nginx_port}; server_name api.example.test;
  location / {{ strata on; strata_policy example-api;
   proxy_pass http://127.0.0.1:{backend.server_port}; }}
 }}
}}
""")
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = f"detect_leaks=0,detect_odr_violation=0,log_path={out}/asan"
        env["UBSAN_OPTIONS"] = f"print_stacktrace=1,log_path={out}/ubsan"
        nginx_log = (out / "nginx-process.log").open("wb")
        logs.append(nginx_log)
        nginx = subprocess.Popen([str(args.nginx.resolve()), "-p", str(work) + "/", "-c", str(conf)],
                                 env=env, stdout=nginx_log, stderr=nginx_log, start_new_session=True)
        processes.append(nginx)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def status(path):
            try:
                with opener.open(f"http://127.0.0.1:{nginx_port}" + path, timeout=1) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                e.close()
                return e.code
            except (OSError, urllib.error.URLError):
                return None

        eventually(lambda: status("/benign") == 200, "benign request did not reach real upstream")
        assert status("/?q=1%27%20OR%201%3D1--") == 403, "real SQLi was not blocked"
        assert status("/after-reload") == 200
        children = Path(f"/proc/{nginx.pid}/task/{nginx.pid}/children").read_text()
        # The same source path changes; the engine receives an immutable file.
        replacement = work / "incoming"
        replacement.write_bytes(second)
        replacement.replace(source)
        eventually(lambda: version() == 2, "agent did not install second bundle")
        eventually(lambda: status("/after-reload") == 403, "worker did not hot reload")
        assert nginx.poll() is None, "NGINX exited during hot reload"
        assert children and Path(f"/proc/{nginx.pid}/task/{nginx.pid}/children").read_text() == children, "worker processes restarted"
        c = control.read_bytes()
        name = c[66:66 + struct.unpack_from("<H", c, 64)[0]].decode()
        assert hashlib.sha256((work / name).read_bytes()).digest() == c[32:64]
        # A signed older bundle without rollback authorization must not win.
        replacement.write_bytes(first)
        replacement.replace(source)
        eventually(lambda: "older bundle requires signed rollback flag" in (out / "agent.log").read_text(),
                   "older bundle was not rejected")
        assert version() == 2 and status("/after-reload") == 403
        tampered = bytearray(second)
        tampered[40] ^= 1
        replacement.write_bytes(tampered)
        replacement.replace(source)
        eventually(lambda: "bundle verification failed" in (out / "agent.log").read_text(),
                   "tampered bundle was not rejected")
        assert version() == 2 and status("/after-reload") == 403
        eventually(lambda: event_file.exists() and '"block_id"' in event_file.read_text(), "no exported real event")
        with opener.open(f"http://127.0.0.1:{metrics_port}/metrics", timeout=2) as r:
            metrics = r.read().decode()
        assert any(line.startswith("strata_agent_standalone_events_exported_total ")
                   and float(line.split()[1]) > 0 for line in metrics.splitlines())
        events = [json.loads(line) for line in event_file.read_text().splitlines()]
        assert any(942100 in ev.get("rule_ids", []) and ev.get("node_id") == "example-node" for ev in events)
        result = {"benign": 200, "sqli": 403, "before_reload": 200, "after_reload": 403,
                  "bundle_version": version(), "control_hash_matches": True, "events": len(events),
                  "no_nginx_reload_command": True, "worker_pids_unchanged": True,
                  "rejected_rollback_and_tampering": True, "elapsed_seconds": round(time.monotonic() - started, 3), "scope": "local processes; not package/VM acceptance"}
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    finally:
        cleanup_errors = []
        for process in reversed(processes):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            if process.returncode:
                cleanup_errors.append(f"process exited with {process.returncode}; inspect {out}")
        for log in logs:
            log.close()
        backend.shutdown()
        backend.server_close()
        backend_thread.join()
        if cleanup_errors:
            raise AssertionError("; ".join(cleanup_errors))
    assert not list(out.glob("asan*")) and not list(out.glob("ubsan*")), "sanitizer report produced"
    assert "DATA RACE" not in (out / "agent.log").read_text(), "Go race detected"
    print(json.dumps(result))


if __name__ == "__main__":
    main()
