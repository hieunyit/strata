# M4 — Real HTTP proof of signed rule staging on both NGINX versions

Base PR #188 (`879bdc0`), branch `codex/m4-staging-http-proof`. Adds a reproducible standalone probe using the real compiler, a signed two-policy bundle, ASan/UBSan NGINX and an isolated intentionally vulnerable in-memory SQLite backend. Only Rule 700011 (SQLi) is staged in example-api; Rule 700012 (XSS) and example-web remain enforced. A known test seed is generated locally and removed before proxy startup; no real credentials or application data.

Per version, four paired cases on each policy: SQLi-only, XSS-only, both and clean. example-api returns **200/log, 403/block, 403/block, 200/allow**; example-web returns **403/block, 403/block, 403/block, 200/allow**. The selected SQLi reaches the SQLite UNION oracle only in the staged policy; mixed input still blocks on the healthy XSS rule. Assertions check real backend/proxy status, all action variables, healthy Rule ID and EVT-/STR- prefixes. Action assertions exclude a fail-open/error result masquerading as staging.

```sh
python3 tests/security/staging_probe.py --nginx-version 1.30.5 --out-dir build/m4-staging-http-1305-final
python3 tests/security/staging_probe.py --nginx-version 1.31.6 --out-dir build/m4-staging-http-1316-final
```

Executed inside the dev image on CPUs 6–10, existing rebuilt sanitizer binaries and private target directory. **Both pass: 16 paired cases / 32 actual HTTP attempts total**, no sanitizer files. [1.30.5 output](evidence/m4-staging-http/output-1305.txt), [1.31.6 output](evidence/m4-staging-http/output-1316.txt). Each evidence subdirectory includes request rows, source/compiler/bundle/module hashes and counts. No accuracy/throughput metric is derived: permitting the selected attack is intentional in this functional fixture; no browser XSS oracle is claimed.

Self-review: fresh private output directories required; all subprocesses/timeouts and proxy/backend cleanup bounded; no shell command interpolation/dependencies; errors/assertions fail the run; tests/evidence scope only. Script syntax compiled; both final runs use the exact recorded source hash. No hosted CI wait, main merge, staging/production access or automatic re-enforcement.

This proves compiler-to-proxy behavior of a manually selected signed overlay. It does not prove approved-policy auto-derivation, a durable worker/outbox, Fleet/event delivery, reviewer notification or the five-minute activation SLA; those remain pending.
