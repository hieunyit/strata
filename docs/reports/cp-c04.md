# CP-C04 · Alerts and reports

Branch: `codex/cp-c04-docs`; dependent on C02 #365. Open for review, no deployment.

Grouped durable incidents cover deploy/operation failure, node heartbeat/certificates,
fail-open growth, spool/drop counters, artifact disk, ingest health, backup failure and
exception expiry. The same cause across nodes produces one incident per scope, with
one-hour cooldown, acknowledgment, known recovery and recurrence. First cumulative
counter observation, reset, stale data and missing measurements remain unknown.

The C03 HMAC/HTTPS outbox supplies SSRF/rebinding protection, no redirects, bounded
five-attempt retries and crash leases. Payloads contain opaque incident/report IDs,
fixed cause/state and aggregate counts. No URI, client address, node name, sample,
arbitrary error text or actor identity is copied. Without a receiver, no alert/report
outbound entry is created. Receiver acceptance may precede a crash: receivers should
deduplicate `X-Strata-Delivery`.

Application/environment schedules are opt-in, daily or weekly UTC. Reports retain
aggregate security-event counts and generation-time health for thirty days. They do
not infer total traffic from security events. Report generation uses fenced two-minute
leases; old workers cannot publish. A changed application etag pauses the schedule;
old-scope content is hidden. Every API read, schedule write, acknowledgment and download
rechecks complete current environment authority. Schedule creation/update has durable
request receipts; updates and acknowledgment require an etag and audit.

## Acceptance and local gates

All commands ran on CPUs 6–10 using isolated PostgreSQL/ClickHouse and private browser
fixtures. Logs are in ignored `/home/hellc/strata-compact-c04/build/`.

- Full CP `go test -p 1 -race ./...` with real PG/CH; exact final result below.
- Final targeted tests: operations **3.525s**, store **4.173s**, API **2.217s**, CLI
  **2.370s**, exit 0. Cases include cooldown/grouping, acknowledgment/stale etag,
  unknown-source recovery refusal, bounded delivery metadata, report retries/fencing,
  changed scope, retention, counter reset/freshness, environment isolation and backup
  failure receipt. A scheduled report rejects another route's event and contains no
  client addresses or request paths.
- UI `npm run lint`, `npm test -- --run`, `npm run build`, exit 0:
  **37 files, 279 tests passed**, build **17.59s**.
- Browser: **26 existing tests passed**. The new test initially expected the wrong
  translated health label; after correcting its fixture assertion, **1/1 passed in
  7.1s**, including acknowledge and schedule changes.
- E2E migration up/down, Fleet enroll/connect/revoke, four-eyes and policy edit/deploy:
  `go test -race -count=1`, exit 0, **56.613s**.
- No Rust/C, agent, proto, request-path, bundle-format or dependency change. No benchmark
  or shared lab/staging/production mutation. Existing tests remain enabled.

Browser evidence: [operations](cp-c04-operations.png).

## Bounds and operational limits

Incidents: 10,000 retained entries, thirty-day retention, latest 200 per API list.
Environment scans: ten per cycle with a carried cursor; health node cap 1,000; exception
pages 200 with explicit truncation. Schedules: 1,000; five due reports per cycle, report
quota 10,000, body 16 KiB, latest 32 per environment. Full queues defer work; they never
silently advance a report schedule. Global incidents require global audit authority.
Remote database disk metrics and uncollected signals stay unknown. Backup failures
before a database connection exists cannot be persisted in that database; CLI failures
remain visible to its caller. No deployment or external receiver was exercised.

## Self-review

- Acceptance has real database positive/negative tests and browser evidence.
- Errors never include backup secrets or raw remote errors; source failures stay visible.
- Lists, payloads, leases, quotas and retention are bounded.
- Mutations authorize and audit; exports recheck binding and contain aggregate values only.
- Scope is control plane, generated API/UI and associated tests/docs.
- Full lint result and ordered review PRs are appended before publication.

Final CP run (`c04-full-final.log`) passed every package, exit 0: API **110.040s**,
store **49.321s**, with remaining packages passed/cached from the same stack. The
first run overlapped a test-file split and caught a generated test-main mismatch;
the completed rerun used the stable final files. Go lint then caught one trailing
formatting issue in that test file; `gofmt` and a full lint rerun passed, **0 issues**
(`c04-lint-final.log`, exit 0). No test behavior was removed or weakened.
