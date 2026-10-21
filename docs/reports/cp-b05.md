# CP-B05 · System health and doctor

Implements Compact B05 after B02/B01/B04 and the final integration corrections. PostgreSQL
and ClickHouse remain; local authentication remains the default, OIDC/Keycloak optional.
B03 is excluded. Operator instructions: [doctor runbook](../runbook/doctor.md).

## Delivered

- Authenticated `/v1/health` and the Health page collect dependency/schema/lease readiness,
  artifact disk space, ingest queue/invalid events/delivery lag/clock skew, failed operations
  in 24 hours, inspection/body/breaker/shadow, node heartbeat/version drift/certificate,
  spool bytes/capacity/pending batches and dropped events. Agent telemetry is bounded and
  persisted by authenticated Fleet heartbeat (migration 0034); optional protobuf fields
  preserve old-agent compatibility. No bundle ABI change or new dependency.
- Unknown, measured zero, stale, degraded and unavailable are distinct. Sources carry
  observation timestamps; 90-second freshness applies. Future heartbeat/snapshot times
  cannot make data appear fresh. Missing worker metrics do not become measured zeros.
  Inspection aggregates every policy/node rather than a top-N result; the oldest latest
  observation controls freshness. ClickHouse lag queries are bounded and quiet periods
  return unknown. Large counters retain UInt64 precision as decimal strings.
- The page polls every five seconds, ages cached results independently of network progress,
  localizes English/Vietnamese labels and next actions, and paginates nodes (50/page).
  The API caps nodes at 1,000 and explicitly reports truncation. Scoped users see only
  authorized nodes/events; whole-node request counters and global policy operation counts
  are withheld when their dimensions do not support the caller's scope. Machine scope
  ceilings still apply.
- `strata-control-plane doctor -config FILE [-json] [-support-bundle NEWFILE]` reads existing
  schemas, lease, counters and filesystem without migration, worker startup or lease
  acquisition. A dedicated ClickHouse version reader avoids the migration-ledger creation
  performed by the normal migration helper. Exit statuses are documented in the runbook.
- The private support tar.gz contains allowlisted health, numeric/boolean/duration effective
  configuration, generated diagnostic status lines and a SHA-256 manifest. Node IDs are
  pseudonymized. Unknown fields, free-form strings, credential paths and raw logs/request
  data never enter the archive. Existing paths/symlinks are refused atomically; file/member
  permissions are 0600 and members are bounded to 4 MiB. Secret/PII regression tests cover
  nested payloads and configuration injection.

## Validation

All commands used CPUs 6–10 and isolated PostgreSQL 17.11 / ClickHouse 25.8.33. Tests did not
modify the shared lab, staging or production. Local Compact gates apply (AGENTS §8a).

```text
control-plane: go test -p 1 -race ./... → PASS
  api 27.156s; cmd/server 107.830s; health 1.959s; ingest 28.268s; store 33.753s
agent: go test -p 1 -race ./... → PASS
control-plane / agent: golangci-lint run ./... → 0 issues.
UI lint and production build → PASS
UI unit tests → 33 files / 255 tests passed
Playwright → 21 passed (53.6s)
Final health/applications/releases browser checks → 3 passed (10.1s)
e2e real agent enrollment/connect/revoke + persisted spool heartbeat → PASS (31.074s)
e2e migration up/down, four-eyes, policy edit/deploy → PASS (27.480s)
buf generate / buf lint / admin client generation → PASS
```

Focused read-only doctor/ClickHouse tests, unavailable dependencies, scoped withholding,
freshness/future times, measured zero, failed operations, disk errors, spool bounds and
support-bundle leakage/refusal tests passed. Integrated store/API suites after the binding
authority correction passed (33.651s / 23.068s); final policy/admin publication tests passed
(2.404s / 7.848s), both with race. UI release/application precondition tests and build passed.
Final integrated rerun after every correction: `go test -p 1 -race ./...`, exit 0;
admin 8.431s, API 26.142s, cmd/server 97.114s, Fleet 35.774s, health 1.866s,
policy 3.498s, store 33.948s. Agent full race rerun and lint also passed (`0 issues.`).
Local outputs are retained in `build/compact-b-final-{go,agent,agent-lint}.log`;
control-plane lint output is `build/b05-lint-final-complete.log`.

The first real-agent e2e exposed B02's wrapped optional-manifest absence error, which caused
exit before Hello. It was fixed with a specific sentinel and the e2e passed on retry. An
existing manifest referencing a missing binary still fails. Binding mutation and scoped
publication corrections are documented in [integration fixes](cp-b-integration-fixes.md).
No existing test was disabled or signing/TLS/authentication check bypassed.

## Limits and self-review

Remote PostgreSQL/ClickHouse disk capacity has no source yet and remains unknown. Offline
doctor cannot observe the live process's ingest queue. Inspection/spool values are diagnostic
counters rather than proof that every worker is alive or has activated a module. No benchmark,
full live fault matrix, native detector quality run or production deployment is claimed.
Support exports deliberately omit raw logs and arbitrary effective-config strings; C03's
cross-product privacy pipeline is future work.

Self-review: all delivered conditions have automated evidence above; read errors become
unknown/unavailable rather than successful zeros; queries/telemetry/export/node lists are
bounded; RBAC is enforced on the server; no secret/PII is exported; shared proto/OpenAPI
contracts and design notes are updated; both Go linters and UI lint pass. See the final
implementation index for the dependent PR order.
