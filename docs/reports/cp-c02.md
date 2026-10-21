# CP-C02 · Rule and exception lifecycle

Branch: `codex/cp-c02-docs`, dependent on C01 #351. Open for review; no deployment.

Configured rule metadata includes source, version, CVE, attack family, owner and review date.
Canonical hashes cover full rule conditions, so retained-ID edits appear in catalog diffs
and signed release changelogs. Twenty immutable snapshots are retained. Older releases
without hashes report unknown comparisons. Configured catalog/policy usage never asserts
that a particular pack is active on a node.

Exception inventory pages current, latest approved and node-active older revisions. It shows
owner, route/method/field/rule, expiry, approval/replay evidence and explicit unknown usage.
Runtime expiry already works without reload. Cleanup/revoke actions create replay drafts
with etags and durable request receipts; four-eyes and release remain mandatory. Automatic
maintenance preserves human drafts, recovers after a committed draft/crash and reconciles
superseded tasks. Terminal receipts expire after thirty days. New root-path exceptions are
rejected across all policy writers; identical legacy entries can be carried forward.

A real cross-application leak found during implementation was fixed: rule telemetry and FP
counts now respect route/policy/node scope. Legacy FP records without scope fail closed.
First FP classification after a case-only row retains its original automation semantics.

## Local gates

All commands ran in isolated containers on CPUs 6–10; PostgreSQL/ClickHouse were real.
Logs are under ignored `build/` in `/home/hellc/strata-compact-c02`.

- Full CP: `go test -p 1 -race ./...`, exit 0 (`c02-full-go.log`):
  api 103.508s, store 44.803s, ingest 30.308s, ruleinventory 2.026s.
- Added scope regression failed before the fix (`c02-scope-before.log`), passed after:
  ingest 2.634s, store 2.908s (`c02-scope-after.log`).
- Final store/API lifecycle checks and reconciliation, `go test -p 1 -race ./store
  ./ruleinventory ./api`; a development reconciliation SQL error was caught and fixed.
  Final dedicated reconciliation and lint results are recorded below.
- Tools: `go test -p 1 -race ./internal/release ./internal/lifecycle` using native compiler
  and evaluator, exit 0: release 1.634s, lifecycle 1.084s; lint 0 issues.
- Fresh Rust build: `cargo test --locked -p libstrata --test policy_exceptions`, exit 0:
  **4 passed**, including `loaded_exception_expires_for_a_new_transaction_without_reload`.
- UI: `npm run lint`, `npm test -- --run`, `npm run build`, exit 0:
  **36 files, 275 tests passed**, production build 19.64s.
- Selected e2e: migration up/down, Fleet enroll/connect/revoke, four-eyes and policy
  edit/deploy, `go test -race -count=1`, exit 0: **58.348s**.

Browser screenshots: [catalog](cp-c02-rules.png), [exceptions](cp-c02-exceptions.png).
Browser APIs are synthetic authenticated fixtures; Go tests exercise real persistence/scope.
No Rust/C source, proto, bundle format, request path, dependencies or live collector changed.
Shared lab/staging/production were untouched. No benchmark ran.

## Self-review

- Acceptance: metadata/diff, scoped usage/cost, lifecycle provenance/expiry and reviewed
  cleanup have automated positive and negative tests.
- Errors: failed snapshots remain visibly stale; absent measurements remain unknown.
- Bounds: file/rule/metadata limits, SQL paging, catalog history twenty, task quota 10,000,
  expiry scans one hundred, task history twenty and terminal retention thirty days.
- Security: writes check complete policy scope and audit; no raw event payload in catalog;
  privacy filters and viewer reason restrictions apply; no implicit activation.
- Scope: control-plane, rule release tool, generated API/UI and related tests/docs only.
- Lint: exact final results and ordered PR links appended before publication.

Final checks: reconciliation **3.044s**, lint **0 issues**, final store **46.379s**
and API **108.206s** passed. Browser run: **24 existing tests passed**; the two new
fixtures initially omitted their constants, then the corrected isolated rerun passed
**2/2 in 8.7s**. No existing test was removed or disabled.
