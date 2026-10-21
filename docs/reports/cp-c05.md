# CP-C05 · API discovery preview

Branch: `codex/cp-c05-docs`, dependent on C04 #375. Open for review; no deployment.
PostgreSQL/ClickHouse and local-auth defaults remain. B03 is excluded.

The dedicated backend-observation feed defaults **off**. Enabling it requires an actual
legal approval reference and unexpired approval, an independent private HMAC key and an
explicit allowlist of machine collectors. Ordinary sessions, untrusted machines, missing
or expired approval, non-backend responses, non-2xx status, wrong routes and excessive
inputs are rejected. Only synthetic approvals/traffic were used in tests. No collector
was enabled or installed on NGINX. A trusted backend/access-log adapter must supply the
separate contract after actual legal approval; the security-event stream is not used.

Normalization precedes persistence: query data is removed, unknown path segments and
resource identifiers are replaced, source addresses become keyed per-scope/day pseudonyms,
and stable observation UUIDs are keyed/deduplicated across batches. No raw address, path
identifier, query, body or request header is stored. Conservative templates can merge
routes. Proposal eligibility requires **20 observations, 3 distinct address sources in
one UTC day and a 10-minute observation span**. Distinct addresses are not proof of
independent people; human review remains essential.

The OpenAPI 3.0/3.1 operation index stores paths/methods/media types/observed body bounds.
It rejects duplicate keys, YAML aliases, remote references, invalid paths and excessive
complexity. It does not implement general schema validation or resolve local references.
Proposals retain immutable baseline digests, evidence and before/after changes. Draft
conversion commits the proposal/version link, candidate digest metadata, policy draft,
replay and audit atomically. Retries and concurrent calls produce one draft/replay.
Changed bindings or baselines cannot attach an old candidate. The UI shows the document
diff beside the existing review controls for the exact policy revision.

**Runtime OpenAPI enforcement is absent in the current branch.** This is a documentation
proposal workflow, clearly labelled in UI and downloaded `x-strata-mode: documentation_only`
OpenAPI files. It does not change request processing, protobuf, FFI, dependencies or bundle
format, and does not automatically enable blocking. Normal four-eyes/replay/release gates
remain; approval of a documentation proposal does not add engine support.

## Acceptance and local gates

All commands used isolated containers pinned to CPUs 6–10. Logs are in ignored
`/home/hellc/strata-compact-c05/build/`. PostgreSQL/ClickHouse were real; traffic, accounts,
approval references and browser API fixtures were synthetic.

- CP: `go test -p 1 -race ./...`, exit 0 (`c05-full-go.log`): API **115.103s**, CLI
  **99.933s**, fleet **45.606s**, ingest **30.746s**, local auth **37.829s**, store
  **55.716s**. Full Go lint result appended below.
- Final security regressions (`c05-final-acceptance.log`), exit 0: normalization **1.087s**,
  store **7.095s**, API **2.443s**, auth **1.125s**, config passed/cached, CLI **1.277s**.
  Cases cover legal/machine scope gates, source/identifier privacy, no security-event
  fallback, batch/observation dedupe, cardinality/row caps, retention, stale baselines,
  concurrent draft conversion, etag/idempotency, exact replay linkage and self-approval
  refusal. Final API-only pass: **2.878s** (`c05-api-final.log`).
- A retention parameter-type error was caught during implementation and corrected with
  an explicit PostgreSQL timestamp cast; the final retention regression passed.
- UI full lint/unit/build: **38 files, 283 tests passed**, build **19.57s**, exit 0.
  After embedding exact-version review and improving the editor, final affected UI tests
  **4/4 passed**, lint clean, build **19.37s**, exit 0.
- Browser: **28/28 passed**. Final discovery-only rerun **1/1 in 7.3s** covers legal-off
  display, immutable diff, draft/replay, authenticated document download and exact-version
  review with a visibly pending replay (no fabricated DONE result).
- E2E: migrations up/down, Fleet enroll/connect/revoke, four-eyes and policy edit/deploy:
  `go test -race -count=1`, exit 0, **56.894s**.
- No benchmarks or shared lab/staging/production mutation. Existing tests remain enabled.

Evidence: [discovery and exact-version review](cp-c05-discovery.png).

## Bounds and self-review

- Batch: 100 observations / 256 KiB JSON; dedupe UUIDs are keyed before storage.
- Observations: 100,000 global, 10,000 per environment, 1,000 endpoints per scope;
  seven-day observations/batch receipts. Twenty immutable proposals per environment,
  1,000 global, thirty-day retention.
- OpenAPI API upload 128 KiB; parser ceiling 1 MiB, 20,000 YAML nodes, depth 32,
  1,000 paths / 2,000 operations. Stored document 1 MiB, change record 64 KiB.
- Reads/writes/downloads revalidate complete current environment authority. Machine
  ingestion additionally requires dedicated scope, trusted identity and legal gate.
- Errors omit raw inputs and private-key contents. Privacy/leak tests inspect actual
  PostgreSQL rows/audit; source values are never copied to external receivers.
- The control-plane-only digest reference is omitted from signed compiler inputs.
  Current engine/replay/approval behavior is preserved, including missing/revoked scopes.
- Scope: control plane, generated API/UI, related tests/docs; no new dependency.

Final full Go lint: **0 issues**, exit 0 (`c05-lint.log`). Final CLI/UI/browser/e2e
command exit codes were also checked, not inferred by filtering successful test lines.

## Ordered review PRs

- [discovery: anonymize a legally gated backend feed](https://github.com/hieunyit/strata/pull/376) · base `codex/cp-c04-docs`
- [discovery: bound OpenAPI indexing and immutable changes](https://github.com/hieunyit/strata/pull/377) · base `codex/cp-c05-normalize`
- [store: bound and deduplicate discovery observations](https://github.com/hieunyit/strata/pull/378) · base `codex/cp-c05-openapi-index`
- [store: version discovery baselines by environment](https://github.com/hieunyit/strata/pull/379) · base `codex/cp-c05-observations`
- [store: bind discovery proposals to one reviewed policy revision](https://github.com/hieunyit/strata/pull/380) · base `codex/cp-c05-documents`
- [discovery: verify privacy quotas and concurrent draft recovery](https://github.com/hieunyit/strata/pull/381) · base `codex/cp-c05-proposals`
- [api: scope dedicated discovery and documentation proposals](https://github.com/hieunyit/strata/pull/382) · base `codex/cp-c05-store-tests`
- [server: configure legal discovery gates and private retention](https://github.com/hieunyit/strata/pull/383) · base `codex/cp-c05-api`
- [api: define discovery provenance and immutable evidence](https://github.com/hieunyit/strata/pull/384) · base `codex/cp-c05-integration`
- [api: define legally gated discovery ingestion](https://github.com/hieunyit/strata/pull/385) · base `codex/cp-c05-metadata-contract`
- [api: define discovery draft and document download contracts](https://github.com/hieunyit/strata/pull/386) · base `codex/cp-c05-telemetry-contract`
- [ui: review discovered API changes beside policy replay](https://github.com/hieunyit/strata/pull/387) · base `codex/cp-c05-proposal-contract`
- [docs: record Compact C completion and discovery limits](https://github.com/hieunyit/strata/pull/388) · base `codex/cp-c05-ui`
