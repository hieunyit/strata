# Compact B · Implementation and review index

Requested scope: **B01, B02, B04, B05**; **B03 excluded**. Keep PostgreSQL and ClickHouse.
Local authentication remains the default; Keycloak/OIDC is an optional integration.

PR [#295](https://github.com/hieunyit/strata/pull/295) was merged as explicitly requested:
`7cdb41fb67d99889b0edd1f3adbc2426063efd79`. It closes the A review corrections, including
lease takeover and render-before-reset transactional restore. The PRs below are open for
review; they have not been merged or deployed to staging/production.

## Review and merge order

These are dependent PRs, split to keep individual reviews around 400 non-generated lines.
Review each diff against its listed base, and merge in order. Preserve merge history or
rebase/retarget descendants if using squash; do not merge a child before its dependencies.
The final documentation branch contains the complete implementation for integrated review.

| Order | PR | Contents |
| --- | --- | --- |
| 1 | [#296](https://github.com/hieunyit/strata/pull/296) | B02 Fleet inventory and drift |
| 2 | [#297](https://github.com/hieunyit/strata/pull/297) | B02 verified module manifest |
| 3 | [#298](https://github.com/hieunyit/strata/pull/298) | B02 capability compatibility and UI |
| 4 | [#299](https://github.com/hieunyit/strata/pull/299) | B01 scoped authority resolution |
| 5 | [#300](https://github.com/hieunyit/strata/pull/300) | B01 application/environment model |
| 6 | [#301](https://github.com/hieunyit/strata/pull/301) | B01 durable role bindings |
| 7 | [#302](https://github.com/hieunyit/strata/pull/302) | B01 scoped event/statistics access |
| 8 | [#303](https://github.com/hieunyit/strata/pull/303) | B01 API and request authorization |
| 9 | [#304](https://github.com/hieunyit/strata/pull/304) | B01 OpenAPI/client |
| 10 | [#305](https://github.com/hieunyit/strata/pull/305) | B01 application UI and report |
| 11 | [#306](https://github.com/hieunyit/strata/pull/306) | B04 signed immutable artifact snapshots |
| 12 | [#307](https://github.com/hieunyit/strata/pull/307) | B04 release records and atomic receipt |
| 13 | [#308](https://github.com/hieunyit/strata/pull/308) | B04 configurable pinned canary settings |
| 14 | [#309](https://github.com/hieunyit/strata/pull/309) | B04 prepare/review/deploy/rollback workflow |
| 15 | [#310](https://github.com/hieunyit/strata/pull/310) | B04 OpenAPI/client |
| 16 | [#311](https://github.com/hieunyit/strata/pull/311) | B04 release UI and report |
| 17 | [#312](https://github.com/hieunyit/strata/pull/312) | Integration startup/authority/publication corrections |
| 18 | [#313](https://github.com/hieunyit/strata/pull/313) | B05 measured worker/spool heartbeat telemetry |
| 19 | [#314](https://github.com/hieunyit/strata/pull/314) | B05 bounded observations/read-only CH probe |
| 20 | [#315](https://github.com/hieunyit/strata/pull/315) | B05 freshness/scoped health collector |
| 21 | [#316](https://github.com/hieunyit/strata/pull/316) | B05 private allowlisted support archive |
| 22 | [#317](https://github.com/hieunyit/strata/pull/317) | B05 API and read-only doctor |
| 23 | [#318](https://github.com/hieunyit/strata/pull/318) | B05 OpenAPI/client |
| 24 | [#319](https://github.com/hieunyit/strata/pull/319) | B05 Health UI |

The last `codex/cp-b05-docs` PR adds this index, the operator runbook and acceptance report.
Schema migrations are sequential: 0030 inventory, 0031 requirements, 0032 application scope,
0033 releases, 0034 health. Protobuf additions are optional; the engine/bundle ABI is unchanged.

## Behavior and boundaries

B02 prevents incompatible nodes from receiving a new bundle, including late enrollments.
B01 stores application/environment ownership and resolves durable scoped role bindings on
each request. Revocation does not restore stale token authority; SSE rechecks access.
Shared-policy edits require authority over every referencing environment.

B04 pins artifact sections, inputs, replay evidence, baseline and canary configuration for
independent approval. Deployment and receipt are atomic. Rollback republishes historical
signed sections under a higher version, surviving changed rules/compiler and signing-key
rotation. Publication is installation-wide and requires authority over every included policy,
even unchanged versions; authoring/replay/review remain scoped.

B05 distinguishes unknown/stale from measured zero and shows source freshness/next actions.
Doctor is read-only; private support exports contain only allowlisted diagnostic data.
Remote database disks and offline live-process queues remain unknown. No raw logs/request
data are copied. Health counters do not prove every worker has activated a module.

## Evidence and operational limits

Per-area evidence and self-review: [B02](cp-b02.md), [B01](cp-b01.md), [B04](cp-b04.md),
[integration fixes](cp-b-integration-fixes.md), [B05](cp-b05.md).
Operator instructions: [doctor](../runbook/doctor.md).

The final integrated control-plane race rerun after all corrections exited 0 (API 26.142s,
cmd/server 97.114s, Fleet 35.774s, health 1.866s, policy 3.498s, store 33.948s).
The final agent race rerun and both linters also passed. Outputs remain in the review
worktree's ignored `build/` directory; the B05 report lists filenames.

All builds/tests used CPUs 6–10 and isolated PostgreSQL/ClickHouse. Both Go modules passed
their full race suites and lint (`0 issues.`). UI lint/build passed; 255 unit tests and
21 browser tests passed. Three final Health/Applications/Releases browser regressions passed.
Selected e2e covered real-agent enrollment/connect/revoke, persisted spool telemetry,
migration up/down, four-eyes and policy edit/deploy. Native B04 tests used the real compiler
and verified section identity/signatures across rollback/key rotation; synthetic completed
replay records test evidence binding, not detector quality.

No benchmark, full live fault matrix, staging/production rollout or shared-lab mutation is
claimed. Release artifacts are retained with a 1,000-record limit and space checks; no
automatic orphan artifact collector was added. B03 fleet configuration deployment and C03
cross-product privacy work are outside this request.
