# CP-B04 · Immutable releases

Release preparation pins the signed artifact containing every policy/rule/schema section,
compiler/rule/input digests, exact approved replay operation IDs, baseline and canary
thresholds. It does not record a deployed bundle or change node desired versions. The
existing policy validation/replay/four-eyes gates run before preparation. Global reviewers
approve the exact hash and replay ID map, with etag and independent immutable subject.
Global release management is intentional: the signed bundle covers the whole installation;
application-scoped users retain policy review rights but cannot read or publish global
release snapshots.

Deployment reassigns a strictly newer header version/time, clears the rollback flag, verifies
and signs, then atomically commits bundle + rollout + desired versions + release receipt.
Capability failure rolls everything back. Repeating deployment returns its existing receipt.
A changed baseline, historical rollback or differing replay baseline requires an explicit
acknowledgment of the *current* baseline; the UI pins the checkbox to that version. Changing
canary configuration requires preparing/reviewing a new release. Canary threshold settings
are available in YAML/flags and validated for finite bounded values; comparison method and
source-cap protections remain intact.

Rollback prepares a new release from the historical artifact, including old rule and schema
sections. It requires independent approval and an explicit historical-evidence warning.
Current compiler/rule files are not consulted to rebuild it. Signing key rotation is supported
by retaining the artifact's verification key and signing the new version with the current key.
The UI links policy editing/replay/review, immutable release evidence, canary configuration,
per-node rollout status and rollback preparation. Block-rate increases are not labeled FP.
Long preparation/publication requests receive the existing extended deploy timeout.

Validation on CPUs 6–10, isolated PostgreSQL 17.11 / ClickHouse 25.8.33:

```text
control-plane: go test -p 1 -race ./... → exit 0
api 24.664s; store 34.057s; all packages passed
golangci-lint run ./... → 0 issues.
UI lint/build → exit 0; 32 files / 252 tests passed
Playwright → 20 passed (1.0m)
e2e migration / four eyes / policy edit+deploy → 27.722s, exit 0
```

Native targeted tests with the existing workspace `target/release/strata-compile`:

```text
TestNativeReleaseReviewDeployAndRollback PASS (3.39s)
TestReleaseRollbackKeepsNativeSectionsAcrossKeyRotation PASS (1.38s)
TestReleaseReviewAndAtomicRolloutInPostgres PASS (0.75s)
```

The native flow uses synthetic completed replay evidence to test binding, not detector
quality. It executes the real compiler, verifies signatures and compares all section bytes.
Tests break the live compiler/rules and rotate the signing seed before rollback; artifacts
still verify, content stays identical and versions increase. Additional tests cover wrong
review IDs/hash, self approval, stale etag/baseline, capability rejection, duplicate requests,
API scope denial and preparation outliving HTTP timeouts (4.082s with race).

An initial new API fixture used the wrong test subject prefix; fixed the fixture and reran.
Two overlapping full test invocations shared a scratch database and interfered with schema
reset tests; both were discarded. The final full run above used its own `b04_suite` database.
The migration inventory initially placed the new table after replay alphabetically; corrected
its expected order and reran all three selected e2e tests. No existing test was disabled.

Limits: releases are retained (maximum 1000); artifact space checks protect the filesystem.
Snapshot artifacts are under `releases/`, included by filesystem backup and not pruned with
ordinary bundles. Interrupted preparations may leave an unreferenced private artifact;
there is no automatic release garbage collector in this task. No benchmark, staging,
production or shared lab mutation. Native fixtures do not establish live canary/FP quality.

Self-review: bounded inputs/retention, replay and four-eyes enforced on server, all writes
atomic/audited, no secret exposed, no bundle-format/engine change, local checks above.

Final integration exposes actionable global capability/replay preconditions while preventing unrelated node metadata disclosure to scoped policy callers. See `cp-b-integration-fixes.md`.
