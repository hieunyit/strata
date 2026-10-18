# M4 — active source and approved replay ancestry

Branch `codex/m4-staging-source-guards`, based on PR #193.

Automation must start from what the fleet actually runs, not the newest draft/approval or an uploaded bundle. `BundlePolicies` selects the exact immutable versions listed in a recorded bundle. `StagingSourceReady` requires the latest bundle, a completed latest rollout, at least one enrolled node and ACTIVE/desired state for every enrolled node. Empty DONE rollouts, a mere ACK before rollout completion, a VERIFIED state or superseded bundle do not qualify.

`StagingRoot` follows only durable additive actions, bounded by the signed codec's 4096-entry maximum; an ordinary deployment starts a new root. `replay.Gate.CheckStaging` verifies every root version's approval-bound completed replay, its exact original input digest, samples and original baseline artifact/version. It accepts an additive descendant through this recorded ancestry while the ordinary `Gate.Check` still rejects reuse against a changed current baseline. No fake approval, modified spec or relaxed ordinary deploy gate.

Validation: [output](evidence/m4-staging-source-guards/checks.txt). PostgreSQL test checks actual stored ACK/desired/rollout states, source selection despite a new draft, additive root recovery and normal-bundle root reset. Gate tests exercise valid ancestry, missing/unapproved/pending/wrong-operation or version, changed root inputs/original baseline/SHA, zero samples, stale/forged current source and altered policy versions. These are storage/proof guards, not an agent activation or automatic writer test. Full `go test -race ./store ./replay -count=1` passes (store 15.147 s, replay 4.841 s); scoped lint: 0 issues. Existing ordinary gate regressions remain unchanged and pass.

Self-review: all I/O uses context; ancestry and policy count are bounded; lookup errors/missing history fail closed; no secrets/PII/dependencies/public API changes; only store/replay guards and tests/docs. No automation is enabled by this PR. Remaining M4: wire the restricted additive writer, worker/notifications and prove the under-five-minute activation chain.
