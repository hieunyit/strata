# M4 — idempotent rollout recovery

Branch `codex/m4-staging-rollout-recovery`, based on PR #192.

`LatestStagingAction` recovers the latest recorded bundle's durable action; superseded intents cannot win over a new human bundle. `StartStagingRollout` creates the rollout, links its ID and updates desired node versions in one PostgreSQL transaction. Concurrent replicas and a restart after commit reuse that rollout. Retrying returns unacknowledged nodes for another notification, including after a lost first notice. Existing agents deduplicate pending/active version offers.

The automatic path refuses empty/invalid fleets, invalid wave plans, revoked nodes, a changed latest bundle and another running/paused/failed rollout. It never unpauses a human pause, retries a failed rollout, recreates an abort or supersedes another rollout. Ordinary rollout behavior is retained through a shared transaction helper and short record lock. `Fleet.Rollouts.StartStaging` uses this path and the existing presence channel; it does not call the ordinary create/supersede operation.

New real-PostgreSQL race tests prove: commit-before-publish recovery, audit rollback, two replica callers producing one rollout, durable desired version, repeated publication through Fleet's real presence channel, suppression of notices after ACTIVE ACK, preservation of a human pause, newer-bundle fencing and refusal to claim an empty fleet or abort an in-flight rollout. These tests simulate status ACK through Store; they do not run an agent/NGINX activation chain.

Evidence: [output](evidence/m4-staging-rollout-recovery/checks.txt). Full `go test -race ./store ./fleet -count=1` passes (store 14.379 s, Fleet 29.317 s); scoped lint reports 0 issues. The first compilation of the new test caught a local variable declaration error, fixed before execution; an intermediate lint run overlapped adding the Fleet test import and reported a typecheck error, while the final run on the completed source is clean; no existing assertion/test was removed.

Self-review: context reaches all database I/O; ledger/rollout/desired/audit changes are atomic; maps/waves/nodes are bounded; no event snippets, credentials, dependencies or public endpoint; changes limited to rollout/storage/Fleet and related tests/docs. Remaining M4: source/approval-bound writer, worker/notification wiring and real automatic activation under five minutes. This component does not yet run automatically.
