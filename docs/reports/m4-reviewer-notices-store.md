# M4 — durable reviewer notice history

Branch `codex/m4-reviewer-notices-store`, based on PR #198.

Reviewer notices read the durable staging ledger, independent of audit log traffic. The ordered index (migration 0022) and `(created_at, id)` keyset retain stable pagination even when several actions share a timestamp. Counts and bundle/rollout versions are decimal strings so JavaScript cannot round UInt64 evidence. The read includes historical rollout state or PENDING when not linked; it makes no current runtime/ACTIVE claim. No acknowledgment or reset write is introduced.

Real PostgreSQL `-race` tests create two recorded derivations, pause the linked rollout, reconstruct a Store and page equal timestamps without duplicates/loss. UInt64 maximum roundtrips as an exact string; pending/paused states and no additional audit writes are asserted. Query cancellation, limits and paired cursor bounds are tested. Full store race suite: 16.752 s; scoped lint: 0 issues. [Output](evidence/m4-reviewer-notices-store/checks.txt).

Self-review: read-only, context with five-second I/O limit, at most 51 rows, indexed ordering, no PII/dependencies/test removals. Related store/schema/tests/docs only. The API and visible reviewer notification are separate follow-up components; M4 remains unfinished until those and the real activation chain are proven.
