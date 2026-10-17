# M4 — Immutable FP report provenance before automatic staging

Branch `codex/m4-fp-report-provenance`, base PR #179 (`3b78a27`). User decision: automatic staging is permitted only by an explicit opt-in in a policy that passed replay and four-eyes approval; default off. This PR provides evidence binding, not the automation itself.

The diagnostic FP snapshot can change when an annotation reason is edited. It previously had neither deployed bundle version nor the initial report time. Reusing those rows for automation could treat an old edit as a new spike, attribute a multi-rule event to every rule, or carry old FP reports into a new artifact.

Migration 0020 adds five nullable fields on the existing retained context row: initial report time, initial policy, decision time, rule IDs and UInt64 bundle version (PostgreSQL numeric). Only new annotations populate them, within the same annotation/audit/request-id transaction. Reason edits and retries preserve that original evidence. Legacy rows and edits after context retention are never promoted or backfilled. The existing diagnostic snapshot/count semantics remain.

`RuleFPReportCount` is a read-only, bounded query requiring exact policy and bundle, exactly one distinct matched rule, and both first-report and decision-time half-open windows (each at most 24 hours). Unknown bundle 0 is excluded by query validation. Nanosecond boundaries preserve PostgreSQL's microsecond grid. This count is evidence for a later evaluator; it does not authorize a policy change. The API derives bundle version from its event lookup; request JSON cannot supply internal context. Existing RBAC/etag/audit remain.

Validation:

```sh
# Dev image, own PostgreSQL; full suite on CPUs 6–13.
go test -race -count=1 ./...
golangci-lint run
```

Targeted real PostgreSQL: store 2.349 s, API 1.795 s. Full control plane: all packages passed, including API 8.979 s, Fleet 29.200 s, store 9.881 s; lint `0 issues.`. [Full output](evidence/m4-fp-report-provenance/full.txt), [targeted output](evidence/m4-fp-report-provenance/targeted.txt). Initial regression failed on the missing provenance column ([red output](evidence/m4-fp-report-provenance/red.txt)). An intermediate new test used an incorrect audit column name; corrected to the existing `after` column before final validation.

Tests cover migration up/down, no inferred legacy evidence, API source binding, UInt64 max, policy/bundle/rule/time mismatches, fractional boundaries, immutable first time despite upstream snapshot/reason change, retry idempotency, ambiguous/unknown reports, duplicate-ID normalization, audit rollback, retention/re-edit, invalid bounds and JSON privacy. Existing diagnostic tests and assertions are retained.

Self-review: errors propagate; bounded windows/rule lists; no PII or credentials added; no dependencies or existing public endpoint response changed; changes limited to control-plane persistence/API mapping, its tests and this evidence. No staging/production access, main merge or hosted CI wait.

Remaining M4: approved opt-in configuration, signed per-policy log-only runtime overlay, durable evaluation/outbox/audit notification, and lab proof of activation within five minutes. No automatic re-enforcement is authorized.
