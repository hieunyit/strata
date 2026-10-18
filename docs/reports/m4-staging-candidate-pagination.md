# M4 — bounded durable FP candidate pagination

Branch `codex/m4-staging-candidate-pagination`, based on PR #196.

The periodic worker must avoid scanning ClickHouse once for every configured rule or repeatedly evaluating the same fixed top-N. `Store.StagingCandidates` prefilters immutable first single-rule FP reports for the exact bundle, policy, event/report windows and configured minimum count. It pages by `(policy_name, rule_id)`, with at most 64 rows and a five-second database deadline. Scope bounds mirror 4096 policies/16 IDs each, with duplicate rejection. Legacy, ambiguous, wrong-policy/bundle and out-of-window reports do not qualify. This query grants no staging authority; the writer must re-query fresh counts and all approvals.

`Service.Observe` adapts the existing scoped evaluator's counts/windows/errors to the writer, without treating its ThresholdMet boolean as authority. The service remains read-only; production worker wiring follows separately.

Tests on PostgreSQL verify exact counts despite retries, minimum counts, exclusions, exclusive bounds and traversal to a later policy, plus invalid/duplicate/oversized scope/page and canceled query. Adapter tests retain scope/counts and query errors. The first new fixture omitted the required subject on a legacy report; fixed the fixture and gave repeated creates the same request_id, without changing annotation validation or any existing test.

Evidence: [output](evidence/m4-staging-candidate-pagination/checks.txt). Full `go test -race ./store ./rulehealth -count=1` passes (16.760 s / 1.710 s); scoped lint: 0 issues. Self-review: bounded I/O/input, no silent truncation of query scope or count-as-approval; no PII/dependencies/public endpoints; only store/service and related tests/docs. M4 still lacks production worker/notification wiring and an actual automatic activation deadline proof.
