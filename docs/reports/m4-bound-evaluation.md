# M4 — Bundle-bound threshold evaluation

Branch `codex/m4-bound-evaluation`, base PR #181 (`f39b979`). This read-only component evaluates the explicitly configured threshold; it grants no approval or deployment authority and does not run an automatic worker.

`ClickHouseStore.RuleMatchCount` uses FINAL and exact policy + bundle + Rule ID + half-open decision window. It preserves nanosecond query boundaries and caps execution at five seconds and memory at 256 MiB. The denominator is matched stored security events, not total requests.

`rulehealth.Service.Evaluate` reads that denominator and immutable initial, single-rule FP reports for the same bundle/policy/window. Off, shadow and non-allowlisted rules perform no I/O. Invalid input, missing stores, cancellation, query failures, insufficient counts and FP counts exceeding matched events never pass. Exact 128-bit products avoid UInt64 overflow and floating-point rounding near the configured basis-point threshold. Evaluation shares the existing health API's four query slots and one five-second context for both databases; there are no state writes, callbacks or unbounded counters.

Validation:

```sh
go test -race -count=1 ./rulehealth ./ingest
golangci-lint run ./rulehealth/... ./ingest/... ./api/...
TEST_CPUS=6-10 tests/e2e/rule-health.sh
```

Unit/area tests: rulehealth **1.102 s**, ingest **5.561 s**, lint **0 issues** ([output](evidence/m4-bound-evaluation/unit.txt)). Real isolated PostgreSQL 17.11 + ClickHouse 25.8.33: `TestRuleHealthDurableSources` **0.99 s**, package **2.135 s**, race enabled ([output](evidence/m4-bound-evaluation/real-stores.txt)). Two unmerged event retry rows count as one match/report for bundle 7; bundle 8 has exactly zero of both. A fractional lower boundary excludes the event. Existing health API persistence, privacy, audit and raw-row assertions remain.

Tests also cover threshold equality/below, minimum counts, inconsistent snapshots, UInt64 maximum and the two sides of 5% at that scale, exact scope/deadline propagation, all off/no-I/O paths, missing/error stores, cancellation and four simultaneous evaluations blocking a fifth evaluation and health API query. Cancellation releases every waiting test goroutine.

Self-review: errors propagate, query bounds hold, no PII/secrets/dependencies/interfaces added, only control-plane evaluation/query code and related tests/evidence changed. No hosted CI wait, main merge or staging/production access.

Remaining authority checks belong to the forthcoming writer: active approved policy/version, approved input digest, managed-rule membership and durable idempotency. This is a configured threshold gate, not a calibrated statistical spike detector. Durable staging state, signed log-only runtime overlay, reviewer audit/notification and the under-five-minute activation proof are still pending. No automatic re-enforcement.
