# M4 — Explicit opt-in in the reviewed policy

Branch `codex/m4-approved-opt-in`, base PR #180 (`b065819`). Implements the user's decision: automatic reduction to staging may be delegated by an approved policy; default off.

Adds `PolicySpec.auto_staging` to the existing admin protobuf/REST contract and generated Go/OpenAPI/UI types. The internal spec validates an explicit allowlist (1–16 distinct nonzero IDs), a bounded window, minimum matched events/reports and a basis-point threshold. No thresholds or enablement are implied. A fully configured disabled object retains its parameters. Internal effective staged state is not an API input.

This metadata uses normal policy versions and the existing replay/four-eyes/deploy path. It is included in the complete replay input digest; snapshot tests mutate every field and prove the digest changes while captured inputs stay immutable. PostgreSQL tests prove a draft is not deployable, self-approval fails, an independent approval persists the exact delegation, and a newer unapproved edit does not replace the approved version. This test exercises the store approval gate; existing admin tests exercise the replay prerequisite. UI form/YAML saves preserve the config; the advanced approval diff exposes changes.

The [contract](../spec/rule-auto-staging.md) defines semantics and an illustrative, uncalibrated configuration. Activation must additionally verify existing managed-rule membership against approved compiler inputs. Numeric-ID validation alone grants no runtime authority.

Validation in isolated local fixtures:

- `buf lint` and `buf generate --template buf.gen.admin.yaml`: exit 0.
- `go test -race -count=1 ./admin ./policy`: admin **4.971 s**, policy **1.978 s**; scoped golangci-lint **0 issues**.
- Real PostgreSQL independent-approval regression: **1.596 s**; final digest regression suite: **1.385 s**.
- Node 24.21.0 generation/lint/build: pass; build **16.95 s**. Full UI: **15 files / 92 tests pass**. After adding opt-in to the form/YAML preservation fixture, lint and all **5** advanced-policy tests pass (**8.04 s**).

[Raw evidence](evidence/m4-approved-opt-in/ui.txt), [Go](evidence/m4-approved-opt-in/go.txt), [approval](evidence/m4-approved-opt-in/postgres-approval.txt), [digest](evidence/m4-approved-opt-in/digest.txt), [preservation](evidence/m4-approved-opt-in/ui-preserve.txt). Initial UI invocation lacked dependencies (exit 127); installing the lockfile in this worktree fixed the environment. Final UI logs include existing React act warnings; all tests pass.

Self-review: bounded metadata and explicit disabled default; errors propagate; no new dependencies/secrets; existing RBAC/audit/etag unchanged; only policy contract, mappings, tests and documentation touched; generated churn excluded from the roughly 400-line review budget. Hosted CI was not awaited, main was not merged and no staging/production was accessed.

Remaining: a bounded evaluator, durable authorized staging state/outbox, signed per-policy log-only runtime behavior, reviewer-visible audit/notification and activation-within-five-minutes proof. This component alone performs no automatic action and cannot restore enforcement.
