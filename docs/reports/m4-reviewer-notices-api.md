# M4 — reviewer notice read API

Branch `codex/m4-reviewer-notices-api`, based on PR #199.

`GET /v1/rules/staging-actions` exposes durable notice history to approver/admin (`policies:approve`). It returns exact decimal-string evidence and historical rollout state, not current ACTIVE protection. Keyset cursor/limit are validated before I/O; pages have at most 50 rows, queries at most 1024 bytes, cursor at most 512 bytes. GET only, no-store, generic 503 on storage errors. No acknowledgment/reset/action endpoint is added. Main wires the optional store only when PostgreSQL exists.

OpenAPI and generated TypeScript types include the contract. Tests enforce 401/403/allowed-role behavior, exact pagination/cursor propagation, UInt64 maximum serialization, missing service, bad/repeated/unknown inputs, method rejection and error privacy. A real PostgreSQL API read fixture survives a fresh server/store and changes no audit rows; it seeds historical metadata, not an activation/approval proof. Writer and activation paths have separate tests.

Evidence: [output](evidence/m4-reviewer-notices-api/checks.txt). API/server race suites: 8.667 s / 1.116 s; lint: 0 issues; API type generation succeeds. The first UI build passed TypeScript then hit EACCES on an older root-owned dist directory. Rebuilding into this task's private build output passes in 16.73 s and avoids modifying that artifact.

Self-review: authenticated exact route, bounded read-only I/O, no secrets/snippets/IPs in notices, no dependency/tests disabled; API/store wiring/OpenAPI/generated types and related tests/docs only. Visible reviewer notification and real automatic node activation deadline proof remain unfinished.
