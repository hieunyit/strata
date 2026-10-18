# M4 — visible reviewer notifications

Branch `codex/m4-reviewer-notices-ui`, based on PR #200.

The header now surfaces durable automatic-staging notices to approver/admin. It polls the generated-OpenAPI-typed client every 15 seconds when visible, without overlapping requests, and aborts on unmount. Reviewers can page history and open the affected rule/policy's events. Decimal-string evidence stays exact. Pending/paused/failed/completed rollout labels describe publication history; the panel explicitly avoids claiming current node protection. It never edits policy, approvals or enforcement.

Unread state is a per-user browser preference, labeled as such. Unavailable/malformed responses show an unavailable channel instead of an empty healthy history or raw backend errors. Escape/outside close, keyboard focus return and responsive panel placement are handled. All added copy has English/Vietnamese translations. Viewer/operator do not mount or query the notification UI; the API separately enforces its permission.

Validation: full UI lint, **99 tests in 16 files**, build **16.40 s**. Seven new cases cover role gating, exact UInt64 text, history/cursor, browser/user read state, unavailable/malformed data, a blocked in-flight request/no overlap, cleanup and Vietnamese text. Initial Vitest cases passed but the old root-owned result cache raised EACCES; the final run disables the optional cache and uses a private build output. No assertions/tests were disabled. [Output](evidence/m4-reviewer-notices-ui/checks.txt).

A companion native Chromium/private PostgreSQL/local-auth test has also passed and produced desktop English/Vietnamese/mobile screenshots; its fixture, browser test and images are published separately so each change remains reviewable. It exercises actual HTTP authentication/authorization, not mocked API responses. That browser fixture reads seeded historical metadata; it is not the final agent/NGINX activation proof.

Self-review: bounded one-page state, no background overlap, abortable I/O, read-only API/browser preferences, no secrets/PII/dependencies; UI and related tests/docs only. Remaining M4 is the actual full FP-to-node activation deadline proof; no main merge or production access.
