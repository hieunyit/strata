# Machine credential branch review — incremental integration

Selected from the W15–W20 branch stack; the complete stack remains unmerged. This first change contains only authentication primitives and RBAC. PostgreSQL persistence, atomic audit/idempotency, management routes, generated contract and UI are separate follow-ups; no management route or machine authenticator is enabled by this foundation alone.

- Machine credentials require known, explicit nonempty scopes and positive TTL at most 365 days. Authentication rejects legacy empty scopes, absent roles, expired/revoked credentials and failed usage writes.
- Principal permission is the intersection of roles and any explicit scope ceiling. Nil scopes retain session RBAC; empty explicit scopes, wildcard scopes and scopes without a role grant no permissions. Unknown permissions remain denied.
- Keep bearer credentials in Authorization headers; URL query authentication from the branch is rejected for GET and HEAD too. Prefix dispatch is optional until a durable store is wired.
- Usage I/O stays within a bounded request context. Token generation and authentication clone privilege slices. SHA-256 hashes identify 192-bit random secrets; plaintext is not part of token JSON metadata.
- The old runtime RAM store is not selected. A single-pair fixture exists only in _test.go.

Validation on this exact tree: full auth tests with -race PASS, auth lint 0 issues. All control-plane packages compiled with go test ./... -run '^$' before the final permission simplification; this compile check is not a full-package test claim. Empty/wildcard/roleless scope tests fail before the final fix and pass afterward. Logs are under evidence/branch-consolidation. Existing auth role/session/OIDC tests also pass. No hosted CI or operational Gate acceptance claimed.

The branch stack's RAM writes/ignored audit, duration overflow and query-token path were reproduced separately; durable API and real-PG tests pass in the isolated feature tree, but are not included or declared active by this first change. Geo/bot, hourly aggregate and rate/challenge defects remain separate review work. Preserve the owner's existing body/rate saturation/M4 policy decisions.


## Durable store selected after #223

Authentication foundation merged in #223, main `e3f65746a2df465e79b8f3fd1b4fd903483d6170`. Its integration branch was deleted with SHA guards; cleanup totals are now 127 remote / 126 local deletion actions (including temporary integration branches).

Migration 0023 adds machine accounts, independently revocable tokens and actor-scoped immutable command receipts. Legacy service_accounts rows remain intact and are not activated implicitly. Management mutations authorize the principal, bound I/O, serialize request retries, check etags and commit credential/audit/receipt in one transaction. Token issue checks the account role ceiling; account creation records the authenticated subject. Reads are bounded to 1,001 rows and report overflow instead of silently truncating. Large account/token listings need future pagination.

Plaintext secrets never enter token metadata, audit or receipts. A repeated token issue returns the original metadata, and the API follow-up must omit plaintext on retry. Machine audit state includes immutable actor_subject because the legacy audit table stores only display actor. Revoke audit has both before and after; delete invalidates child tokens in the same transaction.

On the selected main-based tree, two real-PostgreSQL store tests PASS with -race (2.115 s): persisted credentials work through new store objects, retries do not duplicate records, scope/expiry validation rejects invalid credentials, revocation takes effect, and a synthetic audit failure rolls back account and receipt before a successful retry. Migration unit tests PASS (cached); store/db lint 0 issues. Raw output is in machine-store-boundary.log.gz. These are not process-restart or production drills. API management routes and UI are still a separate follow-up at this checkpoint.


## Contract before management wiring

Store merged in #224 as main `7fb0ad625397a660a9ed3b64c6781a03b5b1208b`; its temporary branch was deleted with SHA guards. Totals: 128 remote / 127 local deletion actions, including temporary integration branches.

The optional management contract now specifies etags, immutable command IDs, known bounded scopes, one-time plaintext and retry receipts without plaintext. It uses shared parameters/responses and generated TypeScript types. Management routes can still be unavailable until the separate handler/wiring change; this contract does not declare them active. Validation: no duplicate YAML keys, 154 resolvable refs and 24 unique operation IDs; four management paths. openapi-typescript generation and UI TypeScript lint PASS. No policy/proto/FFI or enforcement behavior change.
