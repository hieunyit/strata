# Machine credential branch review — incremental integration

Selected from the W15–W20 branch stack; the complete stack remains unmerged. This first change contains only authentication primitives and RBAC. PostgreSQL persistence, atomic audit/idempotency, management routes, generated contract and UI are separate follow-ups; no management route or machine authenticator is enabled by this foundation alone.

- Machine credentials require known, explicit nonempty scopes and positive TTL at most 365 days. Authentication rejects legacy empty scopes, absent roles, expired/revoked credentials and failed usage writes.
- Principal permission is the intersection of roles and any explicit scope ceiling. Nil scopes retain session RBAC; empty explicit scopes, wildcard scopes and scopes without a role grant no permissions. Unknown permissions remain denied.
- Keep bearer credentials in Authorization headers; URL query authentication from the branch is rejected for GET and HEAD too. Prefix dispatch is optional until a durable store is wired.
- Usage I/O stays within a bounded request context. Token generation and authentication clone privilege slices. SHA-256 hashes identify 192-bit random secrets; plaintext is not part of token JSON metadata.
- The old runtime RAM store is not selected. A single-pair fixture exists only in _test.go.

Validation on this exact tree: full auth tests with -race PASS, auth lint 0 issues. All control-plane packages compiled with go test ./... -run '^$' before the final permission simplification; this compile check is not a full-package test claim. Empty/wildcard/roleless scope tests fail before the final fix and pass afterward. Logs are under evidence/branch-consolidation. Existing auth role/session/OIDC tests also pass. No hosted CI or operational Gate acceptance claimed.

The branch stack's RAM writes/ignored audit, duration overflow and query-token path were reproduced separately; durable API and real-PG tests pass in the isolated feature tree, but are not included or declared active by this first change. Geo/bot, hourly aggregate and rate/challenge defects remain separate review work. Preserve the owner's existing body/rate saturation/M4 policy decisions.
