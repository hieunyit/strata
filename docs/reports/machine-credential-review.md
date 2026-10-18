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


## Management API wired after #225

Contract merged in #225 as `980ff43529a639069c6a705b9ccd4ea810021fac`; temporary branch deleted with SHA guards. Totals are 129 remote / 128 local deletion actions, including integration branches.

The server wires its durable store and machine authenticator when PostgreSQL is configured. Management routes check admin permissions; writes require immutable command IDs and etags. Single-use plaintext responses carry Cache-Control: no-store, and identical issue retries return metadata with replayed=true and no secret. CORS preflight includes the two command headers for configured origins. TTL seconds are checked before duration multiplication; command/body/path strings are bounded and invalid UTF-8/NUL is rejected. Public errors omit database internals.

Full control-plane go test -race -count=1 ./... PASS with real PostgreSQL, followed by golangci-lint 0 issues. New real-PG API tests cover concurrent retry, rollback on failed audit, new server objects over persisted state, expired/revoked tokens, role refusal, an admin-role token restricted to events:read, missing/hostile input and secret-response cache control. Before the last input guard, an invalid UTF-8 header returned 404; the added negative test now passes with 400. Optional CH/native/browser fixtures need their own configuration and are not implied by this package run.

The web workflow is the next integration step. Action scopes are implemented here; connector-group scoped role bindings remain separate work. The weekly branch's Geo/bot/standalone/hourly changes and operational Gate claims remain under review.


## Web component foundation after #226

Management API merged as #226, main `33e61fe5b0203e250033f4071af49b495684eb14`; its branch was removed with SHA guards. Totals: 130 remote / 129 local deletion actions including integration branches.

The typed client uses the generated contract. The token dialog keeps one command through uncertain responses, pins account/token etags, validates the returned account/scopes/lifetime, ignores stale list results and serializes writes. It masks a new secret by default, offers explicit reveal/copy with error handling, traps keyboard focus, restores the trigger and supports Escape. EN/VI strings are included. A replay receipt explains that plaintext cannot be recovered and supports revoking that token.

Seven component regressions and eleven existing page tests PASS; TypeScript lint PASS. These include double-submit, uncertain retry, wrong-account receipt, pinned revoke, focus, stale reads and failed clipboard access. Management-page wiring and the standalone Chromium acceptance fixture are the next review steps; this component-only change does not expose a new page entry point. Final browser evidence will be recorded with that fixture.


## Management page wiring

The token client/dialog foundation merged in #227. The Users page now separates local accounts from service accounts. Admins can create an account with explicit roles, issue scoped credentials through the dialog, revoke individual tokens and delete accounts with etag/idempotency guards. Uncertain commands retain their original inputs; read versions suppress late results. Closing the dialog refreshes active counts without removing the focused trigger. The component is keyed to account ID and hidden when admin rights disappear.

The mobile page keeps account identity and actions visible, with supplementary metadata in desktop columns. The subtitle describes automation tokens and uses EN/VI resources. Full UI suite before the three additional component tests: 148 PASS; final affected suite: 18 PASS (7 component, 11 page); TypeScript lint and the mobile build PASS. Actual Chromium/PG acceptance has run successfully and will be committed with its fixture/evidence in the next small review. Source-page cleanup keeps both local-account behavior and machine commands in their respective API workflows. Component branch cleanup totals: 131 remote / 130 local actions including integration branches.


## Independent browser acceptance after #228

The management page merged in #228 as `f568e45b7780104a865fbce78a8716a17406183f`; its branch was deleted with SHA guards. Totals: 132 remote / 131 local deletion actions including integration branches.

The new opt-in fixture runs built UI/Chromium against real local-password authentication, the HTTP API and an isolated migrated PostgreSQL database. It drops the first token response after the server commits, retries the identical command and verifies metadata-only replay, revokes that orphan credential, issues another token, checks masked one-time display, proves events:read succeeds while machine writes are 403, then revokes and confirms 401. It also verifies viewer/approver refusal, a 390 px VI dialog, focus restoration and zero credentials in URL query parameters. PostgreSQL has exactly six machine audits/receipts and zero remaining accounts/tokens after deletion. The request credentials never enter saved results, trace, video or screenshots.

Final Chromium PASS: 6.7 s (runner 9.2 s); entire Go -race fixture PASS 16.509 s; API lint 0 issues. UI full suite PASS: 25 files / 151 tests (32.50 s), TypeScript lint PASS; mobile build PASS. Screenshot was visually inspected: account identity/actions fit 390 px, secrets absent. Source/build hashes and sanitized outcomes are in browser-machine-3-postgres-result.json.gz and browser-machine-3-browser-result.json.gz. The first browser scenario already passed, but its Go wrapper failed on an incorrect evidence hash path; the fixture path was corrected and the complete wrapper rerun successfully. The first failed wrapper log is retained, not represented as a pass.

This accepts the admin-console credential workflow on a local fixture. Group-scoped role binding, deployment/NGINX, real traffic/soak, other weekly features and operational Gates retain their separate acceptance requirements.
