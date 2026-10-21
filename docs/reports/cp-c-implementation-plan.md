# Compact C · Implementation plan

PO request: merge the complete B stack, then implement Compact C. All PRs #296–#320
are merged into main, ending at `ccf04bf7eaefb26ca969cd12ac33d917448e13bf`.
Its tree exactly matches the locally tested B tip. PostgreSQL/ClickHouse and local-auth
defaults remain; B03 remains excluded. Implement sequentially C03, C01, C02, C04, C05,
with small dependent PRs and no new external dependency planned.

## C03 · Privacy and administrative security

- `localauth/`, migration 0035: encrypted pending/enabled TOTP seeds, monotonic used
  timestep, hashed one-use recovery codes, verified sessions and opaque session IDs.
  Password verification and MFA consumption precede session issuance; row locks prevent
  replay/concurrent use. Session authentication rechecks the enabled MFA state.
- Setup/config/main: a separate private 32-byte local-MFA key under `keys/`, included
  by the existing encrypted data-directory backup. Never derive it from the rotating
  bundle signer. Existing configuration can opt in; missing keys cannot bypass enabled MFA.
- Self-service `/v1/auth/mfa` and `/v1/auth/sessions`: password-confirmed setup/confirmation,
  disable/recovery rotation and own-session list/revoke. No M2M/OIDC impersonation of local
  identity. All writes audited without seeds, OTPs, recovery codes or session tokens.
- Shared Go privacy helpers in `agent/pkg/`, used before ingest/Lite persistence and replay
  collection, read/export paths and outbound copies. Reuse policy P-01 sensitive names and
  linear-time mask patterns; preserve request structure needed by replay and route scope.
- Reusable bounded HTTPS delivery with DNS/connect-time SSRF validation, no redirects,
  HMAC signatures and private endpoint allowlist only when explicitly configured. Durable
  audit export cursor/outbox, retry limits and no raw before/after payload by default.
- Generated OpenAPI client, Security page and login MFA input, English/Vietnamese strings.
- Verify RFC 4226/6238 vectors; wrong/reused/parallel OTP, recovery reuse, session revocation,
  concurrent enrollment/password reset, key absence/corruption, account throttling, machine
  credential denial and privacy injection/secret scans. Race tests use real PostgreSQL.

## C01 · Investigation

Persist scoped saved searches and opaque share IDs with access revalidation; extend event
annotations with assignee/status/retention. Group similar events within bounded queries.
Create policy drafts from stored event context using existing etag, request_id, replay and
four-eyes workflow; rate proposals remain measurement-only. Evidence exports run as bounded
durable operations, use a shared CSV injection guard and recheck permission on download.
Update Events/detail UI, OpenAPI and browser/security regressions.

## C02 · Rule and exception lifecycle

Extend rulecat with version/CVE/attack/lifecycle metadata, app usage and measured rule cost;
show pack differences/changelog. Expose bounded exception lifecycle inventory with app,
route/method/parameter/rule, owner/reason/expiry and approval evidence. Reject overly broad
exception drafts; verify runtime expiry, schedule expiry-driven rebuild work without
bypassing release review, and report expiry/unused signals with explicit source limits.
Reuse current compiler/rule lifecycle commands and existing exception workflow.

## C04 · Alerts and reports

Durable grouped incidents from Health/failed deploy/backup and exception signals, cooldown,
acknowledgment and bounded retry delivery through the C03 transport. No request/IP/snippet
payload by default. Persist schedules and reports per application, enforce scope on all
reads/writes/downloads, and expose alert/report UI. Use controllable clocks and fake HTTP
servers to test cooldown/retries/HMAC, DNS rebinding/redirects and leak prevention.

## C05 · Discovery

Use a dedicated opt-in telemetry contract, never violation events as full-traffic evidence.
Require legal approval configuration before ingestion; synthetic fixtures only until that
approval exists. Accept only backend 2xx observations, anonymize before persistence, bound
endpoint cardinality and require several independent sources. Compare normalized routes to
OpenAPI and produce proposals/diffs; conversion creates ordinary draft/replay/review work,
never automatically enables blocking. Keep telemetry collection disabled by default.

## Gates

Use CPUs 6–10 and isolated `strata-compact-c-*` databases; do not mutate the shared lab,
staging or production. Run targeted negative tests with each change, then full affected Go
race/lint, real PG/CH integration, UI lint/unit/build/browser and selected e2e. Check generated
contracts/protobuf if changed; shellcheck scripts. No benchmark. Record commands, exit status,
output, self-review and unverified operational limits in each task report before opening PRs.
