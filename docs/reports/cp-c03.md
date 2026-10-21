# CP-C03 · Privacy and administrative security

All B PRs #296–#320 were merged before C03; main `ccf04bf7eaefb26ca969cd12ac33d917448e13bf`
exactly matches the tested B tree. PostgreSQL/ClickHouse, local authentication default and
optional OIDC remain. Operator instructions: [account security](../runbook/account-security.md).

Delivered:

- Shared bounded P-01 Go filters before ingest/Lite persistence and replay collection, plus
  defensive read-time filtering. Ingest resolves the revision pinned in the event's bundle,
  not the newest draft. Failure does not ACK unfiltered events. Replay drops samples whose
  settings are unavailable; Lite fully masks unresolved payloads without relaxing signature
  checks. Its signed PRIVACY reader is tested against the real compiler. Support archives
  retain their stricter allowlist. No Rust/C, protobuf or bundle ABI change.
- Replay preserves duplicate JSON keys, exact numbers, unchanged scalar escaping, ordinary
  URI/query order/encoding and validated source pseudonyms. Form handling uses content type.
  Malformed JSON/headers are masked, replacement amplification is bounded, and retained
  post-redaction allocations count against the existing buffer quotas.
- Migration 0035: AES-GCM encrypted, session-bound/expiring TOTP enrollment, one-use timestep
  and hashed recovery codes, verified opaque sessions. Independent private key provisioned
  by init and preserved in encrypted backup. Atomic factor consumption/session issuance
  prevents concurrent reuse; enabling MFA revokes other sessions. Auth rechecks MFA state,
  wrong codes persist lockout, and the IP limiter cannot grow unbounded. Host-only audited
  recovery resets lost MFA. No machine/OIDC impersonation, seed/code/token audit or browser
  storage. Generated OpenAPI client and EN/VI Security/login/session UI are included.
- Migration 0036: an audit trigger atomically queues private external copies, avoiding
  commit-order cursor loss. Optional HTTPS transport verifies TLS, checks DNS at connect,
  dials checked IPs, rejects redirects/proxies/private ranges unless explicitly allowlisted,
  and signs timestamp/delivery-ID/body with HMAC. Copies omit raw subjects/resources/actors,
  before/after and request data. Queue cap 10,000; five attempts; persisted backoff/lease/drop
  counter. Saturation preserves local audit; disabling export terminates pending copies.
  Defaults send nothing. No external dependency was added.

Actual validation on CPUs 6–10 with isolated PostgreSQL 17.11 / ClickHouse 25.8.33:

```text
control-plane: go test -p 1 -race ./... → exit 0
  API 30.235s; cmd/server 101.793s; delivery 3.275s; store 36.557s; localauth 37.989s
agent: go test -p 1 -race ./... → exit 0; both Go linters → 0 issues.
UI lint/unit/build → exit 0; 34 files / 259 tests passed
Playwright → 22 passed (1.1m)
Selected e2e Fleet enrollment/connect/revoke, migrations, four-eyes, policy edit/deploy
  go test -race -count=1 ... → exit 0 (58.542s)
Real HTTP MFA login/revocation → race PASS 4.209s
Outbox retries/atomic rollback/disable/full-queue and receiver safety → race PASS 3.068s
Encrypted MFA key backup/restore + config → race PASS 104.082s / 1.365s
```

The new replay regression initially failed: map decoding lost a duplicate key and rounded
`900719925474099312345` (`c03-replay-structure-before.log`). A bounded token stream now
preserves scalar bytes. After correction: privacy/bundle/Lite race tests PASS
(4.190s/1.502s/1.584s); affected ingest/replay/API/policy race suites PASS
(36.018s/5.089s/29.972s/4.249s); both linters again `0 issues.`; real native compiler PRIVACY
reader test PASS 1.223s. Full suites preceded this final correction; affected suites were
rerun afterward. The migration inventory was updated, and no existing test was disabled.

Additional negatives cover RFC 4226/6238 vectors, missing/corrupt/swapped keys, expired or
stale enrollment, concurrent/reused OTP, consumed recovery codes, locked accounts, non-local
credentials, secret scans, malformed JSON, amplification, quota accounting, HMAC, rebinding
and redirects. Unresolved Lite metadata uses full masking, preserving its original watcher
signature/header contract; its old synthetic fixtures continue to pass.

Logs are retained in ignored `build/c03-*.log`: full-go, full-agent, privacy-final-complete,
structure-bounds-final, cp-lint-final-complete, agent-lint-final-complete,
native-privacy-final-complete, ui-full, playwright, selected-e2e, http-outbox and key-backup.
No shared-lab mutation, staging/production deployment, benchmark or external delivery.

Self-review: context-bounded I/O and cancelable workers; bounded inputs/parsers/cache/queue/
sessions/retries/allocations; transactional factor/authorization/audit; no raw secret export;
OpenAPI/design/runbook updated; lint and relevant gates above passed.

Limits: MFA is per local account; IdP MFA remains at the IdP. Keep the independent key with
the DB backup (custom keys outside the data directory need their own backup). Client IP
remains a dedicated authorized analytics field; identity/content follow P-01 with viewer
masking. Audit copies are forward-only, not historical backfill or tamper-proof storage.
Receivers must deduplicate retry IDs; exactly-once network delivery is not claimed. Queue
status is in PostgreSQL; the alert UI belongs to C04. No full live fault matrix is claimed.

Review/merge order (all open for review; no C merge is claimed):

- [#321](https://github.com/hieunyit/strata/pull/321): `codex/cp-c03-privacy-filter`; base `main`.
- [#322](https://github.com/hieunyit/strata/pull/322): `codex/cp-c03-privacy-manifest`; base `codex/cp-c03-privacy-filter`.
- [#323](https://github.com/hieunyit/strata/pull/323): `codex/cp-c03-privacy-sinks`; base `codex/cp-c03-privacy-manifest`.
- [#324](https://github.com/hieunyit/strata/pull/324): `codex/cp-c03-mfa-crypto`; base `codex/cp-c03-privacy-sinks`.
- [#325](https://github.com/hieunyit/strata/pull/325): `codex/cp-c03-mfa-sessions`; base `codex/cp-c03-mfa-crypto`.
- [#326](https://github.com/hieunyit/strata/pull/326): `codex/cp-c03-mfa-enrollment`; base `codex/cp-c03-mfa-sessions`.
- [#327](https://github.com/hieunyit/strata/pull/327): `codex/cp-c03-mfa-api`; base `codex/cp-c03-mfa-enrollment`.
- [#328](https://github.com/hieunyit/strata/pull/328): `codex/cp-c03-mfa-setup`; base `codex/cp-c03-mfa-api`.
- [#329](https://github.com/hieunyit/strata/pull/329): `codex/cp-c03-webhook`; base `codex/cp-c03-mfa-setup`.
- [#330](https://github.com/hieunyit/strata/pull/330): `codex/cp-c03-audit-outbox`; base `codex/cp-c03-webhook`.
- [#331](https://github.com/hieunyit/strata/pull/331): `codex/cp-c03-outbound-config`; base `codex/cp-c03-audit-outbox`.
- [#332](https://github.com/hieunyit/strata/pull/332): `codex/cp-c03-auth-contract`; base `codex/cp-c03-outbound-config`.
- [#333](https://github.com/hieunyit/strata/pull/333): `codex/cp-c03-security-ui`; base `codex/cp-c03-auth-contract`.
- [#334](https://github.com/hieunyit/strata/pull/334): `codex/cp-c03-replay-integrity`; base `codex/cp-c03-security-ui`.
- [#335](https://github.com/hieunyit/strata/pull/335): `codex/cp-c03-docs`; base `codex/cp-c03-replay-integrity`.
