# Audit snapshot after branch consolidation

Scope: reviewed main `0a5100c` from #220. The earlier report from `298eee70` lacked evidence for several broad guarantees and used stale configuration details. This replacement records specific guarantees and their limits.

| Area | Evidence available | Limit / remaining work |
|---|---|---|
| FFI/native lifecycle | Rebuilt NGINX 1.30.5 and 1.31.6, 595 TAP tests each, no ASan/UBSan report in consolidation | HTTP/3 was skipped; LSan disabled; finite tests do not prove absence of all memory defects |
| Detector/optimizer equivalence | 11,590 requests, reference/fast/block engines, zero action/score/rule-set differences | Finite corpus, not proof of coverage for every application |
| Body budget | Repeated-JSON optimization and measured completeness | Large bodies still reach PARTIAL at 10 ms; keep #28 open and preserve the owner's policy decision |
| Policy review/deploy | Prepared-input hashes, approval binding, transaction-checked expected_replay_id and deploy gate | Does not attest runtime image/shared libraries or grant a production Gate |
| Exceptions | PostgreSQL draft/audit/idempotency; signed exact route/field/TTL runtime; replay/four-eyes flow | Generic override resolver from the old W14 branch is not an implemented runtime feature |
| Event classification | Durable annotation and audit; generated UI client; real Chromium/auth/API/PG acceptance, direct viewer/approver writes refused | Event data in that browser fixture is seeded; deployment is a different test boundary |
| Ingest recovery | Durable PG watermark and CH FINAL; real CP SIGKILL between commits with native events | Full HA/load/operational game day remains open |
| Privacy | Mask sensitive request fields before truncation, API role-based redaction | Not a compliance certification or guarantee that arbitrary user content has no PII |
| Signed bundles | Integrity verification at publication/agent/worker; bad artifact retains last-known-good in tested chain | Trust in signer/key management remains necessary; signatures do not make rule semantics safe |
| Rule candidates | Header candidates retained in draft #221, schema and match/no_match checks | S content review, application context and cost/coverage assessment still required |
| Branch-only features | Manifest and concrete defects recorded in consolidation report | Geo/bot section collisions, fake latency, RAM credentials and retry-counting aggregates are not accepted merely because a weekly report says Done |

Raw logs, source SHAs and exact fixture boundaries: [consolidation report](../reports/branch-consolidation.md), [tracker](../reports/remediation-tracker.md). No hosted CI or staging/production acceptance is claimed. No fourteen-day enforce period or production FP percentage can be inferred from these local tests.
