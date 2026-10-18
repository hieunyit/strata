# M4 — real automatic activation within five minutes

Branch `codex/m4-real-activation-chain`, based on PR #202. Local acceptance is now met; main has not received the stack and no staging/production environment was accessed.

The new e2e test runs real compiler/replay binaries, independent API approval, signed object storage, PostgreSQL, agent enrollment/mTLS, two NGINX workers, Unix datagram events and ClickHouse. Draft creation queues a real 4,300-sample replay: 716 newly blocked samples with the two-rule fixture. Deploy before approval is rejected. Source bundle 1 enforces 100 actual SQLi requests; exactly 100 deduplicated events must reach ClickHouse before five are reported FP through the authorized API. These are deliberate simulated FP classifications, not an accuracy claim.

| Native ASan/UBSan NGINX | Fifth FP response → real log-only HTTP | Full race-enabled e2e |
|---|---:|---:|
| 1.30.5 | **11.079373795 s** | 41.246 s |
| 1.31.6 | **11.906453312 s** | 41.134 s |

Both runs prove SQLi `403/block/STR` → `200/log/EVT` and actual origin response, XSS remains `403/block`, and mixed SQLi+XSS still blocks with rule 700012 and STR ID. The installed derived bundle verifies its signature. Its EVT reaches ClickHouse under bundle 2; reviewer GET returns the durable action, exact 100/5 evidence and completed rollout. The source bootstrap initially uses the legacy no-metrics delay before NGINX starts; after NGINX is running the test requires a nonempty metrics file and proves derived ACTIVE adds no missing-metrics fallback log. Derived ACK is not simulated.

[Results 1.30.5](evidence/m4-real-activation-chain/1.30.5/result.json), [results 1.31.6](evidence/m4-real-activation-chain/1.31.6/result.json), [commands/output](evidence/m4-real-activation-chain/checks.txt), [source hashes/scope](evidence/m4-real-activation-chain/metadata.json). Full e2e lint: 0 issues. No sanitizer reports; LSan is disabled for this HTTP fixture. Earlier full native 595-test suites cover memory/ABI checks separately. This finite two-rule/single-node test is not a production, large-cardinality or throughput SLO.

The checks caught three fixture mistakes before success: corpus parameter keys differed from the initial narrow selectors; the event socket directive requires `unix:`; and a new private ClickHouse server needs schema installation. Corrected fixtures, retaining all real replay/signature/approval/event/verdict assertions. The existing migration table inventory omitted tables from migrations 15–21; its exact expected list now includes all 25 tables, preserving self-approval rejection, double-up, complete rollback and reapply checks. Parent inventory fails; corrected inventory passes 8.056 s with race, lint clean. No tests disabled or weakened.

Self-review: private service ownership/loopback ports, cleanup and context; no production dependencies/new packages; no signing/session secrets in evidence; no changes to enforcement code or user-deferred body/rate policies. Reproduce `TestAutomaticStagingInRealNginx` with explicit compiler/replay/NGINX/module paths and a new evidence directory, dev Docker access and the repository's private Rust target. Optional paths absent means the native test skips, so CI absence is not presented as proof.

M4 implementation/notification and scoped local acceptance are complete in the review stack. Human review/merge, deployment, real-traffic calibration, high load/cardinality and later runtime/library attestation remain separate; M4 cannot be called deployed protection on main.
