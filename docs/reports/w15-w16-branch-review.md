# Review W15–W16 branch — source 0dce6de

Scope: review/repair/consolidation of the existing branch, authorized by the owner; no rollout or Gate acceptance. Work stays on this source family until its content has a documented disposition. The final disposition covers all 28 source-changed files in [the manifest](evidence/w15-w16-retirement/source-disposition.json); source retirement acknowledges reviewed replacements, not completion of every weekly acceptance criterion.

| Source area | Disposition |
| --- | --- |
| Machine credentials and Users UI | Replaced by reviewed main #223–#229: durable transactions/audit/idempotency, bounded scopes/expiry, UI/browser acceptance. Do not import RAM credentials or query tokens. |
| Audit query | Selected and repaired in #236–#238: DB filters before LIMIT, explicit time bounds, literal substring matching, immutable subject persistence, bounded request/query, generic backend errors and has_more. The typed UI now queries these stored-history filters; browser fixture/evidence is retained separately. |
| Nine-block policy panel | Source controls for templates/content profiles/violations/signature sets only change local React state; they are not serialized into the saved policy. Exclude those fake controls and retain main's preserved advanced policy data. Full nine-block form/runtime behavior is not claimed delivered. |
| GeoIP ingestion/schema | Real MMDB loader, safe cache, authoritative enrichment, DB migration/projections and optional startup configuration accepted in W16-G2-01. Real PostgreSQL/ClickHouse and loader/main-process negative tests retained. No W17 updater/map or operational Gate acceptance follows. Source mock is excluded; the preparation scope of W16-G2-01 is accepted with the evidence in [its report](w16-g2-01.md). |
| Module README | Rewritten against the actual directive parser, defaults, key rotation and block page handling; signed configuration checks on both supported NGINX versions are recorded below. |
| Quality/Gate reports | Unsupported results replaced with explicit outstanding campaign/operational evidence; no Gate approval or rollout inferred from code tests. |
| Connector-group role bindings | Not implemented by this source. Current role permissions intersect machine scopes; group-specific binding is an outstanding feature, not a selected source change. |

## Audit backend acceptance

Before repair, hostile query values were ignored, a filtered request could silently return unrelated recent rows, and the HTTP error exposed PostgreSQL endpoint details. Fresh regressions failed on main before these changes (raw stdout attached).

Filters for actor/channel/action/resource/from/to now run in PostgreSQL before the bounded newest-row limit. The time interval is [from,to); action/resource searches treat `%`, `_` and SQL text as literal data. Invalid/duplicate/unknown/malformed query parameters are rejected. The API fetches one extra row to report `has_more`; unavailable filter support fails explicitly. Error bodies omit DB details; audit responses are no-store. A five-second context bounds DB reads.

Migration 0024 adds an immutable subject column for future audit writes and an actor/time index. Store and local-account writers preserve authenticated subjects; historical unknown subjects remain blank. Credential audit envelopes are retained unchanged. Existing version-18/19 upgrade tests now seed their historical rows through the historical SQL schema rather than invoking a current writer against a deliberately downgraded DB; upgrade/provenance assertions remain intact.

Evidence: real PostgreSQL test seeded an older target plus 600 newer unrelated entries, then found the older entry through combined actor/channel/action/resource/time filters. Tested exclusive time end, literal SQL/wildcard input, viewer 403, truncation, before/after states and subject preservation through both writers. Full control-plane `go test -race -count=1 ./...` passed (API 13.627s, Fleet 38.789s, local auth 30.290s, store 21.008s); `golangci-lint run` reports 0 issues. Optional ClickHouse/native/browser tests still require their own fixtures; they are not claimed by this suite. OpenAPI and generated TypeScript now describe the previously undocumented audit endpoint.

## Audit UI selection

The original source's store search intention is now exposed through the generated audit contract. Separate actor/resource/action/channel/time fields search stored history; quick text search is explicitly limited to displayed rows. UI shows the newest matching-row limit and `has_more`, exports the displayed filtered set, converts local time bounds to RFC3339, and rejects inverted ranges. The existing bounded-read hook aborts superseded reads and ignores late responses. A failed read hides stale rows and disables export. Before/after values `false` and `0` remain visible; the inspector traps focus, closes with Escape and restores the trigger. All added labels are EN/VI.

Validation: seven AuditPage tests passed, including older-response suppression, invalid dates, refresh failure and focus/false-value regressions. Full UI suite: 25 files / 156 tests passed; TypeScript lint and production build passed. A separate real-browser/PostgreSQL fixture also passed before selecting this UI, with a 601-row historical dataset; its reproducible harness and receipt are recorded in the following evidence change. This completes the selected audit filter path, not the branch's missing nine-block runtime implementation or operational Gate B.

## Reproducible browser acceptance

The checked-in opt-in Go fixture starts an isolated local-auth/API/admin gateway and a fresh real PostgreSQL database, serves the built UI, and launches Chromium on the same private loopback network. It seeds one older target plus 600 later unrelated history records, in addition to fixture auth activity. Chromium initially sees 200 rows with truncation, then combines actor/resource/action/channel/time bounds to find the older target and its immutable subject; CSV contains the target and excludes unrelated rows. The before/after inspector, Tab/Shift-Tab/Escape/focus restoration and 390px Vietnamese form pass. Viewer and approver each get direct API 403 and no audit table. No external requests, query credentials or browser errors were observed; traces/videos/automatic screenshots are off and only synthetic metadata appears in the manual screenshot.

`TestAuditBrowserLab` passed with Go -race (15.25s fixture / 16.471s package); Chromium passed in 5.7s (8.8s runner), API lint 0 issues. The PostgreSQL target row remains unchanged after reading; receipts include source/build hashes. This verifies local audit query/UI behavior; it is not GeoIP, clean-VM, rollout or Gate evidence.

## Final source disposition

Source `0dce6de4c0410168642eb260d9c9f8ea7e028d2c` adds three commits over the shared base `e93dc0b`. All 28 changed files have an explicit disposition and original-content hash in the manifest. The source contains no additional completed connector-group role-binding implementation or saved nine-block form to recover. Those gaps stay open; local form state must not masquerade as an enforced policy.

Credentials/auth/RBAC/wiring/Users tests are replaced by #223–#229. Audit store/handler/client tests and filtering UI are replaced by #236–#238. The source mock GeoIP reader, mutable cache and producer-trusted metadata are replaced by #241–#245, including real MMDB and real ClickHouse tests. The source's original tests/claims are not silently copied as proof of these replacements. Runtime and Go dependency repairs #239–#240 are part of the selected base.

The original weekly Done declarations are excluded. W15-Q/S campaign, real-traffic tokenizer tuning, W16 million-request quality, retrospective/operator fail-closed choices and Gate B remain unaccepted. Their reports now state the missing artifacts explicitly. No staging/production connection, fail-mode/body/rate-table behavior change or rollout was performed.

After validation, the final integration uses an explicit `ours` history merge of this source, preserving the reviewed replacement tree and the old commits for recovery. This is deliberate selective consolidation, not approval of the old RAM credential service, unsaved controls or Gate claims. Only this exact source SHA may be retired; concurrently advanced W17/W21 and other independent feature heads remain outside this acknowledgement. The verified complete Git bundle contains committed refs, not uncommitted worktree content.


## Directive/build validation

The module reference now lists all 21 directives with parser-accepted contexts, syntax and defaults. It includes the aggregate breaker threshold `2% 10s 200 open=30s`, Unix socket prefix, raw 32/64-byte trusted keys, file-only 64 KiB block page, shadow-only stream restriction, binary metrics and cooperative-budget limits. The README's actual `nginx` code block is extracted by `connectors/nginx/scripts/check-readme.py`, then checked with a real signed bundle; no signature bypass or disabled Strata.

The rebuild reproduced a separate build-script defect: `STRATA_LIB` changed, but the configure cache omitted its path and the link still used the old absent `/src/target/release/libstrata.a`. The stamp now includes the selected archive path. Both versions reconfigured/relinked successfully using `/src/build/m4-runtime-target/release/libstrata.a` with `-Wall -Wextra -Werror`; source C/Rust request handling is unchanged.

Commands/results (full raw output retained in the evidence directory):

- Separate `cargo build --offline --locked --release -p libstrata-ffi --features test-hooks`, then `STRATA_LIB=... connectors/nginx/scripts/build.sh <version> build` for both versions: PASS.
- `python3 connectors/nginx/scripts/check-readme.py --version <version> --bin-dir build/m4-runtime-target/release`: NGINX 1.30.5 and 1.31.6 each **11 configuration cases PASS**, including all remaining directives, key rotation and rejection of old enum/threshold/socket syntax, missing key, oversize page and stream/enforce conflict. Binary/module SHA256 is in stdout.
- From `connectors/nginx`, matching binary in PATH and TEST_NGINX_LOAD_MODULES/STRATA_COMPILE/STRATA_MKBUNDLE configured, `prove t/003-config.t t/090-breaker.t`: **Files=2, Tests=60, Result: PASS**, 32 s stable and 33 s mainline. Expected negative configuration errors appear in the raw log; no test was removed or disabled.
- Shell syntax, Python compilation, relative documentation links (6 files / 10 links) and `git diff --check`: PASS.

Initial attempts are retained too: an unmounted Cargo registry could not resolve dependencies; the shared verified cache fixed that. A combined compiler+FFI Cargo invocation unified the compiler-only Hyperscan feature and produced a non-PIC link error; building FFI separately as the Makefile does fixed the archive. The first prove command ran from the wrong directory and bailed before executing tests; the final runs use the Makefile's working directory. These setup failures are not reported as passing tests. This follow-up does not claim a fresh full native sanitizer/H3/Valgrind campaign; earlier sanitizer evidence remains scoped to its own reviewed unchanged runtime.

Self-review: directive values/defaults and source dispositions checked against code; no runtime/interface/dependency change; build archive selection now participates in cache invalidation; tests retain negative paths; no private key material logged; only module docs/build/verification and review evidence/tracker changed. Approval applies to this selected replacement tree and source retirement; weekly operational acceptance remains outstanding.
