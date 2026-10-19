# Review W15–W16 branch — source 0dce6de

Scope: review/repair/consolidation of the existing branch, authorized by the owner; no rollout or Gate acceptance. Work stays on this source family until its content has a documented disposition. PR #144 remains open until that review is complete.

| Source area | Disposition |
| --- | --- |
| Machine credentials and Users UI | Replaced by reviewed main #223–#229: durable transactions/audit/idempotency, bounded scopes/expiry, UI/browser acceptance. Do not import RAM credentials or query tokens. |
| Audit query | Selected and repaired in this change: DB filters before LIMIT, explicit time bounds, literal substring matching, immutable subject persistence, bounded request/query, generic backend errors and has_more. The typed UI now queries these stored-history filters; browser fixture/evidence is retained separately. |
| Nine-block policy panel | Source controls for templates/content profiles/violations/signature sets only change local React state; they are not serialized into the saved policy. Exclude those fake controls and retain main's preserved advanced policy data. Full nine-block form/runtime behavior is not claimed delivered. |
| GeoIP ingestion/schema | Real MMDB loader, safe cache, authoritative enrichment and DB schema/projections verified in their reviews, including real ClickHouse migration/ingest tests. Runtime startup activation remains pending. Source mock is excluded; W16-G2-01 is not complete. |
| Module README and quality/Gate reports | Pending final code/directive comparison and correction of unsupported operational claims. Gate B cannot be inferred from passing unit tests. |

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
