# Review W15–W16 branch — source 0dce6de

Scope: review/repair/consolidation of the existing branch, authorized by the owner; no rollout or Gate acceptance. Work stays on this source family until its content has a documented disposition. PR #144 remains open until that review is complete.

| Source area | Disposition |
| --- | --- |
| Machine credentials and Users UI | Replaced by reviewed main #223–#229: durable transactions/audit/idempotency, bounded scopes/expiry, UI/browser acceptance. Do not import RAM credentials or query tokens. |
| Audit query | Selected and repaired in this change: DB filters before LIMIT, explicit time bounds, literal substring matching, immutable subject persistence, bounded request/query, generic backend errors and has_more. UI integration follows separately. |
| Nine-block policy panel | Source controls for templates/content profiles/violations/signature sets only change local React state; they are not serialized into the saved policy. Exclude those fake controls and retain main's preserved advanced policy data. Full nine-block form/runtime behavior is not claimed delivered. |
| GeoIP ingestion/schema | Pending real MMDB loader, safe cache lifetime, authoritative enrichment, schema migration and real ClickHouse tests. Source reader is a mock, insufficient for W16-G2-01. |
| Module README and quality/Gate reports | Pending final code/directive comparison and correction of unsupported operational claims. Gate B cannot be inferred from passing unit tests. |

## Audit backend acceptance

Before repair, hostile query values were ignored, a filtered request could silently return unrelated recent rows, and the HTTP error exposed PostgreSQL endpoint details. Fresh regressions failed on main before these changes (raw stdout attached).

Filters for actor/channel/action/resource/from/to now run in PostgreSQL before the bounded newest-row limit. The time interval is [from,to); action/resource searches treat `%`, `_` and SQL text as literal data. Invalid/duplicate/unknown/malformed query parameters are rejected. The API fetches one extra row to report `has_more`; unavailable filter support fails explicitly. Error bodies omit DB details; audit responses are no-store. A five-second context bounds DB reads.

Migration 0024 adds an immutable subject column for future audit writes and an actor/time index. Store and local-account writers preserve authenticated subjects; historical unknown subjects remain blank. Credential audit envelopes are retained unchanged. Existing version-18/19 upgrade tests now seed their historical rows through the historical SQL schema rather than invoking a current writer against a deliberately downgraded DB; upgrade/provenance assertions remain intact.

Evidence: real PostgreSQL test seeded an older target plus 600 newer unrelated entries, then found the older entry through combined actor/channel/action/resource/time filters. Tested exclusive time end, literal SQL/wildcard input, viewer 403, truncation, before/after states and subject preservation through both writers. Full control-plane `go test -race -count=1 ./...` passed (API 13.627s, Fleet 38.789s, local auth 30.290s, store 21.008s); `golangci-lint run` reports 0 issues. Optional ClickHouse/native/browser tests still require their own fixtures; they are not claimed by this suite. OpenAPI and generated TypeScript now describe the previously undocumented audit endpoint.
