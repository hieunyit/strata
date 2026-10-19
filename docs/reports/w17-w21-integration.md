# W17–W21 integration tracker

Scope: review existing branches, repair/select completed code, test locally,
merge per reviewed slice and delete only consolidated refs. Hosted CI is not
awaited per user instruction. Existing Done claims are not acceptance evidence.

| Week | Accepted work / evidence | Remaining boundary |
| --- | --- | --- |
| 17 | [SSTI component](ssti-detector-review.md), [compiler/runtime](w17-ssti-runtime-review.md), [CMDi](w17-cmdi-review.md). MMDB reader/cache/authoritative ingest/storage/startup foundations accepted in #241–245 | JA4 reference vectors/runtime; GeoIP update job, aggregate API, offline tiles/map, PL2/exclusions and load acceptance |
| 18 | Foundations above retained | Stats/geo/timeline/SSE and UI; authenticated/expiring bot feeds and actual engine verification; CRS expansion/bot pack review |
| 19 | [Lite packaging/installer](standalone-installer-review.md), [bootstrap](standalone-bootstrap-review.md) | Geo/ASN compiler+verdict+approved-policy path and drill-down. [Clean-VM acceptance held by user](standalone-vm-hold.md) |
| 20 | Unsafe blanket SQLi exemptions excluded; existing detector and malicious regressions retained | Corpus-based FP tuning, replay-safe hourly aggregates, dashboard using real telemetry and API template |
| 21 | Candidate histories/rules preserved | Durable schema API and signed positive-model enforcement; generated-client UI; ID conflicts/content review; real red-team/regression evidence |

Rate-table saturation remains measurement-only by user decision; no implicit
rate/challenge enforcement or saturation-policy change. Large-body budget/default
handling and default-off M4 opt-in remain unchanged. No staging/production access,
no week-pointer or Gate assertion. Source W17/W21 and dependent branches remain
until their complete changed-file disposition is reviewed.
