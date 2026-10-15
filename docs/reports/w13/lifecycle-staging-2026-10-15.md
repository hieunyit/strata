# Rule review, 2026-10-15

RV-S-02: `strata-rules lifecycle`. 9064 rules. False positives over the last 7 days, threshold 0.05% of a policy's requests (RV-S-01).

## Rules to review (8)

Suspected false positives in shadow (attack sources excluded). Each line suggests a time-bound exception to consider (rule + policy + path, until the date); tuning the rule is preferred when the path is not the only one.

| Rule | Name | Pack | Policy | Events | Sources | Requests | Share | Top path | Exception until |
| ---: | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| 941100 | XSS Attack Detected via libinjection | core | pilot-verify | 2 | 1 | unknown | - | `/v1/verify` | 2026-10-29 |
| 941110 | XSS Filter - Category 1: Script Tag Vector | core | pilot-verify | 2 | 1 | unknown | - | `/v1/verify` | 2026-10-29 |
| 941160 | NoScript XSS InjectionChecker: HTML Injection | core | pilot-verify | 2 | 1 | unknown | - | `/v1/verify` | 2026-10-29 |
| 941180 | Node-Validator Deny List Keywords | core | pilot-verify | 2 | 1 | unknown | - | `/v1/verify` | 2026-10-29 |
| 941390 | Javascript method detected | core | pilot-verify | 2 | 1 | unknown | - | `/v1/verify` | 2026-10-29 |
| 942100 | SQL Injection Attack Detected via libinjection | core | pilot-verify | 2 | 1 | unknown | - | `/v1/verify` | 2026-10-29 |
| 700001 | Log4Shell JNDI lookup (CVE-2021-44228, CVE-2021-45046) | core | pilot-upload | 1 | 1 | unknown | - | `/v1/upload` | 2026-10-29 |
| 944150 | Potential Remote Command Execution: Log4j / Log4shell | core | pilot-upload | 1 | 1 | unknown | - | `/v1/upload` | 2026-10-29 |

## Old rules: no event in 90 days

Not judged yet: the event store holds 2.0 days, under 90 days.

## Review dates

No rule is past its review date.

Rules without an owner or a review date, by source:

| Source | No owner | No review date |
| --- | ---: | ---: |
| crawler-user-agents | 1454 | 1454 |
| crs | 148 | 148 |
| et-open | 7377 | 7377 |
| organization | 2 | 2 |
| sigma | 21 | 21 |
| strata | 52 | 52 |

## Upstream

Pinned by the importers; a re-import starts from these (then `make test-crs-ftw` and the benign corpus, before any release).

- OWASP CRS (`tools/strata-import-crs/crs.lock`): `4.25.2`
- Sigma (`tools/strata-import-signatures/sources.lock`): `2026-10-06 (8a48134)`
- ET Open (`tools/strata-import-signatures/sources.lock`): `11308`
- crawler-user-agents (`tools/strata-import-signatures/sources.lock`): `2026-09-29 (9345a7a)`
