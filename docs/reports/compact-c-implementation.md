# Compact C · Implementation index

User request: merge B, then implement C03/C01/C02/C04/C05; B03 remains excluded.
All B PRs #296–#320 were merged, final main commit
`ccf04bf7eaefb26ca969cd12ac33d917448e13bf`. No staging/production deployment.

| Task | State | Report / review |
| --- | --- | --- |
| C03 Privacy, local MFA, sessions, external audit copies | Code/tests complete; open dependent PRs #321–#335 | [Acceptance and ordered PRs](cp-c03.md), [final PR #335](https://github.com/hieunyit/strata/pull/335) |
| C01 Investigation | Code/tests complete; open dependent PRs #336–#351 | [Acceptance and ordered PRs](cp-c01.md) |
| C02 Rule/exception lifecycle | Code/tests complete; open PRs #352–#365 | [Acceptance and ordered PRs](cp-c02.md) |
| C04 Alerts/reports | Code/tests complete; open PRs #366–#375 | [Acceptance and ordered PRs](cp-c04.md) |
| C05 Discovery | Code/test complete; collection disabled pending actual legal approval | [Acceptance and ordered PRs](cp-c05.md); documentation-only preview |

Use the PR bases in each report and merge in order. C work remains open for review unless
explicitly recorded as merged. PostgreSQL/ClickHouse and local-auth defaults remain.


All requested C code is implemented in the dependent review stack. C05 does not supply
runtime OpenAPI enforcement or install a live collector. Its separate feed is legally
gated and disabled by default; only synthetic observations were exercised. Review and
merge these PRs in dependency order before deployment. No C PR is claimed as merged.
