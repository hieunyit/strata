# Compact C · Implementation and merge index

All B PRs #296–#320 were merged at `ccf04bf7eaefb26ca969cd12ac33d917448e13bf`.
C03/C01/C02/C04/C05 and the deployment handbook are now merged into main through
all 75 PRs #321–#395. Integration commit: `84160a3ee6ec296ff10d57082512c9820cb99b16`.
The merge receipt and exact-tree verification are recorded in
[compact-main-merge.md](compact-main-merge.md). No staging/production deployment.

| Task | State | Acceptance / implementation history |
| --- | --- | --- |
| C03 Privacy, local MFA, sessions, external audit copies | Merged #321–#335 | [C03](cp-c03.md) |
| C01 Investigation | Merged #336–#351 | [C01](cp-c01.md) |
| C02 Rule/exception lifecycle | Merged #352–#365 | [C02](cp-c02.md) |
| C04 Alerts/reports | Merged #366–#375 | [C04](cp-c04.md) |
| C05 Discovery documentation preview | Merged #376–#388; collection defaults off | [C05](cp-c05.md) |
| Deployment handbook | Merged #389–#395 | [Handbook](../operations/README.md), [validation](compact-deployment-guide.md) |

Task reports retain the historical PR bases and acceptance results from their initial
publication. The latest merge state is this index and the merge receipt. The stack was
collapsed from #395 towards #321, with the full tested tree checked after every merge;
#321 then introduced the complete integration into main in one update.

PostgreSQL/ClickHouse and local authentication remain the defaults. B03 remains excluded.
C05 does not install a live collector or enforce OpenAPI at runtime. Its separate feed
requires actual legal approval and remains disabled; only synthetic traffic was tested.

Final C local gates: control-plane race suite on real PostgreSQL/ClickHouse, Go lint
**0 issues**, UI **283 tests** plus final **4 affected tests**, **28 browser tests** plus
final discovery review rerun, selected e2e **56.894s**, all exit 0. The merge audit also
reran the restart regression: **2,000/2,000 events, zero loss and zero duplicates**,
**19.943s**, and the pinned-download safety tests: **5/5**, exit 0. Existing GitHub CI
runner/source-download failures are documented separately; they are not reported as green.
