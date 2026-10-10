# corpus

Test data for the rules (docs/plan/plan.md › Luồng S), corpus v0 (W04-S-01).
Never packed into a bundle; see NOTICE for origins and licenses.

| Path | What | Made by |
| --- | --- | --- |
| `attack/<type>.jsonl` | attack payloads: `{payload, attack_type, source, license}`; `source` is `repo@commit:path:line` | `strata-rules corpus fetch` from the pinned commits in `sources.yaml` |
| `benign/synthetic.jsonl` | 2,000 ordinary API and web requests (names with apostrophes, SQL and HTML words in prose, dotted paths, JSON) | `strata-rules corpus benign --seed 1` |
| `crs-ftw/<group>.jsonl` | the go-ftw tests of CRS 4.25.2: `{rule, test, expect: match/no_match, request}` | `make crs-ftw`; tests that could not be converted: `docs/crs-ftw-unconverted.md` |

Requests use the same fields as the tests of rule files (`method`, `uri`,
`headers`, `body`, `remote_addr`). A payload is sent in a query parameter
and in a form field, and in the path for path traversal.

```bash
make test-rules   # builds strata-compile and strata-eval, runs rule tests and the report
```

`strata-rules report` compiles every rule under `rules/` and runs the corpus
through libstrata (`strata-eval`): false positives on `benign/`, and recall
(some rule matched / blocked) per attack type. On a pull request CI also
runs it on the base branch's rules and shows the change in the job summary.
Rules using an operator, transformation or target the engine does not
evaluate yet are counted as skipped.
