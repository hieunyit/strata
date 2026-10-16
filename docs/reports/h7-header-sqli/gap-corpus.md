## Rule report (corpus v0, libstrata)

11 rules evaluated, 0 skipped (the engine lacks an operator, transformation or target).

### Recall by attack type

| Attack type | Payloads | Detected % | Blocked % |
| --- | ---: | ---: | ---: |
| command-injection | 479 | 30.9 | 30.9 |
| path-traversal | 466 | 13.5 | 13.1 |
| sql-injection | 807 | 2.1 | 2.0 |
| xss | 529 | 44.0 | 42.3 |

### False positives on benign requests

| Benign requests | Some rule matched | Blocked |
| ---: | ---: | ---: |
| 3000 | 0 (0.00%) | 0 (0.00%) |
