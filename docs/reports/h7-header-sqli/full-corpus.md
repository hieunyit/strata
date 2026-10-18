## Rule report (corpus v0, libstrata)

9065 rules evaluated, 0 skipped (the engine lacks an operator, transformation or target).

### Recall by attack type

| Attack type | Payloads | Detected % | Blocked % |
| --- | ---: | ---: | ---: |
| command-injection | 479 | 94.6 | 94.6 |
| path-traversal | 466 | 98.5 | 97.4 |
| sql-injection | 807 | 77.1 | 76.8 |
| xss | 529 | 76.4 | 75.8 |

### False positives on benign requests

| Benign requests | Some rule matched | Blocked |
| ---: | ---: | ---: |
| 3000 | 0 (0.00%) | 0 (0.00%) |
