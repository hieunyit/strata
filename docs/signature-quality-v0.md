## Rule report (corpus v0, libstrata)

9054 rules evaluated, 0 skipped (the engine lacks an operator, transformation or target).

### Recall by attack type

| Attack type | Payloads | Detected % | Blocked % |
| --- | ---: | ---: | ---: |
| command-injection | 479 | 94.6 | 94.2 |
| path-traversal | 466 | 93.8 | 92.7 |
| sql-injection | 807 | 76.6 | 76.3 |
| xss | 529 | 75.8 | 75.2 |

### False positives on benign requests

| Benign requests | Some rule matched | Blocked |
| ---: | ---: | ---: |
| 2000 | 12 (0.60%) | 12 (0.60%) |

Rules matching benign requests:

| Rule | Benign requests matched |
| --- | ---: |
| 942100 | 12 |
