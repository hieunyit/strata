## Rule report (corpus v0, libstrata)

9043 rules evaluated, 0 skipped (the engine lacks an operator, transformation or target).

### Recall by attack type

| Attack type | Payloads | Detected % | Blocked % |
| --- | ---: | ---: | ---: |
| command-injection | 479 | 95.0 | 52.0 |
| path-traversal | 467 | 86.7 | 86.1 |
| sql-injection | 946 | 71.9 | 69.7 |
| xss | 667 | 52.8 | 52.5 |

### False positives on benign requests

| Benign requests | Some rule matched | Blocked |
| ---: | ---: | ---: |
| 2000 | 167 (8.35%) | 167 (8.35%) |

Rules matching benign requests:

| Rule | Benign requests matched |
| --- | ---: |
| 930120 | 96 |
| 942100 | 71 |
