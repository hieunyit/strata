### NGINX 1.31.6

Throughput (64 connections, keep-alive); Δ against off:

| Scenario | req/s off | req/s phase 0-1 | Δ | req/s full | Δ | engine mean µs (p01 / full) | fail-open (p01 / full) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 24,821 | 14,986 | -39.6% | 3,140 | -87.4% | 33.4 / 528.8 | 0 / 87 |
| 64k | 9,093 | 2,841 | -68.8% | 810 | -91.1% | 449.6 / 2124.7 | 67 / 20335 |
| 1m | 991 | 778 | -21.5% | 476 | -52.0% | 676.8 / 2131.1 | 220 / 11870 |
| h2 | 20,662 | 12,858 | -37.8% | 2,739 | -86.7% | 38.5 / 605.5 | 0 / 150 |

Latency (4 connections, no queueing), µs; overhead = on - off:

| Scenario | p50 off | p99 off | p50 p01 | p99 p01 | overhead p50 / p99 (p01) | p50 full | p99 full | overhead p50 / p99 (full) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 422 | 980 | 618 | 1880 | +196 / +900 | 2950 | 7620 | +2528 / +6640 |
| 64k | 990 | 4220 | 2890 | 7060 | +1900 / +2840 | 5640 | 10550 | +4650 / +6330 |
| 1m | 8230 | 18800 | 8150 | 26430 | -80 / +7630 | 11040 | 21280 | +2810 / +2480 |

Event socket (phase 0-1 bundle; every request sends an event, 64 connections):

| req/s p01 | req/s p01 + events | Δ | events received | events dropped | drop % | events/s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 14,986 | 11,918 | -20.5% | 284,304 | 760 | 0.27% | 14,253 |
