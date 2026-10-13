### NGINX 1.30.5

Throughput (64 connections, keep-alive); Δ against off:

| Scenario | req/s off | req/s phase 0-1 | Δ | req/s full | Δ | engine mean µs (p01 / full) | fail-open (p01 / full) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 40,810 | 21,842 | -46.5% | 4,716 | -88.4% | 24.1 / 298.9 | 1 / 4 |
| 64k | 18,136 | 4,968 | -72.6% | 785 | -95.7% | 266.3 / 2097.1 | 1 / 22193 |
| 1m | 2,505 | 1,658 | -33.8% | 712 | -71.6% | 476.7 / 2079.7 | 9 / 17943 |
| h2 | 43,565 | 24,952 | -42.7% | 4,926 | -88.7% | 24.1 / 330.6 | 2 / 4 |

Latency (4 connections, no queueing), µs; overhead = on - off:

| Scenario | p50 off | p99 off | p50 p01 | p99 p01 | overhead p50 / p99 (p01) | p50 full | p99 full | overhead p50 / p99 (full) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 157 | 376 | 183 | 429 | +26 / +53 | 1010 | 2280 | +853 / +1904 |
| 64k | 279 | 548 | 1060 | 1890 | +781 / +1342 | 6640 | 11090 | +6361 / +10542 |
| 1m | 2010 | 3400 | 2350 | 4130 | +340 / +730 | 7530 | 12760 | +5520 / +9360 |

Event socket (phase 0-1 bundle; every request sends an event, 64 connections):

| req/s p01 | req/s p01 + events | Δ | events received | events dropped | drop % | events/s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 21,842 | 13,887 | -36.4% | 351,372 | 4,647 | 1.31% | 17,801 |
