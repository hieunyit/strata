### NGINX 1.30.5

Throughput (64 connections, keep-alive); Δ against off:

| Scenario | req/s off | req/s phase 0-1 | Δ | req/s full | Δ | engine mean µs (p01 / full) | fail-open (p01 / full) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 25,762 | 19,449 | -24.5% | 876 | -96.6% | 37.1 / 2104.1 | 4 / 17650 |
| 64k | 16,813 | 4,105 | -75.6% | 663 | -96.1% | 307.6 / 2238.6 | 158 / 15010 |
| 1m | 1,397 | 1,438 | +2.9% | 590 | -57.8% | 515.9 / 2135.4 | 25 / 13232 |
| h2 | 35,103 | 20,290 | -42.2% | 876 | -97.5% | 38.1 / 2111.4 | 13 / 16996 |

Latency (4 connections, no queueing), µs; overhead = on - off:

| Scenario | p50 off | p99 off | p50 p01 | p99 p01 | overhead p50 / p99 (p01) | p50 full | p99 full | overhead p50 / p99 (full) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 150 | 784 | 234 | 547 | +84 / -236 | 5725 | 849750 | +5576 / +848966 |
| 64k | 318 | 3145 | 1355 | 3890 | +1036 / +745 | 5920 | 13395 | +5602 / +10250 |
| 1m | 2660 | 7505 | 2650 | 5390 | -10 / -2115 | 9195 | 16520 | +6535 / +9015 |

Event socket (phase 0-1 bundle; every request sends an event, 64 connections):

| req/s p01 | req/s p01 + events | Δ | events received | events dropped | drop % | events/s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 19,449 | 13,575 | -30.2% | 303,258 | 901 | 0.30% | 20,277 |
