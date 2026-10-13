### NGINX 1.31.6

Throughput (64 connections, keep-alive); Δ against off:

| Scenario | req/s off | req/s phase 0-1 | Δ | req/s full | Δ | engine mean µs (p01 / full) | fail-open (p01 / full) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 37,195 | 20,122 | -45.9% | 4,833 | -87.0% | 27.4 / 336.5 | 1 / 47 |
| 64k | 18,815 | 3,803 | -79.8% | 744 | -96.0% | 297.8 / 2094.7 | 75 / 21853 |
| 1m | 2,130 | 1,107 | -48.0% | 611 | -71.3% | 624.6 / 2082.4 | 269 / 17772 |
| h2 | 42,119 | 24,939 | -40.8% | 4,774 | -88.7% | 24.0 / 338.0 | 5 / 41 |

Latency (4 connections, no queueing), µs; overhead = on - off:

| Scenario | p50 off | p99 off | p50 p01 | p99 p01 | overhead p50 / p99 (p01) | p50 full | p99 full | overhead p50 / p99 (full) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 169 | 1740 | 198 | 703 | +29 / -1037 | 1130 | 3120 | +961 / +1380 |
| 64k | 229 | 482 | 1760 | 12140 | +1531 / +11658 | 6720 | 11410 | +6491 / +10928 |
| 1m | 2400 | 5310 | 2400 | 6270 | +0 / +960 | 5720 | 12460 | +3320 / +7150 |

Event socket (phase 0-1 bundle; every request sends an event, 64 connections):

| req/s p01 | req/s p01 + events | Δ | events received | events dropped | drop % | events/s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 20,122 | 14,911 | -25.9% | 425,529 | 1,501 | 0.35% | 21,352 |
