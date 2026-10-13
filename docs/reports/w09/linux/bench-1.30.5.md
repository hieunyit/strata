### NGINX 1.30.5

Throughput (64 connections, keep-alive); Δ against off:

| Scenario | req/s off | req/s phase 0-1 | Δ | req/s full | Δ | engine mean µs (p01 / full) | fail-open (p01 / full) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 25,947 | 14,724 | -43.3% | 3,162 | -87.8% | 35.0 / 526.6 | 0 / 93 |
| 64k | 9,472 | 2,916 | -69.2% | 806 | -91.5% | 434.2 / 2136.0 | 82 / 20225 |
| 1m | 1,013 | 733 | -27.6% | 483 | -52.3% | 753.1 / 2129.1 | 432 / 12061 |
| h2 | 20,453 | 13,127 | -35.8% | 2,800 | -86.3% | 39.1 / 589.9 | 0 / 160 |

Latency (4 connections, no queueing), µs; overhead = on - off:

| Scenario | p50 off | p99 off | p50 p01 | p99 p01 | overhead p50 / p99 (p01) | p50 full | p99 full | overhead p50 / p99 (full) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| small | 397 | 1090 | 583 | 2250 | +186 / +1160 | 2720 | 6580 | +2323 / +5490 |
| 64k | 1020 | 2630 | 2900 | 5780 | +1880 / +3150 | 5660 | 10080 | +4640 / +7450 |
| 1m | 8750 | 20310 | 9350 | 27900 | +600 / +7590 | 12690 | 22500 | +3940 / +2190 |

Event socket (phase 0-1 bundle; every request sends an event, 64 connections):

| req/s p01 | req/s p01 + events | Δ | events received | events dropped | drop % | events/s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 14,724 | 11,668 | -20.8% | 284,193 | 733 | 0.26% | 14,246 |
