# H6 — Isolated restart fixture and honest delivery scope

Branch: `codex/h6-lossless-fixture-isolation` · base: `534573e` (PR #178).

The previous test discovered a server through fixed localhost ports or legacy environment variables and truncated `events` and `node_seq`. Running that test could erase another lab's data. It now creates a private ClickHouse 25.8.33 container with a random password and ephemeral loopback port, registers cleanup immediately after creation, and removes only that container ID and its volumes. It never adopts a discovered server and no longer truncates tables.

The producer has a bounded write deadline, synchronized close/send, a bounded restart-threshold wait and explicit retry/rate accounting. Existing delivery, restart-boundary and raw duplicate assertions remain. A second test creates two fixtures, points legacy variables at the first, and proves the second neither adopts it nor changes its sentinel row.

Validation in the dev image, with Docker CLI/socket mounted, CPUs 6–10:

```sh
cd tests/e2e
go test -race -count=1 -timeout 8m -v -run '^(TestLosslessFixtureIgnoresLegacyAddresses|TestLosslessRestartUnderLoad)$' .
golangci-lint run
```

```text
retry-capable producer: 2000 datagrams, 7 retried writes, 870.14 datagrams/s over 2.298470167s; not NGINX throughput
ClickHouse received 2000 / 2000 events
SUCCESS: All 2000 events accounted for in ClickHouse with zero loss and zero duplicates across agent restart under load!
--- PASS: TestLosslessRestartUnderLoad (16.72s)
--- PASS: TestLosslessFixtureIgnoresLegacyAddresses (10.41s)
ok github.com/strata/strata/tests/e2e 28.294s
0 issues.
```

Raw evidence: [output](evidence/h6-lossless-isolation/output.txt). The unsafe parent fixture was inspected, not executed against a shared database. This is a real agent graceful SIGTERM restart with its existing spool, a retry-capable test producer and a test Fleet ingest server. It does not prove NGINX sink delivery, unclean crash durability, production identity binding, a throughput target, or the complete five-fault game day. The test server accepts the node ID from the payload; production authorization is outside this fixture.

Self-review: all assertions retained; error/deadline/cleanup paths bounded; generated password is not logged; no runtime interfaces or dependencies changed; only e2e tests and their evidence changed; race tests and area lint passed. Hosted CI was not required or awaited.
