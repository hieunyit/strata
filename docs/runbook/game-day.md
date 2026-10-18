# Game-day evidence and remaining acceptance

The retired W14 harness ran selected unit tests or searched for `catch_unwind` and printed five disaster scenarios as passed. Those commands did not exercise the claimed failures; zero selected tests could also exit successfully. They are not Gate evidence.

The compatibility entry point `tests/chaos/game_day_test.sh VERSION build/NEW_OUTPUT` now delegates to the native fault runner **inside the dev image**. That runner rebuilds the selected NGINX/module, runs the three named native suites, verifies a nonzero TAP summary and fails on sanitizer reports or skipped coverage. It tests signed-bundle rejection, panic/fail-mode and circuit-breaker components. It does not run five infrastructure scenarios or declare the whole game day complete.

Additional actual chains are in `tests/e2e/`:

| Fault | Test / evidence |
|---|---|
| Network outage/cut/reset | `network_faults_test.go`; [network drills](../reports/h6-network-drills.md) |
| Actual CP process restart | `TestControlPlaneProcessRestartWithRealNginx`; [process restart](../reports/h6-control-plane-process-restart.md) |
| SIGKILL between CH commit and PG watermark, with native panic event | `TestControlPlaneCrashBetweenIngestCommits`; [crash window](../reports/h6-ingest-commit-crash.md) |
| Corrupted object after deploy verification | `TestCorruptedArtifactKeepsNativeLastKnownGood`; [artifact chain](../reports/h6-corrupted-artifact-chain.md) |

These fixtures own their containers/data and require the explicit native/compiler/replay/evidence environment described by the reports. Missing fixture configuration causes Go tests to skip, so a bare `go test` success is insufficient. Preserve logs, executable/artifact hashes, event IDs, acknowledgements and spool state. Never disable signatures, TLS or authorization to make a drill pass.

Still required for operational acceptance: coordinated load and multiple nodes, realistic event-pressure/loss boundaries, real application bypass campaign, long soak and observed recovery with operator responsibilities. The unintegrated rate/challenge prototype is not evidence of offline brute-force protection. Only the operator/PO can accept rollout and Gate results after the required observations.
