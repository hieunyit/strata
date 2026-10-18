# Go runtime security prerequisite for branch consolidation

Review scope: an independently deployable prerequisite found while reviewing W15–W16 GeoIP. This selects no pending weekly feature and proves no rollout/Gate. Owner authorized local verification, fixes and merges without waiting for hosted CI.

The initial `govulncheck v1.1.4 -json ./ingest` run used Go 1.25.14 and reported 13 affected stdlib advisory IDs; nine had symbol traces. These are conservative call-graph findings, not demonstrated exploitability of a deployed endpoint. The scan included the in-progress GeoIP reader; none of these findings came from its decoder dependency. The advisory DB timestamp and raw streams are retained in evidence.

The dev image now installs the SHA-256-verified Go 1.26.9 archive, and rebuilds all Go tools with that compiler. golangci-lint moves to 2.10.1 for Go 1.26 support. All nine repository Go modules require `go 1.26.9`, so builds cannot silently use an older compiler. AGENTS' environment note follows the actual minimum; its weekly pointer/status tables are unchanged.

## Verification boundary

The review image `strata-dev:go1.26.9-review` was built from the existing dev image using the exact updated Go/tool installation block. It removes the old Go installation before extraction and limits build parallelism. `go version` confirms go1.26.9 and `golangci-lint version` confirms it was built with go1.26.9. This validates the changed Go layer; a full unrelated Rust/nightly/quictls image rebuild is not claimed, nor was the shared dev image retagged or any running service redeployed.

Full control-plane `go test -race -count=1 -timeout 10m ./...` passed against an owned real PostgreSQL 17.11: API 14.508s, Fleet 38.422s, local auth 29.500s, store 20.854s; lint 0 issues and server builds passed. The complete agent race suite/lint/build also passed. Race tests, lint and builds passed for the differential module and all five rule/import/mutation/comparison tool modules. The first CRS run correctly failed for a missing fixture; the rerun mounted the already checksum-verified CRS 4.25.2 fixture read-only and passed. No test was disabled.

The e2e run uncovered a stale exact table inventory: migration 0023 creates machine_accounts/machine_requests/machine_tokens, but the assertion predated that change. The test now explicitly expects those three tables and checks the same exact inventory again after downgrade/re-upgrade. Its all-tables-removed and schema-enforced four-eyes assertions remain intact. The corrected full e2e short suite passed with race detection in 191.825s; e2e lint reports 0 issues. It exercises real agent enrollment, four-eyes replay/deploy, force-shadow and rollout/signature refusal against fresh lab containers. Long outage/certificate/network-fault cases are intentionally excluded by the existing -short mode, and native restart/corruption/M4 cases lack opt-in native fixtures. These exclusions are not counted as passes. The initial failing output is retained; this is a schema-test maintenance correction, not a relaxation of the migration contract.

A full-control-plane scan with Go 1.26.9 reports **zero stdlib findings**. It still reports separate findings in gRPC, pgx, JOSE and x/* dependencies. These remain an explicit follow-up security change, not a clean bill of health for the whole dependency graph. JSON-mode exit status alone is not treated as absence of findings; the report's finding records are inspected.

## Reproduction

Use `STRATA_DEV_IMAGE=strata-dev:go1.26.9-review deploy/dev/run.sh`, the shared Go cache, and only owned isolated lab fixtures. In control-plane and agent: `go test -race -count=1 -timeout 10m ./...`, `golangci-lint run`, `go build ./cmd/...`. In conformance/differential and each tools/* Go module: race tests, lint, `go build ./...`. E2e uses Docker access on the lab host and creates/removes its own PostgreSQL/MinIO containers; native fixtures remain opt-in. Scan: `go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -json ./...`; group finding records by module and symbol traces, not all OSV metadata records.

Sources: [Go downloads/checksums](https://go.dev/dl/?mode=json), [Go security database](https://vuln.go.dev/), [golangci-lint Go 1.26 support](https://github.com/golangci/golangci-lint/releases/tag/v2.9.0).

Self-review: changed installation inputs checksum-verified; no request-path policy, C ABI, proto, rule or secret changes; all module minimums checked; real negative/security tests retained; error evidence and residual dependency risks explicitly recorded. Existing deployed binaries require rebuilding and redeployment by their operator to receive the runtime fix.
