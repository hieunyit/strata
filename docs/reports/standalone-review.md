# Review RV-G1-01 — signed bundle foundation

Source: standalone prototype at `9569d12` (also included in `65d0ce2`). Decision: repair before selecting code. This PR adds an internal watcher package; CLI/installer activation and the clean-VM SQLi/hot-reload acceptance remain pending. It does not mark the whole task Done.

Three fresh regressions failed on the source: no trusted key was accepted; replacing a same-named source produced a control digest different from installed bytes; corrupt control state was silently discarded. The replacement requires a trusted Ed25519 key, verifies every bundle, persists content-addressed files with file/directory fsync before updating the existing control inode, rejects unsigned rollback and same-version content changes, and restores the active version across restart. The existing signed rollback flag remains supported.

File and HTTP reads are bounded by the existing fleet limit (1 GiB); directory scans stop above 4,096 entries. Empty HTTP bodies, HTTP errors, cancellation, tampered signatures and oversized sparse files are rejected. A corrupt control file is an initialization error. Network transport retains normal TLS verification; signed HTTP sources remain supported as specified by the prototype design.

Validation: `go test -race -count=1 ./internal/standalone ./internal/bundles ./pkg/bundlefmt` passed (1.187s / 1.858s / 1.070s); `golangci-lint run ./internal/standalone/...` passed. Raw red/green stdout is compressed alongside the branch-consolidation evidence. The synthetic test bundles prove signing/control behavior, not engine layout conformance or the clean-VM acceptance.

Self-review: errors propagate; untrusted data has explicit size/entry limits; no signing bypass or new dependencies; edits are limited to the selected agent package and review evidence. No staging/production access. Old immutable files are retained, so periodic operator retention is still needed; the directory cap fails visibly rather than deleting a bundle workers might still use. Runner cancellation/export lifecycle, CLI validation, packaging and clean-VM evidence are reviewed separately.

## Event exporter selection

The source silently counted events as exported with no destination, did not actually write the documented `stdout`/`-` destinations, and accepted writes after closing sinks. All three regression tests failed before the repair. The selected exporter requires a destination, writes explicit stdout without taking ownership of the process descriptor, rejects/counts writes after close, and bounds syslog dial/write operations to two seconds. Existing real UDP syslog + JSONL output coverage is retained. Runtime/service coordination and CLI remain separate.

Validation: `go test -race -count=1 ./internal/standalone` and `golangci-lint run ./internal/standalone/...` passed; compressed red/green output is in the evidence directory. No new dependency, protocol or enforcement change. JSONL and syslog are direct sinks, without a durable queue/retry guarantee; disk/network failures are surfaced and counted.

## Runner lifecycle selection

A real blocked HTTP bundle request and a forced event-socket failure reproduced the source leak: Run returned while the watcher request remained live and the JSONL descriptor stayed open. The runner now owns a child context, cancels and joins all three service functions on either failure or parent cancellation, then closes the socket/exporter and returns combined cleanup errors. Syslog writes have the deadline from the preceding component. Event node identity is stamped from trusted runner configuration before export.

Validation: the whole agent module passed `go test -race -count=1 ./...` (agent 11.669s, standalone 1.340s) and `golangci-lint run` (0 issues). After adding node identity stamping, standalone tests passed again (1.294s), including socket-to-JSONL transport and parent-cancel / metrics-bind-error / blocked-download failure cleanup; standalone lint passed. Evidence includes the failing source run and fresh accepted outputs. CLI activation, package installer and clean-VM/native SQLi/hot-reload acceptance remain pending; this is not an RV-G1-01 Done claim.

## CLI selection

`strata-agent run --standalone` now exposes the reviewed internal runner. It requires a bundle source, trusted key, and JSONL/stdout/syslog sink; URL mode also needs an install directory. File and URL sources are mutually exclusive. Standalone-only arguments in fleet mode, and explicit fleet/auth/fallback arguments in standalone mode, fail with a descriptive error instead of being ignored. Common fleet flags preserve their existing behavior.

Validation: a real Cobra invocation with a signed synthetic fixture installed version 7 and its correct digest, then stopped on context cancellation without a control plane. Negative cases cover missing source/key/destination configuration and incompatible flags. `go test -race -count=1 ./cmd/strata-agent ./internal/standalone` passed (1.162s / 1.328s); full-module golangci-lint reported 0 issues. The fixture checks CLI/signature/control integration; it does not prove a real engine accepts the bundle layout. The package installer and clean-VM/native SQLi/hot-reload acceptance remain pending.

Example for an operator-supplied signed bundle (paths must match NGINX):

```sh
strata-agent run --standalone --bundle-file /var/lib/strata/bundles/source.sbn \
  --bundle-pubkey /etc/strata/bundle.pub --bundle-dir /var/lib/strata/bundles \
  --control-file /var/lib/strata/bundles/control --events-jsonl /var/log/strata/events.jsonl
```

## Native process lab on two NGINX versions

Fresh `make nginx-asan NGINX_VERSION=1.30.5` and `1.31.6` completed before running `tests/e2e/standalone-native.py`; the unchanged engine/FFI tree matches the previously reviewed integration (no diff from `0a5100c` under engine/src or engine/ffi). The agent executable was built with `go build -race`. Both runs use Docker `--network none` and loopback HTTP only. Stable: 1.719s; mainline: 1.675s before teardown. Both returned benign 200 / SQLi 403, changed the same bundle source path, observed the second rule block after hot reload, kept worker PIDs unchanged, verified the installed bytes against the control digest, rejected an older signed bundle without rollback authorization and rejected tampered content. Four real events reached JSONL and the exported-event counter was positive. Clean exits, no Go race report and no ASan/UBSan report; LSan is disabled, no leak/soak claim.

The first harness run failed because the sample IR scores SQLi at 5 while the engine threshold is 100. The generated transport fixture now explicitly sets that detector to `block_alone` and uses the existing native suite's SQLi payload. No shipped rule, policy, budget or fail mode was changed. The failed output is retained. This is transport/detector integration evidence, not a claim about the full core rule pack. The harness has no empty-bundle or compile-error fallback. It retains generated files under ignored build/ for diagnosis.

**Still pending:** repair/package the one-command installer and its systemd files, and prove clean-system installation plus rule compilation/update under the task's five-minute acceptance. The old installer harness can fall back to an empty bundle and only checks service/metrics health; that result is rejected as task acceptance.

## Signature preflight for packaging

Added `strata-agent verify-bundle --bundle-file ... --bundle-pubkey ...` to verify the signed header without installing/activating files. It reuses bounded bundle reads and a bounded (65-byte probe) trusted-key reader, accepts the existing one/two-key rotation format, honors cancellation and propagates command output errors. The watcher uses the same key reader. Engine section/layout checking remains the proxy's responsibility; this command does not replace `nginx -t` or authorize rollback.

Validation: direct and CLI tests cover valid/rotated/untrusted keys, missing arguments, short data, oversized keys, tampered signatures, cancellation and absence of activation side effects. `go test -race -count=1 ./cmd/strata-agent ./internal/standalone` passed (1.178s / 1.318s); agent lint reported 0 issues. This prepares safe installer preflight; it does not activate the unreviewed installer.

Further installer review found two additional blockers in the source: `${STRATA_STANDALONE_ARGS}` in systemd expands an aggregate argument incorrectly, and the reused socket unit is bound to `strata-agent.service` (fleet), so standalone socket activation/upgrade behavior needs its own verified service/socket handling. The prototype also never enables an inspection policy in a server/location. These are recorded as unfinished rather than importing a script that reports success without blocking a request.


## Packaged standalone service/socket acceptance

Standalone now has its own socket unit explicitly activating `strata-agent-standalone.service`, with conflicts against the Fleet pair on the same path. Parameters use one systemd EnvironmentFile value per argument; BUNDLE_SOURCE contains exactly one `--bundle-file=...` or `--bundle-url=...` argument, preserving spaces. There is no aggregate shell expansion or shell evaluation. The package ships disabled by default, with the existing service sandbox plus a dedicated logs directory.

Deb upgrade and RPM posttrans use a shared installed restart helper. An active/enabled standalone mode takes priority over a stale Fleet identity; its socket remains open while the process restarts. Otherwise the existing enrolled-Fleet path is selected. Restart errors propagate; removal disables/stops both mode pairs and preserves operator data. Source service/socket and environment defaults were rewritten, not copied verbatim. The Lite design section now records the implemented boundary without an instantaneous reload or clean-VM claim.

Built static agent with Go 1.26.9, packaged fresh test versions 0.0.1/0.0.2 using nfpm 2.43.1 for deb/rpm, then invoked `deploy/packaging/test/test-standalone-units.py` with the two packages, a signed compiler fixture and its public key. Fresh privileged Ubuntu 24.04 and Rocky 9 systemd containers each use `--network none`, no host systemd/Docker socket, no control plane or database:

- Final Debian run **PASS, 165/165 events, 27.881s**; RPM **PASS, 165/165 events, 27.381s**. Each checks package install/upgrade/removal, real unit validation, paths containing spaces in actual process argv, preserved environment/control digest/socket inode, restart PID change, socket activation, trusted node identity and no unexpected Fleet activation.
- Reproduced the source's aggregate `${STRATA_STANDALONE_ARGS}` pattern in an actual systemd oneshot: the trusted-key argument is swallowed into one bundle-file value and the CLI refuses it. The selected individual arguments start correctly.
- A signed bundle was fetched from a private loopback HTTP server using the URL source argument; the unit processed a further event and retained the control digest. This checks argument/source wiring, not external TLS or publisher availability.
- The Fleet branch of the package hook also restarts and retains its socket, using an explicit local sleep-process override. This checks mode/hook selection only; it is not an enrolled Fleet/control-plane regression chain.
- An initial own unit candidate passed both mutually exclusive source flags with one empty value; Cobra correctly refused it. The unit now passes exactly one source option. The red output and earlier file-only/upgrade receipts remain retained; no test or validation was disabled.

Evidence: [raw logs and image/package provenance](evidence/standalone-packaging/). Shell syntax, Python AST parse and diff whitespace pass. Product Go/Rust/C code and dependency pins are unchanged, so previous runtime race/sanitizer evidence is not claimed rerun here. Self-review: fresh packages start no mode automatically; trusted key mandatory; per-argument expansion handles spaces; bounded test waits; upgrade/removal exercised on both package managers; no secret/real credential, production access, shared state teardown or new dependency.

**Still outstanding:** safe one-command installer, actual core rule tooling/artifact, route activation and native SQLi/hot-rule-update proof on a clean installation. These systemd tests are not the five-minute VM acceptance. Source `9569d12` also inherits unreviewed W17–W19 content; that branch is preserved rather than acknowledging its whole tree by ancestry.


## Named-policy installation preflight

A valid signature alone cannot show that the policy named in the proposed NGINX route exists in the bundle. `verify-bundle` now optionally accepts `--policy` and `--require-enforce`. Selection is read from the same signed bytes: at most 4096 v1 policy entries, bounded offsets/table/section region, 1–55 byte lowercase ASCII names with zero padding, unique names and valid mode/canary. Requiring enforce rejects shadow and partial canary; it never edits policy. General signature-only verification remains compatible. The command still activates no file or service; [operator scope and example](../runbook/standalone.md).

New CLI positive cases failed before implementation with `unknown flag: --policy`. Final full agent `go test -race -count=1 ./...` passed (agent 11.588s, fallback 16.705s, standalone 1.379s, bundlefmt 1.374s); lint 0 issues and agent build passed. Focused verbose runs pass 24 bounds/name/mode cases, the valid 4096-entry boundary, compiler-generated/rotated-key fixtures, signature tampering and seven CLI options cases. A native compiled executable also verified the compiler fixture's named enforce policy. No original test removed or weakened.

A 10-second focused Go fuzz run passed **34,519 executions / 19 new interesting inputs** (11.054s including finish), with signatures regenerated so parsing is reached. The initial larger seed managed only six executions; it was replaced by a small policy-only seed to target this parser, with the real compiler fixture retained in deterministic tests. One initial style lint failure was corrected. All initial/final output is retained in [evidence](evidence/standalone-policy-preflight/); finite fuzzing is not a proof of defect absence.

Self-review: verification precedes interpretation of the table; count/offset/name/canary arithmetic is bounded; missing/ambiguous/malformed selection returns an error, no request path, activation, default budget/fail mode or shared bundle format change; no dependency/key material added. Full engine sections/Hyperscan/rule quality/NGINX mode still need runtime validation. This preflight does not yet pin the policy across later watcher updates; installer/watcher wiring remains the next step.
