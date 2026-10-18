# Review RV-G1-01 — signed bundle foundation

Source: standalone prototype at `9569d12` (also included in `65d0ce2`). Decision: repair before selecting code. This PR adds an internal watcher package; CLI/installer activation and the clean-VM SQLi/hot-reload acceptance remain pending. It does not mark the whole task Done.

Three fresh regressions failed on the source: no trusted key was accepted; replacing a same-named source produced a control digest different from installed bytes; corrupt control state was silently discarded. The replacement requires a trusted Ed25519 key, verifies every bundle, persists content-addressed files with file/directory fsync before updating the existing control inode, rejects unsigned rollback and same-version content changes, and restores the active version across restart. The existing signed rollback flag remains supported.

File and HTTP reads are bounded by the existing fleet limit (1 GiB); directory scans stop above 4,096 entries. Empty HTTP bodies, HTTP errors, cancellation, tampered signatures and oversized sparse files are rejected. A corrupt control file is an initialization error. Network transport retains normal TLS verification; signed HTTP sources remain supported as specified by the prototype design.

Validation: `go test -race -count=1 ./internal/standalone ./internal/bundles ./pkg/bundlefmt` passed (1.187s / 1.858s / 1.070s); `golangci-lint run ./internal/standalone/...` passed. Raw red/green stdout is compressed alongside the branch-consolidation evidence. The synthetic test bundles prove signing/control behavior, not engine layout conformance or the clean-VM acceptance.

Self-review: errors propagate; untrusted data has explicit size/entry limits; no signing bypass or new dependencies; edits are limited to the selected agent package and review evidence. No staging/production access. Old immutable files are retained, so periodic operator retention is still needed; the directory cap fails visibly rather than deleting a bundle workers might still use. Runner cancellation/export lifecycle, CLI validation, packaging and clean-VM evidence are reviewed separately.
