# M4 — Staging and signed-invalid bundles through the C ABI under ASan

Base PR runtime (`0ae7215`), branch `codex/m4-staging-ffi-evidence`. Adds the companion FFI test separated from the runtime PR for review size; no runtime changes.

The test maps a real signed overlay, creates/releases transactions through C ABI functions, submits request-line/header data and verifies log-only actions for selected rules while the other policy blocks. It releases all engines/transactions. Correctly signed negative-score, out-of-range-score and duplicate-ID artifacts must return a null engine with E_BUNDLE. Signature checks are active.

```sh
RUSTC_BOOTSTRAP=1 RUSTFLAGS='-Zsanitizer=address' ASAN_OPTIONS=detect_leaks=1 cargo test --offline --target x86_64-unknown-linux-gnu -p libstrata-ffi --test policy_staging
```

**1 passed, 0 failed, 0 ignored (0.03 s)**, AddressSanitizer and leak detection enabled ([output](evidence/m4-staging-ffi/asan.txt)). Bootstrap only enables sanitizer instrumentation for this isolated test build; production builds do not use it. The combined workspace with this test had **392 passed, 0 failed, 9 unchanged ignored**, clippy/format passed ([output segment](evidence/m4-staging-ffi/combined-workspace.txt.gz)). Runtime PR's separate 391 count excludes this test. [Source hashes](evidence/m4-staging-ffi/source.json) bind the exact restored test bytes and runtime files used by the checks.

The runtime's two rebuilt NGINX suites each passed 595 ASan/UBSan assertions; those use existing fixtures. This companion proves the new overlay at the FFI boundary, not real HTTP activation, Fleet distribution, an automatic writer, end-to-end event delivery, production stability or the five-minute SLA. Compiler/writer/outbox/audit notification remain pending.

Self-review: actual C ABI behavior and teardown tested; malformed signed inputs checked; no new dependencies/secrets/runtime interfaces; test/evidence scope only; area workspace lint clean. The test was temporarily held in ignored build storage to form the small parent PR, then restored byte-for-byte here; no existing test was removed or disabled. No hosted CI wait, main merge or deployment.
