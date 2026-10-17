# M4 — Signed per-policy log-only runtime

Base PR #184 (`649f09f`), branch `codex/m4-log-only-runtime`. Section 11 `STAGING` and mandatory bit 5 of policy byte 62 carry the bounded SSG1 overlay. Old engines reject the bit. Engine loading requires exact flags/entries and a unique existing managed request Rule ID with score 0..1000; unknown, response/protocol, duplicate-ID and invalid-score references fail. A correctly signed negative-score fixture reproduced acceptance before this guard; removing a negative contribution could increase blocking.

Selected rules retain detection and logs while their scores/block_alone stop enforcing only in the selected policy. Healthy rules continue enforcing, including after a staged finding. Hypothetical `would_block` includes staged plus enforced scores; a staged-only finding cannot trigger fail_on_findings. Match tracing retains the existing 16-entry bound. No C ABI signature, dependency, CPU budget or saturation policy changed. Settings default absent/off; no compiler/API automatically emits an overlay yet.

Validation: `cargo fmt --all --check`; `cargo test --offline --workspace --all-features` **391 passed / 0 failed / 9 unchanged ignored**; workspace clippy with all targets/features and `-D warnings` passed ([full compressed output](evidence/m4-log-only-runtime/core.txt.gz)). Tests include policy isolation, retained match/event IDs, mixed scores, block_alone, healthy blocking after a staged match, budget fail-closed semantics, score boundaries, signed malformed records and flag/membership mismatch.

Rebuilt then tested NGINX **1.30.5: 595 PASS (154 s)** and **1.31.6: 595 PASS (153 s)**, ASan/UBSan, no sanitizer reports ([output segment](evidence/m4-log-only-runtime/native.txt.gz)). These use the existing NGINX fixtures; they do not prove new-overlay HTTP activation. `make check-header` passed; `make check-fixtures abi-test` passed after read-only mounting linked-worktree Git metadata ([output](evidence/m4-log-only-runtime/fixture-abi.txt)). The first combined run reached check-fixtures but failed because Git metadata was absent from the container; no fixture diff was hidden. ABI deliberate-panic output is the expected isolation test.

The former unknown-bit tests now reject bit 6 because M4 assigns bit 5; assertions remain. Initial handcrafted contains fixtures lacked compiler-generated Hyperscan images; replaced with self-contained numeric conditions, preserving verdict expectations. [Invalid signed-rule red regression](evidence/m4-log-only-runtime/signed-invalid-red.txt). A new C ABI staging/ASan regression is split into the companion test PR to keep reviews small; this report's 391 count excludes that test.

Self-review:
- Completion evidence: commands and actual outputs above; activation SLA not claimed.
- Error paths: malformed/signed-invalid metadata returns E_BUNDLE; no production unwrap/unsafe added.
- Bounds: overlay 4096 entries/16 per policy; no request-path I/O or locks.
- Security: signed scope and monotone positive-score suppression; no credentials/PII added.
- Scope: engine runtime/bundle, related tests and exact interface documentation.
- Lint: workspace clippy/format clean; no dependencies or tests disabled.

Remaining M4: compiler emission, durable approved-version-bound derivation/outbox/audit notification, and real HTTP activation within five minutes. No automatic re-enforcement, main merge, staging/production access or hosted CI wait.
