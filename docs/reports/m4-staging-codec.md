# M4 — Bounded staging-overlay codec

Branch `codex/m4-staging-codec`, base PR #183 (`b6e3fe8`). Adds a safe Rust codec for the forthcoming signed per-policy log-only overlay. It is not emitted, parsed by Engine::map or used on requests yet; the active bundle format and C ABI are unchanged in this component.

`SSG1 | count u32 | count × (policy_index u32, rule_id u32)`, all little-endian. Empty settings emit no section. Encoding is canonical (policy then rule); reading requires canonical order and an exact match between represented policies and supplied compatibility flags. The later runtime integration must reserve the section/mandatory flag and verify existing managed request-rule membership. The codec alone never authorizes a policy change.

Bounds: 4,096 policies, 4,096 entries overall, 16 per policy (matching the approved delegation limit), nonzero Rule IDs and no duplicate pairs. Header/count/exact length checks happen before record allocation. Maximum section size is 32,776 bytes. Zero count, missing/trailing/truncated records, invalid indexes, duplicate/out-of-order records and missing/extra/duplicate flags are rejected.

Validation in the dev image, CPUs 6–10, offline dependency cache:

```sh
cargo fmt --all --check
cargo test --offline -p libstrata
cargo clippy --offline -p libstrata --all-targets --all-features -- -D warnings
```

**247 passed, 0 failed, 2 ignored**, across 16 test binaries/doc-test results. Three new codec tests include every truncation point, both sides of per-policy bounds, a separately constructed oversized-policy decoder input, oversized global/header counts, canonical round trip, maximum UInt32 Rule ID, default absence and malformed flags/records. Clippy and formatting pass. [Selected unmodified output lines](evidence/m4-staging-codec/checks.txt); complete local output remains `build/m4-staging-codec-clean.log`.

The initial formatter check required formatting the new file; clippy then requested `as_chunks` instead of constant-size `chunks_exact`. Both corrected and the full checks above rerun cleanly. No test was disabled. No new dependencies, unsafe code, request-path allocation or external state writes. Only engine codec/module registration and related evidence changed. No FFI/NGINX path invokes this codec yet; sanitizer activation coverage belongs to the runtime integration that will connect it. Hosted CI was not awaited and no main merge or deployment occurred.

Remaining M4: runtime/mandatory flag/compiler support, durable authorized automatic staging state, bundle derivation/audit notification and under-five-minute lab activation proof. No automatic re-enforcement.
