# W17-R-01: SSTI compiler/runtime integration

Base main `9384efd`. The earlier SSTI component was unreachable from rule IR.
`detect_ssti` is now appended as opcode **18**, preserving all previous 0–17
codes. IR forbids a value; compiler charges semantic cost 10 (41 units for the
fixture's unkeyed args target), and the evaluator handles transforms/negation
through its existing path. No shipped/default rule is enabled, no dependency or
C ABI/layout/section changes. Design/IR documentation records module-first rollout.

The new integration tests failed on the base: schema/operator support missing.
They now compile/sign/map an actual bundle and assert query/form/ERB/arbitrary-byte
attacks, benign/malformed inputs, deep nesting, shadow LOG versus enforce BLOCK,
missing-target negation, schema negatives and legacy opcode stability. Test-only
rule 800817 is in compiler examples, not a production pack.

Validation: libstrata/compiler/FFI `--all-features` **391 passed, 0 failed, 9 existing
ignored**; all-target/all-feature Clippy `-D warnings` and fmt pass. Regenerating
old signed NGINX fixtures changes no bytes. Rebuilt the actual test-hooks archive
and both NGINX ASan/UBSan modules with warning-as-error flags before tests:
**1.30.5: 3 files / 75 tests PASS** (rules/SSTI/fail modes); **1.31.6: full 21 files /
616 tests PASS**, HTTP/3 suite skipped because its binary is not configured.
No ASan/UBSan report; LSan disabled by the existing harness. These are local tests.

The retained pre-change release module (SHA-256 in receipt) rejects the validly
signed new bundle with **bad condition record**, proving the upgrade prerequisite
rather than silent rule omission. [Raw logs/receipts](evidence/w17-ssti-runtime/)
retain the expected red result and two corrected test-authoring mistakes (field
name and shadow action expectation). CMDi/PL2/JA4 and the other W17–W21 work remain
open; this is not complete weekly or production/Gate acceptance.
