# W17-R-01: selected SSTI component

Source `25e959e1b8f2d5a0fd6858033e0ab06889171b9a`, selected file
`engine/src/detectors/injection/ssti.rs`. Original suffix searches retry every
unclosed opener and grow quadratically; a 64 KiB input took **1.425s** in the
recorded optimized component run. Cached per-family closer cursors now advance
monotonically and remember exhaustion. The same input took **0.423ms** in that
run. These are local component observations, not proxy overhead or an SLO.

A second regression reproduces nested arithmetic probes being missed by the
source. The repaired component checks the innermost same-family suffix once,
without recursion or repeated prefix scans. Original attack/benign suites remain;
new tests cover malformed/mixed delimiters, large repeated expressions, arbitrary
bytes and a deterministic bound of three input lengths for closer-search work.
Keyword and expression scans cover disjoint slices with one optional suffix scan.

`cargo test -p libstrata --all-features`: **255 passed, 0 failed, 2 existing ignored**;
Clippy all targets/features with `-D warnings` and workspace fmt check pass. The
reproducer verifies the immutable source hash and expected negative-control exit
101, then proves all three nested regressions fixed. 100,000 deterministic inputs
lose no source detections and add 812 nested-expression detections. This corpus is
not a false-positive/recall acceptance campaign. [Raw output and reproducer](evidence/ssti-detector-review/).

No unsafe code, new dependency, allocation, recursion, FFI/IR/schema/bundle change,
or rule activation. This is a lexical component, not a complete template parser.
CMDi and compiler/operator integration remain unaccepted; the source W17/W21
branches and their unrelated feature content remain preserved. W17-R-01 is not
marked Done by this selection. Native request-path/sanitizer acceptance is still
required when the operator is wired into that path; this change adds no such path.
