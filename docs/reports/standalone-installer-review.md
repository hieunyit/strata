# RV-G1-01 standalone installer selection

Source `46f3d0a`/`9569d12`; inherits reviewed #230–235 and #247–250. Selected
installer requires trusted local packages/key, signed named full-enforce bundle,
isolated native preflight and explicit route. Control readiness checks stable
generation and SHA-256. It refuses existing Fleet/active state; activation failure
stops its pair and restores nginx.conf. OS rollback/migration is not provided.

Real release packages built from `a635da1` (no test hooks), 212 unchanged core
rules through strata-rules; update adds only a test fixture Rule 199999. Ubuntu:
**PASS, 48.378s install / 108.590s harness / 5 events**. Rocky: **PASS, 16.730s /
61.284s / 5 events**, with `--rpm-nginx-repo-only` lab option because existing OS
dependencies suffice; no dependency/signature verification disabled. Default OS
mirror failures are retained, not counted as passes. Keyring umask, missing cmp
and binary-config scan failures were repaired. [Raw evidence/receipts](evidence/standalone-installer/).

Tests cover benign/SQLi, changed rule behavior, stable worker PIDs, invalid signed
metadata/layout, tamper/rollback, hostile/oversized inputs and failed activation.
ShellCheck/syntax/Python AST/diff/package hashes pass. No Go/C/Rust/interface/rule
change or dependency added; errors/copies/polls bounded, no unsigned fallback.
No hosted CI waited. Clean VM/five-minute acceptance is **unproven**; no Done/Gate
change. Source branch retained for inherited W17–W19 disposition. Runbook follows.
