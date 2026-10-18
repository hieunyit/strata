# L4 — Refresh remediation evidence and open work

Base PR #182 (`d4d3fbc`), branch `codex/l4-m4-evidence-status`. `git ls-remote origin refs/heads/main` still reports `e93dc0b4da55ec93ccf3c0a9421cdf8ed0f51719`; no main merge or staging/production action.

Updates `docs/status.md` and the 26-row tracker with the durable M4 replacement (#169–#176), FP provenance (#180), approved opt-in metadata (#181), exact-bundle threshold evaluator (#182), M9 optional-store fix (#171), annotated 20M-event benchmark (#177), actual agent signature/kill proof (#178) and isolated graceful restart fixture (#179). M4 remains incomplete: no durable automatic writer/outbox, signed runtime overlay or under-five-minute activation proof. Large-body and saturated rate-table behavior remain measurement-only per user decisions.

H5 search was repeated read-only: metadata names/keys from 648 Actions artifact rows and 146 cache rows show no archive candidate; inventory of 15 worktrees found only three CRS markers and no ET archive/source. [Scope and summary](evidence/l4-m4-status/archive-inventory.json). Artifact/cache contents were not downloaded; this does not establish that every external backup is absent. Strict ET checksum remains unchanged. Hosted CI was neither launched through Actions nor awaited.

Validation: `git diff --check` passes; relative local links in these three edited reports checked for existence. No runtime code changed, so no additional test suite is needed. PO week pointer, other worktrees and deployment gates remain unchanged. Review component PRs in dependency order; stage3/stage4 integration bases are private and kept fixed.
