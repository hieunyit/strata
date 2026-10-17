# M4 — actual reviewer browser proof on a private lab

Branch `codex/m4-reviewer-notices-browser`, based on PR #201 (`66e45df`).

Chromium logs in through the real local-auth service (random password, real salted hashes/sessions), reads the real notice API/PostgreSQL rows, opens English/Vietnamese notices and checks the panel stays inside a 390-pixel viewport. A second login as viewer sees no notification control, and a direct authenticated request gets 403. No API responses/authentication are mocked. Browser requests to any other origin are aborted and asserted absent. Trace/video are disabled so session/password traffic is not persisted.

The fixture seeds historical notice metadata; it does not approve a policy, deploy a bundle or prove automatic WAF activation. It uses an isolated test database, ephemeral loopback server and explicit container network/host mount. It cannot default to shared lab ports/credentials. A new output directory is required. Existing API read fixtures are factored without changing their assertions.

Results: Chromium **1 passed, 8.8 s**, race-enabled Go/browser fixture **16.699 s**; full API race area **9.320 s**, lint **0 issues**. [Recorded output](evidence/m4-reviewer-notices-browser/checks.txt), [source/image hashes and scope](evidence/m4-reviewer-notices-browser/metadata.json).

Screenshots inspected: [English](evidence/m4-reviewer-notices-browser/reviewer-en.png), [Vietnamese](evidence/m4-reviewer-notices-browser/reviewer-vi.png), [390px](evidence/m4-reviewer-notices-browser/reviewer-mobile.png). Large count text wraps, controls and labels are visible, and pending rollout is not labeled ACTIVE. The background fleet/events are empty in this read fixture.

Reproduce after building the UI to a private directory: run `TestStagingNoticeBrowserLab` with `STRATA_TEST_POSTGRES_DSN` for a disposable database, `STRATA_BROWSER_HOST_REPO`, `STRATA_BROWSER_NETWORK`, `STRATA_BROWSER_UI_BUILD` and new `STRATA_NOTICE_EVIDENCE_DIR`. The dev container needs its own Docker socket/CLI access; the browser image is Playwright v1.64.0. No tokens/private keys are copied to evidence.

Self-review: fixture-only lab scope, actual authorization, bounded browser deadline, private test data, no dependencies or enforcement changes; existing tests retained. The actual ClickHouse/replay/agent/NGINX activation chain under five minutes remains the open M4 acceptance check.
