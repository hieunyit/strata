# Header rule candidates — pending content review

These three files are preserved byte-for-byte from `a71046e` and intentionally excluded from main in PR #220. This branch replaces the overlapping candidate branches from PR #133/#136; it is a draft, not an approved pack release.

- 300011: guarded libinjection detection in custom headers.
- 300012: XSS markup/JavaScript expression detection in custom headers.
- 300013: bounded SQL JSON-function predicates in custom headers.

Existing scoped evidence: [tracker H7](remediation-tracker.md), [Chromium oracle](h7-browser-oracle.md). Header SQLi 8/8, XSS 54/56, benign 47/47 on the selected fixture; these numbers do not establish application-wide recall or production FP. Full-pack performance measurements with these candidates have a different rule set from main's 9,064-rule pack. Large-body budget and application-context coverage remain unresolved.

Required before accepting: the rule-content review by the S reviewer required in AGENTS.md; review of false positives from decoding arbitrary headers and the regex-only alternatives; explicit cost/coverage decision for a release. No reviewer identity or approval is fabricated here. Schema and match/no_match checks will be recorded separately and do not replace that review.

Fresh local checks: `strata-rules lint --repo /src /src/rules/gaps` and `strata-rules test --repo /src /src/rules/gaps` PASS for all 13 gap rules; the three candidates contribute 31 match/no_match requests through the real compiler/engine. [Raw output](evidence/header-rule-candidates/checks.log.gz). Source candidate files remain byte-identical to a71046e. These checks do not grant release approval.
