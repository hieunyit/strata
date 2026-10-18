# Canary 25% observation checklist

Prepared procedure, not an executed 72-hour observation. Gate A, a reviewed pack, accepted 1%/5% observations and operator authorization are prerequisites. Do not enable this on staging/production as part of branch consolidation.

A policy Spec/IR fragment can use `{"mode":"enforce","canary_percent":25}`. This is not a complete REST update request: preserve the current full spec and etag, create a draft, replay it, inspect the report, obtain independent approval bound to that report, then deploy the approved version. Do not replace existing body/fail-mode/privacy/exception settings with a shortened example. REST/proto enum JSON uses its documented representation. `fail_on_findings: "block"` is a valid Spec/IR value, but changing it is a separate policy decision.

The stable canary hash selects clients by basis points: 25% means 2,500/10,000 buckets. This does not promise exactly 25% of a small or uneven traffic sample. Identify policy, connector group, approved version, artifact digest, start time and observation owner in the run record.

Observe application HTTP errors/latency and WAF inspection completeness separately. The agent exposes `strata_requests_total{action="block"}` and `strata_canary_requests_total{group="canary"}` / `group="shadow"`; these counters are not automatically per-policy HTTP 5xx rates. Use the application/proxy metrics actually deployed and policy-filtered event/inspection views. A high block rate alone does not establish false positives.

M4 automatic log-only staging is disabled unless delegated by an independently approved policy. It uses the configured evidence thresholds and source guards, not an unconditional “five FP reports” rule. Automatic reduction of the canary percentage based on HTTP 5xx is not implemented by this checklist. Fallback and policy changes require the existing authorized API/workflow; record reason, operator and resulting version/state.

If inspection completeness, confirmed FP, origin availability or latency violates the approved rollout guardrails, pause expansion and apply the agreed fallback. Verify worker metrics and last-known-good artifact behavior rather than assuming an HTTP 200 means every node changed. Collect raw telemetry/audit and observe continuously for the approved duration. Do not prefill a production FP ratio, claim fourteen days of enforce or sign Gate B without that evidence.
