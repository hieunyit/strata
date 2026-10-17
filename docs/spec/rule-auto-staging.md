# Automatic rule staging: approved opt-in contract

The operator explicitly proposed this delegation on 2026-10-17: automatic reduction to staging may be configured in an approved policy, default off. This setting follows the existing policy version, replay, submit, independent approval and deployment flow. A draft alone grants no authority. It never grants automatic re-enforcement.

`PolicySpec.auto_staging` is control-plane authorization metadata. Omitted or `{ "enabled": false }` is off. A fully configured disabled object can retain its parameters for a later reviewed version. Every supplied configuration must be bounded and valid; no implicit thresholds are installed.

```json
{
  "enabled": true,
  "rule_ids": [942100],
  "window_seconds": 300,
  "min_matches": 100,
  "min_reports": 5,
  "fp_threshold_bps": 500
}
```

These values illustrate syntax; they are not calibrated recommendations. The explicit allowlist contains 1–16 distinct nonzero Rule IDs. Activation must additionally prove each exists in the managed layer of the exact approved compiler inputs. Membership is not guessed from the numeric ID range. The window is 60–86,400 seconds; `1 <= min_reports <= min_matches <= 1,000,000,000`; threshold is 1–10,000 basis points (500 means 5%).

Evaluation must bind both counts to the active policy and bundle and one decision-time cohort. Count only new first FP reports inside the configured time window, with exactly one distinct matched rule, excluding ambiguous multi-rule events, unknown bundle 0 and legacy annotations without provenance. Rewriting a report reason cannot advance its initial time or move its bundle/rule evidence. Zero denominator, inconsistent snapshots, query failures and unapproved/stale inputs cannot authorize action. The share is reports over stored matched security events; it is not a measured FP rate across all requests.

The replay input digest includes this metadata through the complete stored policy spec, although it is not itself an engine setting. Changing enabled, thresholds, rule IDs or other parameters changes the digest. The normal policy API and generated clients carry it; policy edits preserve it and the advanced approval diff exposes it.

Implementation status in this component PR: validated/versioned API metadata, round trip and replay digest binding. The evaluator, durable staging state/outbox, signed runtime overlay and activation deadline proof are separate subsequent changes. No automation runs from this configuration yet. Existing deployment gates remain in force. The runtime overlay must retain detection and logging, suppress only the selected rule's enforcement contribution in the selected policy, and reject unsupported engines. A later approved policy change is required for recovery; the automatic worker cannot restore enforcement.
