# Operations entry points

Use the implemented interfaces and the status of the current checkout. This guide replaces configuration examples from the older architecture branch that named unsupported directives and assumed a public package repository.

- Installation/package layout: [installation runbook](../runbook/install.md), `deploy/packaging/`, `connectors/nginx/README.md`.
- Module directives and fail-mode behavior: [NGINX design](../design/nginx-module.md), `connectors/nginx/src/ngx_http_strata_module.c`. In particular, enabling the module uses `strata on`; do not copy `strata_engine` from the retired guide.
- Policy editing/review: the policy editor saves a draft; review shows an explicit version, replay report and diff. Submit, independent approval and deployment remain distinct operations. The API checks permissions and report provenance; the UI cannot authorize its own write.
- Block ID investigation: open the event, inspect matched rules and inspection status. Operators/admins can record a false-positive classification; a scoped exception is a separate draft that must pass replay/approval/deployment. A classification alone is not a deployment command.
- Emergency virtual patch: [tested workflow](../runbook/virtual-patch.md). Preserve rule provenance and required content review.
- Canary: [25% observation checklist](../runbook/canary-25.md). Gate and traffic prerequisites must be satisfied by operators; merging code does not advance rollout percentage.
- Fault drills: [game-day scope and evidence](../runbook/game-day.md). Component tests and actual operational recovery are recorded separately.

For an isolated developer lab, use the repository's `deploy/dev/run.sh` and `deploy/lab/` scripts. Their credentials and generated artifacts belong to the lab; do not substitute real staging credentials or infer that changing a Git branch upgrades a running node.

Before acting on a dashboard, check whether the value is a measurement, estimate, event-only count or unavailable. An event count is not request throughput; sampled rule timings are not a full engine latency distribution. Missing timing data must not become an invented p99 or an SLA-success badge.
