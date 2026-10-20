# CP-B01 · Applications and scoped access

PostgreSQL remains authoritative; ClickHouse remains the event store. B03 is excluded.

Applications own environments, connector groups and exact host/path-prefix routes linked to
policy/schema references. Global operators configure this ownership graph; administrators
assign global, application or environment roles. Policies shared by several applications
require write/approve/deploy rights on every reference. Subject bindings are resolved on each
HTTP/gRPC authentication. Removing the last binding leaves the subject explicitly denied,
rather than restoring privileges from old token roles. Existing never-bound installations
retain global RBAC. Service token scopes remain an upper bound.

Every supported list/detail, event lookup, search, overview, geo and timeline applies scope.
HTTP/RPC allowlists deny unreviewed global endpoints. Application environment metadata is
filtered too. SSE authenticates and resolves bindings every poll and ends on revocation.
Route queries use raw ClickHouse data where rollups lack the necessary dimensions. Mixed
viewer/operator scopes conservatively mask sensitive fields across the combined query.
Node/group reads are limited; global bundle/rollout lists are withheld from scoped users.
A scoped deploy cannot publish another application's pending approved changes.

The UI exposes applications, ownership, environments/routes, linked policy intent and recent
configuration timestamps, event totals and role assignments. Coverage is explicitly unknown:
request counters do not have host/path dimensions, so scoped telemetry is `events_only`.
Absence of violation events never proves full inspection. Auth/me resolves roles and per-policy
permissions from the server; scoped users cannot see global administrative controls.
Schema IDs are references; this task does not introduce a schema registry.

Validation on CPUs 6–10, isolated PostgreSQL 17.11 / ClickHouse 25.8.33:

```text
go test -p 1 -race ./... (control-plane): exit 0, all packages passed
cmd/server 89.347s; ingest 27.919s; store 32.494s
go test -p 1 -race ./auth ./api ./ingest ./store ./policy: exit 0
api 23.413s; ingest 30.320s; policy 3.805s
```

New tests cover four roles × resource scopes, shared-policy write denial, last-binding
revocation, retries/etag, overlapping route ownership, environment metadata isolation,
Block ID/host/path/node IDOR, scoped overview/geo/timeline, empty scopes, SSE revocation and
aggregate deploy authorization. `golangci-lint run ./...`: exit 0, `0 issues.`

```text
UI lint/build: exit 0
Vitest: 31 files, 249 tests passed
Playwright: 19 passed (53.3s)
e2e FourEyes/MigrationsUpDownOnEmptyDatabase/PolicyEditAndDeploy:
ok github.com/strata/strata/tests/e2e 28.910s
```

OpenAPI clients regenerated. `git diff --check` clean. The first UI run found a missing Save
translation; fixed, then the complete UI suite passed. Mock browser tests log the existing
unconfigured auth-method proxy fallback; every assertion passed.

Limits: no benchmark or native C/Rust change; shared lab/staging/production untouched.
The selected e2e run is not a full native/fault rehearsal. Large app lists use keyset
pagination. Permission graph refuses more than 10,000 routes/nodes rather than widening scope.
The work is split into dependent PRs: auth → model → bindings → events → API → contract → UI.
The API/contracts slices are about 400 handwritten lines; generated clients excluded.

Self-review: error paths fail closed; input/body/list bounds explicit; writes have RBAC and
atomic audit; no credentials logged; scope is Compact B01; local race/lint/UI gates above.
