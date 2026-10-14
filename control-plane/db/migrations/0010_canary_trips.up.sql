-- Cluster tier of the automatic fallback (W12-G2-01): a connector group
-- whose canary group did worse than its shadow group, and the canary
-- policies forced into shadow on every node of the group. The trip holds
-- (the control plane renews the ForceShadow commands) until clearForceShadow
-- removes its policies; at most one open trip per group.
CREATE TABLE canary_trips (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_id    text NOT NULL REFERENCES connector_groups (id),
    reason      text NOT NULL CHECK (reason IN ('block_rate', 'upstream_5xx', 'latency')),
    detail      jsonb NOT NULL DEFAULT '{}',
    policies    text[] NOT NULL CHECK (cardinality(policies) <= 64),
    tripped_at  timestamptz NOT NULL,
    renewed_at  timestamptz NOT NULL,
    cleared_at  timestamptz,
    cleared_by  text
);

CREATE UNIQUE INDEX canary_trips_open ON canary_trips (group_id) WHERE cleared_at IS NULL;
