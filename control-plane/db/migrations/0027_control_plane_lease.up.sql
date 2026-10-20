-- CP-A03: one control plane serves at a time (Compact). The Fleet state
-- (presence, canary monitor, per-policy request counts) lives in the memory
-- of one process, so a second control plane on the same database must not
-- take writes. The holder renews the lease; another process takes it only
-- once it expired. fencing grows by one at every takeover.
CREATE TABLE control_plane_lease (
    id          smallint PRIMARY KEY CHECK (id = 1),
    holder      text NOT NULL CHECK (holder <> ''),
    fencing     bigint NOT NULL CHECK (fencing > 0),
    renewed_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL
);
