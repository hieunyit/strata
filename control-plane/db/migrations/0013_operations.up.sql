-- Long-running operations of the admin API (W13-G2-01): for now the replay
-- of a policy version against the traffic samples (GET /v1/operations/{id}).
-- A control plane claims PENDING rows with FOR UPDATE SKIP LOCKED, so that
-- several control planes share the queue; a RUNNING row whose control plane
-- stopped is failed after the replay timeout.
CREATE TABLE operations (
    id           text PRIMARY KEY CHECK (id ~ '^op-[0-9a-f]{24}$'),
    kind         text NOT NULL CHECK (kind IN ('REPLAY')),
    policy_id    text NOT NULL,
    version      integer NOT NULL,
    state        text NOT NULL DEFAULT 'PENDING'
                 CHECK (state IN ('PENDING', 'RUNNING', 'DONE', 'FAILED')),
    error        text NOT NULL DEFAULT '',
    -- the replay report (control-plane/replay.Report); NULL until DONE
    result       jsonb,
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    FOREIGN KEY (policy_id, version) REFERENCES policy_versions (policy_id, version) ON DELETE CASCADE
);

CREATE INDEX operations_pending ON operations (created_at) WHERE state = 'PENDING';
CREATE INDEX operations_version ON operations (policy_id, version, created_at DESC);
