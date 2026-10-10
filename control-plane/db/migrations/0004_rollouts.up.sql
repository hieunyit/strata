-- Bundle rollouts in waves (nginx-module.md › Phân phối bundle): a deploy
-- creates one; a wave's nodes are told the new version, and the next wave
-- starts only when every node of this one reports ACTIVE. FAILED stops it.
CREATE TABLE rollouts (
    id              bigserial PRIMARY KEY,
    bundle_version  bigint NOT NULL REFERENCES bundles (version),
    state           text NOT NULL DEFAULT 'RUNNING'
                    CHECK (state IN ('RUNNING', 'PAUSED', 'FAILED', 'DONE', 'ABORTED')),
    -- cumulative node counts: wave i covers nodes [waves[i-1], waves[i])
    waves           jsonb NOT NULL,
    current_wave    integer NOT NULL DEFAULT 0,
    soak_seconds    integer NOT NULL DEFAULT 0 CHECK (soak_seconds >= 0),
    wave_done_at    timestamptz, -- when every node of the current wave was ACTIVE
    reason          text NOT NULL DEFAULT '',
    created_by      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX rollouts_running ON rollouts (state) WHERE state IN ('RUNNING', 'PAUSED');

CREATE TABLE rollout_nodes (
    rollout_id  bigint NOT NULL REFERENCES rollouts (id) ON DELETE CASCADE,
    node_id     text NOT NULL REFERENCES nodes (id),
    wave        integer NOT NULL,
    state       text NOT NULL DEFAULT 'PENDING'
                CHECK (state IN ('PENDING', 'NOTIFIED', 'DOWNLOADING', 'VERIFIED', 'ACTIVE', 'FAILED')),
    error       text NOT NULL DEFAULT '',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rollout_id, node_id)
);

-- The version a node should run: set when its wave starts; FetchBundle
-- serves only this version to the node.
ALTER TABLE nodes ADD COLUMN desired_bundle_version bigint;
