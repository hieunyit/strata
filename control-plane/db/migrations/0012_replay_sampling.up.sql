-- Replay sampling per connector group (W12-N-01): the share of requests
-- the nodes sample and the HMAC key their samples are anonymized with
-- (docs/spec/replay-sample.md). The key never goes into node_commands: a
-- REPLAY_SYNC command carries nothing, the dispatcher reads this row when
-- it sends it.
CREATE TABLE replay_sampling (
    group_id    text PRIMARY KEY REFERENCES connector_groups (id),
    rate_bp     integer NOT NULL CHECK (rate_bp BETWEEN 0 AND 10000),
    key_id      text NOT NULL CHECK (key_id ~ '^[A-Za-z0-9._-]{1,16}$'),
    key         bytea NOT NULL CHECK (length(key) = 32),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL
);

ALTER TABLE node_commands DROP CONSTRAINT node_commands_kind_check;
ALTER TABLE node_commands ADD CONSTRAINT node_commands_kind_check
    CHECK (kind IN ('FORCE_SHADOW', 'CLEAR_FORCE_SHADOW', 'DIAGNOSTICS',
                    'DISABLE_RULES', 'SET_DISABLED_RULES', 'ENABLE_RULES', 'REPLAY_SYNC'));
