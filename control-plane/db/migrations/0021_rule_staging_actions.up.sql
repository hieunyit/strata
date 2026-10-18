-- Append-only effective staging state and durable rollout intent. A row means
-- recorded, not ACTIVE: only the linked rollout and node ACKs establish that.
CREATE TABLE rule_staging_actions (
    id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
    policy_id text NOT NULL,
    policy_version integer NOT NULL,
    rule_id bigint NOT NULL CHECK (rule_id BETWEEN 1 AND 4294967295),
    source_bundle bigint NOT NULL REFERENCES bundles (version),
    bundle_version bigint NOT NULL UNIQUE REFERENCES bundles (version),
    matches numeric(20,0) NOT NULL CHECK (matches BETWEEN 1 AND 18446744073709551615),
    reports numeric(20,0) NOT NULL CHECK (reports BETWEEN 1 AND matches),
    window_from timestamptz NOT NULL,
    window_to timestamptz NOT NULL,
    request_digest bytea NOT NULL CHECK (length(request_digest) = 32),
    rollout_id bigint UNIQUE REFERENCES rollouts (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (policy_id, policy_version) REFERENCES policy_versions (policy_id, version),
    UNIQUE (policy_id, policy_version, rule_id),
    CHECK (bundle_version = source_bundle + 1),
    CHECK (window_to > window_from AND window_to - window_from <= interval '24 hours')
);
CREATE INDEX rule_staging_actions_pending ON rule_staging_actions (bundle_version) WHERE rollout_id IS NULL;
