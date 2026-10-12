-- Commands sent to one node through its Connect stream (W07-G1-01):
-- ForceShadow and CollectDiagnostics. A control plane sends the PENDING
-- commands of the nodes connected to it; the agent's CommandResult closes
-- them. A command not answered by expires_at is EXPIRED.
CREATE TABLE node_commands (
    id                text PRIMARY KEY,
    node_id           text NOT NULL REFERENCES nodes (id),
    kind              text NOT NULL CHECK (kind IN ('FORCE_SHADOW', 'DIAGNOSTICS')),
    policy_id         text NOT NULL DEFAULT '',
    duration_seconds  integer NOT NULL DEFAULT 0 CHECK (duration_seconds BETWEEN 0 AND 86400),
    state             text NOT NULL DEFAULT 'PENDING'
                      CHECK (state IN ('PENDING', 'SENT', 'DONE', 'FAILED', 'EXPIRED')),
    error             text NOT NULL DEFAULT '',
    output            text NOT NULL DEFAULT '',
    created_by        text NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX node_commands_open ON node_commands (node_id, created_at) WHERE state IN ('PENDING', 'SENT');
CREATE INDEX node_commands_recent ON node_commands (created_at DESC);
