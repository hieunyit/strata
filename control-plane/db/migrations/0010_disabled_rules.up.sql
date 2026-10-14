-- Emergency kill switch (W12-G2-02): the rules switched off per connector
-- group. Every node of the group gets the list when it connects, so a node
-- that was offline when a rule was disabled catches up.
CREATE TABLE disabled_rules (
    group_id    text NOT NULL REFERENCES connector_groups (id),
    rule_id     integer NOT NULL CHECK (rule_id > 0),
    reason      text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, rule_id)
);
