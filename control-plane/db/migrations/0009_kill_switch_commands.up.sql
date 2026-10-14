-- Emergency kill switch (W12-G1-02): commands that disable or enable rules
-- on a node, with the rule IDs they name.
ALTER TABLE node_commands ADD COLUMN rule_ids integer[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(rule_ids) <= 480);
ALTER TABLE node_commands DROP CONSTRAINT node_commands_kind_check;
ALTER TABLE node_commands ADD CONSTRAINT node_commands_kind_check
    CHECK (kind IN ('FORCE_SHADOW', 'CLEAR_FORCE_SHADOW', 'DIAGNOSTICS',
                    'DISABLE_RULES', 'SET_DISABLED_RULES', 'ENABLE_RULES'));
