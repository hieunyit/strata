DELETE FROM node_commands WHERE kind IN ('DISABLE_RULES', 'SET_DISABLED_RULES', 'ENABLE_RULES');
ALTER TABLE node_commands DROP CONSTRAINT node_commands_kind_check;
ALTER TABLE node_commands ADD CONSTRAINT node_commands_kind_check
    CHECK (kind IN ('FORCE_SHADOW', 'CLEAR_FORCE_SHADOW', 'DIAGNOSTICS'));
ALTER TABLE node_commands DROP COLUMN rule_ids;
