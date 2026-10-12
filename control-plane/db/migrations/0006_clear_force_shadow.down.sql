DELETE FROM node_commands WHERE kind = 'CLEAR_FORCE_SHADOW';
ALTER TABLE node_commands DROP CONSTRAINT node_commands_kind_check;
ALTER TABLE node_commands ADD CONSTRAINT node_commands_kind_check
    CHECK (kind IN ('FORCE_SHADOW', 'DIAGNOSTICS'));
