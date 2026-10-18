ALTER TABLE audit_log ADD COLUMN subject text NOT NULL DEFAULT '';
CREATE INDEX audit_log_actor_at_id ON audit_log (actor, at DESC, id DESC);
