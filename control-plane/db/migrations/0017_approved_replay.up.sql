ALTER TABLE policy_versions ADD COLUMN approved_replay_id text REFERENCES operations(id);
ALTER TABLE bundles ADD COLUMN input_digest text NOT NULL DEFAULT '';
