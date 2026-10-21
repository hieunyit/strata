ALTER TABLE bundles ADD COLUMN required_capabilities jsonb NOT NULL DEFAULT '[]';
