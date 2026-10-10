-- What each bundle was built from: policy id -> version.
ALTER TABLE bundles ADD COLUMN contents jsonb NOT NULL DEFAULT '{}';
