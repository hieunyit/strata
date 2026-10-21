-- Older snapshots remain distinguishable; scoped reads fail closed when they
-- cannot establish route ownership. New values come from the stored event.
ALTER TABLE rule_annotation_context ADD COLUMN node_id text NOT NULL DEFAULT '' CHECK(length(node_id)<=128),
 ADD COLUMN http_host text NOT NULL DEFAULT '' CHECK(length(http_host)<=253),
 ADD COLUMN http_path text NOT NULL DEFAULT '' CHECK(length(http_path)<=2048);
