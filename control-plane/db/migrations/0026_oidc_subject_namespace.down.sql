CREATE OR REPLACE FUNCTION pg_temp.bare_subject(s text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN s LIKE 'oidc:%' THEN substr(s, 6) ELSE s END
$$;

UPDATE policy_versions SET
    created_subject   = pg_temp.bare_subject(created_subject),
    submitted_subject = pg_temp.bare_subject(submitted_subject),
    decided_subject   = pg_temp.bare_subject(decided_subject);
UPDATE event_annotations SET marked_subject = pg_temp.bare_subject(marked_subject);
UPDATE event_annotation_requests SET subject = pg_temp.bare_subject(subject);
UPDATE policy_edit_requests SET subject = pg_temp.bare_subject(subject);
UPDATE machine_requests SET subject = pg_temp.bare_subject(subject);
