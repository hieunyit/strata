-- CP-SEC-01: OIDC principals get their own namespace, "oidc:" and the
-- token's sub (local accounts are "local:", service accounts "sa:"). Before
-- this an IdP could issue a sub such as "local:admin" and pass for that
-- local account in four eyes, idempotency and ownership checks.
-- Stored subjects without one of the three prefixes came from OIDC tokens.
-- audit_log keeps what was recorded: entries before this migration carry
-- the bare sub. role_bindings is left as it is: its subject column mixes
-- bare OIDC subs and service account ids, and no code reads it yet; whoever
-- first uses it stores namespaced subjects.
CREATE OR REPLACE FUNCTION pg_temp.oidc_subject(s text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN s IS NULL OR s = '' OR s LIKE 'local:%' OR s LIKE 'sa:%' OR s LIKE 'oidc:%'
                THEN s ELSE 'oidc:' || s END
$$;

-- one statement per table: the four-eyes CHECK sees the three columns together
UPDATE policy_versions SET
    created_subject   = pg_temp.oidc_subject(created_subject),
    submitted_subject = pg_temp.oidc_subject(submitted_subject),
    decided_subject   = pg_temp.oidc_subject(decided_subject);
UPDATE event_annotations SET marked_subject = pg_temp.oidc_subject(marked_subject);
UPDATE event_annotation_requests SET subject = pg_temp.oidc_subject(subject);
UPDATE policy_edit_requests SET subject = pg_temp.oidc_subject(subject);
UPDATE machine_requests SET subject = pg_temp.oidc_subject(subject);
