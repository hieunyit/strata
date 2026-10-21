CREATE TABLE exception_maintenance (
 policy_id text NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
 source_version integer NOT NULL, source_etag text NOT NULL,
 expired_ids text[] NOT NULL CHECK(cardinality(expired_ids) BETWEEN 1 AND 128),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','drafted','superseded')),
 etag text NOT NULL DEFAULT gen_random_uuid()::text,
 draft_version integer CHECK(draft_version IS NULL OR draft_version>source_version),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(policy_id,source_version),FOREIGN KEY(policy_id,source_version) REFERENCES policy_versions(policy_id,version),
 FOREIGN KEY(policy_id,draft_version) REFERENCES policy_versions(policy_id,version),
 CHECK(state<>'drafted' OR draft_version IS NOT NULL)
);
-- No new root-path exception can enter through another policy write endpoint.
-- Identical legacy entries may be carried forward until explicitly removed;
-- changing their expiry/scope is a new broad grant and is rejected.
CREATE FUNCTION guard_broad_policy_exceptions() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e jsonb;
BEGIN
 IF jsonb_typeof(NEW.spec->'exceptions') IS DISTINCT FROM 'array' THEN RETURN NEW; END IF;
 FOR e IN SELECT value FROM jsonb_array_elements(NEW.spec->'exceptions') LOOP
  IF e->>'path'='/' AND NOT EXISTS(SELECT 1 FROM policy_versions history WHERE history.policy_id=NEW.policy_id AND history.version<NEW.version AND history.spec->'exceptions' @> jsonb_build_array(e)) THEN
   RAISE EXCEPTION 'exception: new root-path grants are too broad' USING ERRCODE='23514';
  END IF;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER broad_policy_exception_guard BEFORE INSERT OR UPDATE OF spec ON policy_versions FOR EACH ROW EXECUTE FUNCTION guard_broad_policy_exceptions();
