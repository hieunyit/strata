-- A rule ID keeps its policy owner across versions and concurrent draft edits.
CREATE TABLE policy_geo_rule_ids(rule_id integer PRIMARY KEY CHECK(rule_id BETWEEN 190000 AND 199999),policy_id text NOT NULL);
INSERT INTO policy_geo_rule_ids(rule_id,policy_id)
SELECT DISTINCT ON ((r->>'id')::integer) (r->>'id')::integer,policy_id
FROM policy_versions v CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(v.spec->'geo_rules')='array' THEN v.spec->'geo_rules' ELSE '[]'::jsonb END) r
WHERE r->>'id' ~ '^19[0-9]{4}$' ORDER BY (r->>'id')::integer,policy_id;
CREATE FUNCTION reserve_policy_geo_ids() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r jsonb; rid integer; own text;
BEGIN
 IF jsonb_typeof(NEW.spec->'geo_rules') IS DISTINCT FROM 'array' THEN RETURN NEW; END IF;
 PERFORM pg_advisory_xact_lock(741003);
 FOR r IN SELECT value FROM jsonb_array_elements(NEW.spec->'geo_rules') LOOP
  IF r->>'id' ~ '^19[0-9]{4}$' THEN
   rid := (r->>'id')::integer;
   INSERT INTO policy_geo_rule_ids(rule_id,policy_id) VALUES(rid,NEW.policy_id) ON CONFLICT DO NOTHING;
   SELECT policy_id INTO own FROM policy_geo_rule_ids WHERE rule_id=rid;
   IF own<>NEW.policy_id THEN RAISE EXCEPTION 'geo rule ID belongs to another policy' USING ERRCODE='23505'; END IF;
  END IF;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER policy_geo_id_guard BEFORE INSERT OR UPDATE OF spec ON policy_versions FOR EACH ROW EXECUTE FUNCTION reserve_policy_geo_ids();
