CREATE TABLE outbound_settings (
    id integer PRIMARY KEY CHECK(id=1),
    audit_enabled boolean NOT NULL DEFAULT false,
    dropped bigint NOT NULL DEFAULT 0
);
INSERT INTO outbound_settings(id) VALUES(1);
CREATE TABLE outbound_deliveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK(kind IN ('audit','alert','report')),
    dedupe text NOT NULL CHECK(length(dedupe)<=160),
    audit_id bigint,
    payload jsonb CHECK(octet_length(payload::text)<=32768),
    state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','running','delivered','failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
    next_attempt timestamptz NOT NULL DEFAULT now(),
    lease_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    UNIQUE(kind,dedupe)
);
CREATE INDEX outbound_pending ON outbound_deliveries(state,next_attempt);
CREATE FUNCTION enqueue_outbound(p_kind text,p_dedupe text,p_audit bigint,p_payload jsonb) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE n integer;
BEGIN
    PERFORM pg_advisory_xact_lock(739905);
    IF EXISTS(SELECT 1 FROM outbound_deliveries WHERE kind=p_kind AND dedupe=p_dedupe) THEN RETURN true; END IF;
    DELETE FROM outbound_deliveries WHERE id IN (SELECT id FROM outbound_deliveries WHERE state IN ('delivered','failed') AND created_at<now()-interval '30 days' LIMIT 1000);
    SELECT count(*) INTO n FROM outbound_deliveries;
    IF n>=10000 THEN
        DELETE FROM outbound_deliveries WHERE id IN (SELECT id FROM outbound_deliveries WHERE state IN ('delivered','failed') ORDER BY created_at LIMIT 100);
        SELECT count(*) INTO n FROM outbound_deliveries;
    END IF;
    IF n>=10000 THEN UPDATE outbound_settings SET dropped=dropped+1 WHERE id=1; RETURN false; END IF;
    INSERT INTO outbound_deliveries(kind,dedupe,audit_id,payload) VALUES(p_kind,p_dedupe,p_audit,p_payload);
    RETURN true;
END $$;
CREATE FUNCTION queue_audit_copy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS(SELECT 1 FROM outbound_settings WHERE id=1 AND audit_enabled) THEN
        PERFORM enqueue_outbound('audit',NEW.id::text,NEW.id,NULL);
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER audit_outbound AFTER INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION queue_audit_copy();
