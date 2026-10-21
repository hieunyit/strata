DROP TRIGGER audit_outbound ON audit_log;
DROP FUNCTION queue_audit_copy();
DROP FUNCTION enqueue_outbound(text,text,bigint,jsonb);
DROP TABLE outbound_deliveries;
DROP TABLE outbound_settings;
