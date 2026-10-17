-- Do not backfill: old event context does not prove initial report time or bundle.
ALTER TABLE rule_annotation_context
 ADD COLUMN first_reported_at timestamptz,
 ADD COLUMN report_policy_id text CHECK (length(report_policy_id) <= 55),
 ADD COLUMN report_event_at timestamptz,
 ADD COLUMN report_rule_ids bigint[] CHECK (
  cardinality(report_rule_ids) BETWEEN 0 AND 64 AND array_position(report_rule_ids,NULL) IS NULL AND
  0 < ALL(report_rule_ids) AND 4294967295 >= ALL(report_rule_ids)),
 ADD COLUMN report_bundle_version numeric(20,0) CHECK (report_bundle_version BETWEEN 0 AND 18446744073709551615),
 ADD CONSTRAINT complete_rule_report CHECK (num_nonnulls(first_reported_at,report_policy_id,report_event_at,report_rule_ids,report_bundle_version) IN (0,5));
CREATE INDEX rule_annotation_report_scope ON rule_annotation_context(report_policy_id,report_bundle_version,report_event_at)
 WHERE first_reported_at IS NOT NULL;
