DROP INDEX rule_annotation_report_scope;
ALTER TABLE rule_annotation_context DROP CONSTRAINT complete_rule_report,
 DROP COLUMN first_reported_at, DROP COLUMN report_policy_id, DROP COLUMN report_event_at,
 DROP COLUMN report_rule_ids, DROP COLUMN report_bundle_version;
