-- Only human-classified FP events, not the traffic stream. Rule IDs and event
-- time come from the server's event lookup in the annotation transaction.
CREATE TABLE rule_annotation_context (
 block_id text PRIMARY KEY,
 policy_id text NOT NULL CHECK (length(policy_id) <= 55),
 event_at timestamptz NOT NULL,
 rule_ids bigint[] NOT NULL CHECK (
  cardinality(rule_ids) BETWEEN 0 AND 64 AND array_position(rule_ids,NULL) IS NULL AND
  0 < ALL(rule_ids) AND 4294967295 >= ALL(rule_ids)
 )
);
CREATE INDEX rule_annotation_context_rules ON rule_annotation_context USING gin(rule_ids);
CREATE INDEX rule_annotation_context_time ON rule_annotation_context(event_at,block_id);
CREATE INDEX rule_annotation_context_policy_time ON rule_annotation_context(policy_id,event_at);
