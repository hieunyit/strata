-- A row lock protects each node across all control-plane replicas. Do not expire
-- watermarks while the node exists: an offline spool may return much later.
CREATE TABLE ingest_sequences (
 node_id text PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 last_seq bigint NOT NULL DEFAULT 0 CHECK (last_seq >= 0)
);
