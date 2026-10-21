-- Configured catalogs are immutable metadata snapshots, not runtime bundle proofs.
CREATE TABLE rule_catalogs (
 digest text PRIMARY KEY CHECK(digest ~ '^[a-f0-9]{64}$'),
 entries jsonb NOT NULL CHECK(jsonb_typeof(entries)='array' AND jsonb_array_length(entries)<=100000 AND octet_length(entries::text)<=33554432),
 created_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE rule_catalog_settings(id boolean PRIMARY KEY DEFAULT true CHECK(id),current_digest text NOT NULL REFERENCES rule_catalogs(digest));
