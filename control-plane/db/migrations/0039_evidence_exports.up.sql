CREATE TABLE evidence_exports (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 owner_subject text NOT NULL, application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 environment_id text NOT NULL,
 filter jsonb NOT NULL CHECK(octet_length(filter::text)<=8192),
 principal jsonb NOT NULL CHECK(octet_length(principal::text)<=1048576),
 sensitive boolean NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','running','done','failed')),
 etag text NOT NULL DEFAULT gen_random_uuid()::text,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3),
 lease_until timestamptz,
 artifact_key text NOT NULL DEFAULT '', sha256 text NOT NULL DEFAULT '',
 row_count integer NOT NULL DEFAULT 0 CHECK(row_count BETWEEN 0 AND 10000),
 truncated boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL DEFAULT now()+interval '24 hours',
 FOREIGN KEY(application_id,environment_id) REFERENCES application_environments(application_id,id) ON DELETE CASCADE
);
CREATE INDEX evidence_exports_queue ON evidence_exports(state,created_at);
