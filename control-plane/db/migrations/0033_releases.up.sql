CREATE TABLE releases (
 id text PRIMARY KEY,
 etag text NOT NULL,
 state text NOT NULL CHECK(state IN ('DRAFT','APPROVED','REJECTED','DEPLOYED')),
 snapshot jsonb NOT NULL,
 snapshot_hash text NOT NULL,
 source_release text REFERENCES releases(id),
 created_by text NOT NULL,
 created_subject text NOT NULL,
 approved_by text NOT NULL DEFAULT '',
 approved_subject text NOT NULL DEFAULT '',
 request_id text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 bundle_version bigint REFERENCES bundles(version),
 rollout_id bigint REFERENCES rollouts(id),
 UNIQUE(created_subject,request_id)
);
