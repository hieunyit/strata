CREATE TABLE discovery_observations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),observation_key text UNIQUE NOT NULL CHECK(observation_key ~ '^[a-f0-9]{64}$'),application_id text NOT NULL,environment_id text NOT NULL,scope_etag text NOT NULL,route_id text NOT NULL,
 method text NOT NULL CHECK(method IN('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS')),
 path text NOT NULL CHECK(length(path)<=512),content_type text NOT NULL CHECK(length(content_type)<=64),
 body_bytes bigint NOT NULL CHECK(body_bytes BETWEEN 0 AND 16777216),source_hash text NOT NULL CHECK(source_hash ~ '^[a-f0-9]{64}$'),
 at timestamptz NOT NULL,expires_at timestamptz NOT NULL DEFAULT now()+interval '7 days',
 FOREIGN KEY(application_id,environment_id) REFERENCES application_environments(application_id,id) ON DELETE CASCADE
);
CREATE INDEX discovery_scope_at ON discovery_observations(application_id,environment_id,scope_etag,at);
CREATE INDEX discovery_expiry ON discovery_observations(expires_at);
CREATE TABLE discovery_batches (
 collector_subject text NOT NULL,batch_id text NOT NULL CHECK(length(batch_id)<=128),fingerprint bytea NOT NULL CHECK(length(fingerprint)=32),
 created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(collector_subject,batch_id)
);
CREATE TABLE discovery_documents (
 application_id text NOT NULL,environment_id text NOT NULL,scope_etag text NOT NULL,
 etag text NOT NULL DEFAULT gen_random_uuid()::text,operations jsonb NOT NULL CHECK(octet_length(operations::text)<=1048576),digest text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),owner_subject text NOT NULL,
 FOREIGN KEY(application_id,environment_id) REFERENCES application_environments(application_id,id) ON DELETE CASCADE,
 PRIMARY KEY(application_id,environment_id)
);
CREATE TABLE discovery_proposals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),application_id text NOT NULL,environment_id text NOT NULL,scope_etag text NOT NULL,route_id text NOT NULL,
 base_digest text NOT NULL,operations jsonb NOT NULL CHECK(octet_length(operations::text)<=1048576),digest text NOT NULL,
 evidence jsonb NOT NULL CHECK(octet_length(evidence::text)<=16384), changes jsonb NOT NULL CHECK(octet_length(changes::text)<=65536),
 etag text NOT NULL DEFAULT gen_random_uuid()::text,created_subject text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL DEFAULT now()+interval '30 days',
 draft_policy_id text,draft_version integer,
 FOREIGN KEY(application_id,environment_id) REFERENCES application_environments(application_id,id) ON DELETE CASCADE,
 FOREIGN KEY(draft_policy_id,draft_version) REFERENCES policy_versions(policy_id,version) DEFERRABLE INITIALLY DEFERRED,
 CHECK((draft_policy_id IS NULL)=(draft_version IS NULL))
);
CREATE INDEX discovery_proposal_expiry ON discovery_proposals(expires_at);
