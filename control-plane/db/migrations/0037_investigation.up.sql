CREATE TABLE saved_searches (
 id uuid PRIMARY KEY,
 application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 environment_id text NOT NULL,
 owner_subject text NOT NULL,
 title text NOT NULL CHECK(length(title) BETWEEN 1 AND 100),
 shared boolean NOT NULL DEFAULT false,
 sensitive boolean NOT NULL,
 filter jsonb NOT NULL CHECK(octet_length(filter::text)<=8192),
 etag text NOT NULL,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '90 days',
 FOREIGN KEY(application_id,environment_id) REFERENCES application_environments(application_id,id) ON DELETE CASCADE
);
CREATE INDEX saved_searches_owner ON saved_searches(application_id,owner_subject,id);
CREATE TABLE investigation_requests (
 subject text NOT NULL, request_id text NOT NULL CHECK(length(request_id) BETWEEN 1 AND 128),
 fingerprint bytea NOT NULL, response jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(subject,request_id)
);
ALTER TABLE event_annotations ADD COLUMN case_only boolean NOT NULL DEFAULT false,
 ADD COLUMN case_data jsonb, ADD COLUMN case_etag text, ADD COLUMN case_expires_at timestamptz;
