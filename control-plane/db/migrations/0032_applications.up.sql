CREATE TABLE applications (
 id text PRIMARY KEY, name text NOT NULL, owner text NOT NULL, etag text NOT NULL,
 created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE application_environments (
 application_id text NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 id text NOT NULL, name text NOT NULL, group_id text NOT NULL REFERENCES connector_groups(id),
 PRIMARY KEY(application_id,id)
);
CREATE TABLE application_routes (
 application_id text NOT NULL, environment_id text NOT NULL, id text NOT NULL,
 host text NOT NULL, path_prefix text NOT NULL, policy_id text NOT NULL REFERENCES policies(id), schema_id text NOT NULL DEFAULT '',
 PRIMARY KEY(application_id,id),
 FOREIGN KEY(application_id,environment_id) REFERENCES application_environments(application_id,id) ON DELETE CASCADE
);
CREATE INDEX application_routes_policy ON application_routes(policy_id);
CREATE TABLE application_subjects (subject text PRIMARY KEY);
CREATE TABLE application_role_bindings (
 id bigserial PRIMARY KEY, subject text NOT NULL, role text NOT NULL CHECK(role IN ('viewer','operator','approver','admin')),
 application_id text REFERENCES applications(id) ON DELETE CASCADE, environment_id text,
 created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 CHECK(application_id IS NOT NULL OR environment_id IS NULL),
 FOREIGN KEY(application_id,environment_id) REFERENCES application_environments(application_id,id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX application_binding_identity ON application_role_bindings(subject,role,coalesce(application_id,''),coalesce(environment_id,''));
CREATE TABLE application_write_requests (
 subject text NOT NULL, request_id text NOT NULL, action text NOT NULL, digest bytea NOT NULL,
 response jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(subject,request_id,action)
);
