-- Control plane database v1 (nginx-module.md › Kiến trúc control plane:
-- policy, version, node, role binding, audit). Later migrations extend
-- these tables; they never edit this file.

CREATE TABLE connector_groups (
    id          text PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE nodes (
    id              text PRIMARY KEY,             -- spiffe://strata/node/<id>
    group_id        text NOT NULL REFERENCES connector_groups (id),
    hostname        text NOT NULL DEFAULT '',
    proxy_version   text NOT NULL DEFAULT '',
    module_version  text NOT NULL DEFAULT '',
    bundle_version  bigint,
    bundle_state    text NOT NULL DEFAULT 'NONE'
                    CHECK (bundle_state IN ('NONE', 'VERIFIED', 'ACTIVE', 'FAILED')),
    cert_serial     text NOT NULL DEFAULT '',
    cert_not_after  timestamptz,
    last_seen_at    timestamptz,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX nodes_group_id ON nodes (group_id);

CREATE TABLE enrollment_tokens (
    id            text PRIMARY KEY,
    group_id      text NOT NULL REFERENCES connector_groups (id),
    token_sha256  bytea NOT NULL UNIQUE CHECK (length(token_sha256) = 32),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,                    -- single use
    used_by_node  text REFERENCES nodes (id),
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policies (
    id               text PRIMARY KEY,
    name             text NOT NULL UNIQUE,
    current_version  integer NOT NULL DEFAULT 0,
    etag             text NOT NULL,
    created_by       text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policy_versions (
    policy_id    text NOT NULL REFERENCES policies (id) ON DELETE CASCADE,
    version      integer NOT NULL CHECK (version > 0),
    spec         jsonb NOT NULL,
    state        text NOT NULL DEFAULT 'DRAFT'
                 CHECK (state IN ('DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'DEPLOYED')),
    created_by   text NOT NULL,
    approved_by  text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, version),
    -- four eyes: whoever drafted a version cannot approve it
    CHECK (approved_by IS NULL OR approved_by <> created_by)
);

CREATE TABLE bundles (
    version     bigint PRIMARY KEY CHECK (version > 0),
    sha256      bytea NOT NULL CHECK (length(sha256) = 32),
    object_key  text NOT NULL UNIQUE,              -- MinIO / S3 key
    size_bytes  bigint NOT NULL CHECK (size_bytes > 0),
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE role_bindings (
    id          bigserial PRIMARY KEY,
    subject     text NOT NULL,                     -- OIDC sub or service account id
    role        text NOT NULL CHECK (role IN ('viewer', 'operator', 'approver', 'admin')),
    group_id    text REFERENCES connector_groups (id) ON DELETE CASCADE,  -- NULL: every group
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX role_bindings_unique ON role_bindings (subject, role, coalesce(group_id, ''));

CREATE TABLE service_accounts (
    id            text PRIMARY KEY,
    name          text NOT NULL UNIQUE,
    scopes        text[] NOT NULL,                 -- e.g. {policies:read,events:read}
    token_sha256  bytea NOT NULL UNIQUE CHECK (length(token_sha256) = 32),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor       text NOT NULL,
    channel     text NOT NULL CHECK (channel IN ('ui', 'api', 'gitops', 'system')),
    action      text NOT NULL,                     -- e.g. strata.admin.v1.PolicyService/UpdatePolicy
    resource    text NOT NULL,
    request_id  text NOT NULL DEFAULT '',
    before      jsonb,
    after       jsonb
);
CREATE INDEX audit_log_at ON audit_log (at);
CREATE INDEX audit_log_resource ON audit_log (resource, at);
