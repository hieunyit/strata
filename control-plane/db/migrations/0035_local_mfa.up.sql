CREATE TABLE local_mfa (
    username text PRIMARY KEY REFERENCES local_users(username) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false,
    seed bytea,
    pending_seed bytea,
    pending_session bytea,
    pending_until timestamptz,
    pending_request text NOT NULL DEFAULT '',
    etag text NOT NULL DEFAULT gen_random_uuid()::text,
    last_step bigint NOT NULL DEFAULT -1,
    recovery_hashes text[] NOT NULL DEFAULT '{}'
);
ALTER TABLE local_sessions ADD COLUMN id uuid NOT NULL DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX local_sessions_id ON local_sessions(id);
ALTER TABLE local_sessions ADD COLUMN mfa_verified boolean NOT NULL DEFAULT false;
