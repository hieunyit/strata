-- Local accounts (PO 2026-10-13): users signing in with a password kept
-- here, next to or instead of the OIDC provider. Passwords are argon2id
-- hashes; sessions are random tokens of which only the SHA-256 is kept.
CREATE TABLE local_users (
    username        text PRIMARY KEY CHECK (username ~ '^[a-z0-9][a-z0-9._-]{1,62}$'),
    password_hash   text NOT NULL,
    roles           text[] NOT NULL DEFAULT '{}',
    disabled        boolean NOT NULL DEFAULT false,
    failed_logins   integer NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    created_by      text NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    last_login_at   timestamptz
);

CREATE TABLE local_sessions (
    token_sha256    bytea PRIMARY KEY,
    username        text NOT NULL REFERENCES local_users (username) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    client_ip       text NOT NULL DEFAULT '',
    user_agent      text NOT NULL DEFAULT ''
);
CREATE INDEX local_sessions_user ON local_sessions (username);
CREATE INDEX local_sessions_expires ON local_sessions (expires_at);
