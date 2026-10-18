-- Keep legacy service_accounts intact: their one-token schema is not activated
-- implicitly. New machine credentials have independent, revocable token rows.
CREATE TABLE machine_accounts (
 id text PRIMARY KEY CHECK (length(id) BETWEEN 2 AND 64),
 metadata jsonb NOT NULL
);
CREATE TABLE machine_tokens (
 id text PRIMARY KEY,
 account_id text NOT NULL REFERENCES machine_accounts(id) ON DELETE CASCADE,
 token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
 metadata jsonb NOT NULL,
 expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 last_used_at timestamptz
);
CREATE INDEX machine_tokens_account ON machine_tokens(account_id);
CREATE TABLE machine_requests (
 subject text NOT NULL,
 request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
 digest bytea NOT NULL CHECK (length(digest)=32),
 receipt jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(subject,request_id)
);
