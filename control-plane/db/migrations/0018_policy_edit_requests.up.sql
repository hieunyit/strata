-- Durable replies for commands that create an immutable policy draft.
CREATE TABLE policy_edit_requests (
 subject text NOT NULL CHECK (subject <> ''),
 request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
 fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
 response jsonb NOT NULL,
 PRIMARY KEY (subject, request_id)
);
