-- CP-A06: the OIDC accounts with the admin role that signed in. Local
-- accounts may be turned off only once one did: otherwise an IdP whose
-- role mapping is wrong would lock every admin out.
CREATE TABLE oidc_admin_sign_ins (
    subject   text PRIMARY KEY CHECK (subject LIKE 'oidc:%'),
    name      text NOT NULL DEFAULT '',
    first_at  timestamptz NOT NULL DEFAULT now(),
    last_at   timestamptz NOT NULL DEFAULT now()
);
