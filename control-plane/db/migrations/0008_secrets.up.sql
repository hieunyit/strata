-- Secrets of the installation that the control plane makes itself
-- (P-01 §1): identity_hmac_key, the key of `privacy: { identity: hmac }`,
-- generated once so pseudonymized identities stay comparable across
-- deploys. STRATA_IDENTITY_HMAC_KEY, when set, is used instead and nothing
-- is stored here.
CREATE TABLE secrets (
    name        text PRIMARY KEY,
    value       bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
