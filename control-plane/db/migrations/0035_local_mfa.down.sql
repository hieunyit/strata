ALTER TABLE local_sessions DROP COLUMN mfa_verified;
ALTER TABLE local_sessions DROP COLUMN id;
DROP TABLE local_mfa;
