-- Four eyes (W13-G2-02): a version is DRAFT, SUBMITTED for review, then
-- APPROVED or REJECTED by someone else, and DEPLOYED once a bundle took it.
-- Deploys build each policy's newest APPROVED or DEPLOYED version (PO
-- 15/10/2026). Who did what is kept by subject (the token's sub, which a
-- user cannot change), besides the display name in *_by.
ALTER TABLE policy_versions
    ADD COLUMN created_subject   text NOT NULL DEFAULT '',
    ADD COLUMN submitted_by      text,
    ADD COLUMN submitted_subject text,
    ADD COLUMN submitted_at      timestamptz,
    ADD COLUMN decided_by        text,
    ADD COLUMN decided_subject   text,
    ADD COLUMN decided_at        timestamptz,
    ADD COLUMN decision_comment  text NOT NULL DEFAULT '';

-- the versions saved before approval existed were deployable: they stay so
UPDATE policy_versions SET state = 'DEPLOYED';

-- whoever drafted or submitted a version cannot approve it
ALTER TABLE policy_versions ADD CONSTRAINT policy_versions_four_eyes CHECK (
    state <> 'APPROVED' OR (decided_subject IS NOT NULL AND decided_subject <> ''
        AND decided_subject <> created_subject AND decided_subject <> coalesce(submitted_subject, '')));

CREATE INDEX policy_versions_submitted ON policy_versions (submitted_at) WHERE state = 'SUBMITTED';
