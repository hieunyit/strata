DROP INDEX policy_versions_submitted;
ALTER TABLE policy_versions DROP CONSTRAINT policy_versions_four_eyes;
ALTER TABLE policy_versions
    DROP COLUMN created_subject,
    DROP COLUMN submitted_by,
    DROP COLUMN submitted_subject,
    DROP COLUMN submitted_at,
    DROP COLUMN decided_by,
    DROP COLUMN decided_subject,
    DROP COLUMN decided_at,
    DROP COLUMN decision_comment;
