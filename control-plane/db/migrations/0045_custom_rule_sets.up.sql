-- RS-3c (docs/plan/rule-sets.md): rule sets made by operators. A policy
-- keeps a copy of a set's filter when saved (policy.RuleSetRef.Match), so
-- editing or deleting a set changes no policy until it is saved again.
CREATE TABLE custom_rule_sets (
 name text PRIMARY KEY CHECK (name ~ '^custom-[a-z0-9][a-z0-9-]{0,47}$'),
 title text NOT NULL CHECK (length(title) BETWEEN 1 AND 128),
 description text NOT NULL DEFAULT '' CHECK (length(description) <= 1024),
 match jsonb NOT NULL CHECK (octet_length(match::text) <= 65536),
 version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
 etag text NOT NULL DEFAULT gen_random_uuid()::text,
 created_by text NOT NULL,
 updated_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
