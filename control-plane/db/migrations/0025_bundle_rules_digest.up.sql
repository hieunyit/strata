-- CP-FIX-01 (PO 20/10/2026): the deploy replay gate checks only what
-- changed. rules_digest commits the compiler and rule inputs alone (not the
-- policies' specs, staged rules or identity key), so a deploy can tell a
-- rule or compiler change, which needs every policy replayed and approved
-- again, from a change of some policies. '' for bundles from before: the
-- first deploy after the upgrade treats the rules as changed.
ALTER TABLE bundles ADD COLUMN rules_digest text NOT NULL DEFAULT '';
