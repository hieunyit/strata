-- CP-A09: after a restore the database may be behind the nodes: they run
-- bundles numbered above every row of bundles. A bundle numbered at or
-- below what a node runs would be refused as older, so the next version is
-- above this floor too (and above every version nodes report). Set by
-- strata-control-plane restore from the database it replaced.
CREATE TABLE bundle_version_floor (
    id       smallint PRIMARY KEY CHECK (id = 1),
    version  bigint NOT NULL CHECK (version >= 0),
    set_at   timestamptz NOT NULL DEFAULT now()
);
