-- A node is online while a control plane holds its Connect stream: set when
-- Hello arrives, cleared when the stream ends, and only trusted while
-- heartbeats keep last_seen_at fresh (a crashed control plane cannot clear
-- it).
ALTER TABLE nodes ADD COLUMN connected boolean NOT NULL DEFAULT false;
