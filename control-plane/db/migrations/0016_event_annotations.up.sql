CREATE TABLE event_annotations (
 block_id text PRIMARY KEY,
 reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
 marked_by text NOT NULL,
 marked_subject text NOT NULL CHECK (marked_subject <> ''),
 marked_at timestamptz NOT NULL DEFAULT now(),
 etag text NOT NULL
);
-- Request records survive subsequent edits, so a delayed retry stays idempotent.
CREATE TABLE event_annotation_requests (
 subject text NOT NULL,
 request_id text NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
 response jsonb NOT NULL,
 PRIMARY KEY (subject,request_id)
);
