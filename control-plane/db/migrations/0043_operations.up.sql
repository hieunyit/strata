CREATE TABLE operation_incidents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 application_id text NOT NULL DEFAULT '', environment_id text NOT NULL DEFAULT '', scope_etag text NOT NULL DEFAULT '',
 kind text NOT NULL CHECK(kind ~ '^[a-z_]{1,48}$'),
 state text NOT NULL CHECK(state IN('open','acknowledged','resolved')),
 signal_state text NOT NULL CHECK(signal_state IN('degraded','unavailable','healthy','unknown','stale')),
 affected integer NOT NULL CHECK(affected BETWEEN 0 AND 1000000),
 etag text NOT NULL DEFAULT gen_random_uuid()::text,
 opened_at timestamptz NOT NULL, observed_at timestamptz NOT NULL, notified_at timestamptz,
 ack_subject text NOT NULL DEFAULT '',
 UNIQUE(application_id,environment_id,scope_etag,kind)
);
CREATE TABLE application_report_schedules (
 application_id text NOT NULL,environment_id text NOT NULL,scope_etag text NOT NULL,
 enabled boolean NOT NULL DEFAULT false, every_hours integer NOT NULL CHECK(every_hours IN(24,168)),
 etag text NOT NULL DEFAULT gen_random_uuid()::text, owner_subject text NOT NULL,
 next_run timestamptz NOT NULL DEFAULT now(), lease_until timestamptz, claim uuid,
 FOREIGN KEY(application_id,environment_id) REFERENCES application_environments(application_id,id) ON DELETE CASCADE,
 PRIMARY KEY(application_id,environment_id)
);
CREATE TABLE application_reports (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),application_id text NOT NULL,environment_id text NOT NULL,scope_etag text NOT NULL,
 period_end timestamptz NOT NULL,period_start timestamptz NOT NULL,
 body jsonb NOT NULL CHECK(octet_length(body::text)<=16384),
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '30 days',
 FOREIGN KEY(application_id,environment_id) REFERENCES application_environments(application_id,id) ON DELETE CASCADE,
 UNIQUE(application_id,environment_id,period_end),CHECK(period_start<period_end)
);
CREATE TABLE backup_observation (
 id integer PRIMARY KEY CHECK(id=1), succeeded boolean NOT NULL,at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX operation_incident_scope ON operation_incidents(application_id,environment_id,observed_at);
CREATE INDEX application_report_expiry ON application_reports(expires_at);

CREATE TABLE operation_counter_baselines (
 kind text NOT NULL,node_id text NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 value numeric(20,0) NOT NULL CHECK(value>=0),at timestamptz NOT NULL,PRIMARY KEY(kind,node_id)
);
