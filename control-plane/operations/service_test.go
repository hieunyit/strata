package operations

import (
	"context"
	"encoding/json"
	"github.com/strata/strata/control-plane/health"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
	"strings"
	"testing"
	"time"
)

func TestSignalsGroupByCauseAndRetainUnknown(t *testing.T) {
	v := health.Snapshot{Checks: []health.Check{{ID: "clickhouse", State: "unavailable"}, {ID: "requests", State: "healthy"}}, Nodes: []health.Node{{Checks: []health.Check{{ID: "heartbeat", State: "degraded"}}}, {Checks: []health.Check{{ID: "heartbeat", State: "degraded"}, {ID: "fail_open", State: "unknown"}}}}}
	got := Signals(v)
	if len(got) != 3 {
		t.Fatalf("signals %+v", got)
	}
	for _, v := range got {
		if v.Kind == "heartbeat" && v.Affected != 2 {
			t.Fatal(v)
		}
		if v.Kind == "fail_open" && v.State != "unknown" {
			t.Fatal(v)
		}
	}
}
func TestWorkerNoReceiverAndBackupRecovery(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := store.New(pool)
	now := time.Now().UTC()
	h := &health.Service{Store: st, Now: func() time.Time { return now }, Ready: func(_ context.Context) (map[string]string, bool) {
		return map[string]string{"postgres": "ok", "lease": "held", "clickhouse": "error"}, false
	}}
	worker := Service{Store: st, Health: h, Events: ingest.NewMockEventStore(), Now: func() time.Time { return now }}
	if err := st.RecordBackupObservation(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := worker.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	incidents, err := st.Incidents(t.Context(), "", "", "")
	if err != nil || len(incidents) != 2 {
		t.Fatalf("incidents %+v %v", incidents, err)
	}
	var n int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM outbound_deliveries`).Scan(&n); err != nil || n != 0 {
		t.Fatal("default outbound", err)
	}
	if err := st.RecordBackupObservation(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := worker.Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	incidents, err = st.Incidents(t.Context(), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range incidents {
		if v.Kind == "backup" && v.State != "resolved" {
			t.Fatal(v)
		}
	}
}

func TestScheduledReportUsesOnlyApplicationRoutesAndNoPayload(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := store.New(pool)
	ctx := t.Context()
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('example-group','Example');INSERT INTO nodes(id,group_id) VALUES('node-a','example-group');INSERT INTO applications(id,name,owner,etag,created_by) VALUES('example-api','Example','team','scope-etag','operator');INSERT INTO application_environments(application_id,id,name,group_id) VALUES('example-api','test','Test','example-group')`); err != nil {
		t.Fatal(err)
	}
	p, err := st.CreatePolicy(ctx, store.Policy{ID: "policy-api", Name: "policy-api", Spec: []byte(`{"mode":"shadow"}`)}, store.Audit{Actor: "operator", Subject: "oidc:operator"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO application_routes(application_id,environment_id,id,host,path_prefix,policy_id) VALUES('example-api','test','api','api.example.test','/api',$1)`, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = st.SaveReportSchedule(ctx, store.ReportSchedule{ApplicationID: "example-api", EnvironmentID: "test", ScopeEtag: "scope-etag", Enabled: true, EveryHours: 24}, store.Audit{Actor: "operator", Subject: "oidc:operator", Action: "reports.schedule", RequestID: "schedule"}); err != nil {
		t.Fatal(err)
	}
	events := ingest.NewMockEventStore()
	if err = events.SaveEvents(ctx, []ingest.Event{{BlockID: "allowed", NodeID: "node-a", PolicyID: p.Name, HTTPHost: "api.example.test", HTTPPath: "/api/search", ClientIP: "198.51.100.47", Action: "block", Timestamp: now}, {BlockID: "private", NodeID: "node-a", PolicyID: p.Name, HTTPHost: "other.example.test", HTTPPath: "/private/search", ClientIP: "203.0.113.12", Action: "block", Timestamp: now}}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	h := &health.Service{Store: st, Events: events, Now: func() time.Time { return now }}
	worker := Service{Store: st, Health: h, Events: events, Now: func() time.Time { return now }}
	if err = worker.Once(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ApplicationReports(ctx, "example-api", "test", "scope-etag", now)
	if err != nil || len(rows) != 1 {
		t.Fatalf("reports %+v %v", rows, err)
	}
	var summary Summary
	if err = json.Unmarshal(rows[0].Body, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Events == nil || *summary.Events != 1 || summary.Blocked == nil || *summary.Blocked != 1 {
		t.Fatalf("scope %+v", summary)
	}
	for _, bad := range []string{"198.51.100", "203.0.113", "/api/search", "/private", "node-a"} {
		if strings.Contains(string(rows[0].Body), bad) {
			t.Fatalf("report leaked %s", bad)
		}
	}
	if _, err = pool.Exec(ctx, `UPDATE applications SET etag='scope-next'`); err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	if err = worker.Once(ctx); err != nil {
		t.Fatal(err)
	}
	paused, err := st.ReportSchedule(ctx, "example-api", "test")
	if err != nil || paused.Enabled {
		t.Fatalf("scope change did not pause: %+v %v", paused, err)
	}

}
