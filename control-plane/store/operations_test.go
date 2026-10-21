package store

import (
	"encoding/json"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"strings"
	"testing"
	"time"
)

func TestIncidentsCooldownAckRecoveryAndPrivacy(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := New(pool)
	ctx := t.Context()
	now := time.Now().UTC()
	signal := Incident{Kind: "heartbeat", SignalState: "degraded", Affected: 17, ObservedAt: now}
	for range 3 {
		if err := st.ObserveIncident(ctx, signal, true); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := st.Incidents(ctx, "", "", "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("group %+v %v", rows, err)
	}
	count := func(want int) {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbound_deliveries WHERE kind='alert'`).Scan(&n); err != nil || n != want {
			t.Fatalf("deliveries %d wanted %d: %v", n, want, err)
		}
	}
	count(1)
	signal.ObservedAt = now.Add(61 * time.Minute)
	if err = st.ObserveIncident(ctx, signal, true); err != nil {
		t.Fatal(err)
	}
	count(2)
	rows, _ = st.Incidents(ctx, "", "", "")
	ack, err := st.AcknowledgeIncident(ctx, rows[0].ID, rows[0].Etag, "", "", "", Audit{Actor: "operator", Subject: "oidc:operator", Action: "incidents.acknowledge", RequestID: "ack"})
	if err != nil || ack.State != "acknowledged" {
		t.Fatalf("ack %+v %v", ack, err)
	}
	if _, err = st.AcknowledgeIncident(ctx, ack.ID, rows[0].Etag, "", "", "", Audit{Subject: "oidc:operator", RequestID: "stale"}); err != ErrEtagMismatch {
		t.Fatalf("stale ack %v", err)
	}
	signal.ObservedAt = now.Add(3 * time.Hour)
	if err = st.ObserveIncident(ctx, signal, true); err != nil {
		t.Fatal(err)
	}
	count(2)
	signal.SignalState = "unknown"
	if err = st.ObserveIncident(ctx, signal, true); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.Incidents(ctx, "", "", "")
	if rows[0].State != "acknowledged" {
		t.Fatal("unknown resolved incident")
	}
	signal.SignalState = "healthy"
	signal.Affected = 0
	if err = st.ObserveIncident(ctx, signal, true); err != nil {
		t.Fatal(err)
	}
	count(3)
	signal.SignalState = "degraded"
	signal.Affected = 1
	signal.ObservedAt = now.Add(4 * time.Hour)
	if err = st.ObserveIncident(ctx, signal, true); err != nil {
		t.Fatal(err)
	}
	count(4)
	var raw []byte
	if err = pool.QueryRow(ctx, `SELECT jsonb_agg(payload) FROM outbound_deliveries`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"operator", "client_ip", "snippet", "http_path", "ack_subject", "application_id"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("payload leaked %s", bad)
		}
	}
	if err = st.ObserveIncident(ctx, Incident{Kind: "arbitrary\nsecret", SignalState: "degraded"}, true); err == nil {
		t.Fatal("bad cause accepted")
	}
}
func TestReportSchedulesLeasesScopeAndRetention(t *testing.T) {
	pool := localauthtest.Pool(t)
	st := New(pool)
	ctx := t.Context()
	now := time.Now().UTC()
	a := Audit{Actor: "operator", Subject: "oidc:operator", Action: "reports.schedule", RequestID: "first"}
	if _, err := pool.Exec(ctx, `INSERT INTO connector_groups(id,name) VALUES('example-group','Example'); INSERT INTO applications(id,name,owner,etag,created_by) VALUES('example-api','Example','example-team','scope-etag','oidc:operator'); INSERT INTO application_environments(application_id,id,name,group_id) VALUES('example-api','test','Test','example-group')`); err != nil {
		t.Fatal(err)
	}
	v := ReportSchedule{ApplicationID: "example-api", EnvironmentID: "test", ScopeEtag: "scope-etag", Enabled: true, EveryHours: 24}
	saved, err := st.SaveReportSchedule(ctx, v, a)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := st.SaveReportSchedule(ctx, v, a)
	if err != nil || retry.Etag != saved.Etag {
		t.Fatal("idempotency", err)
	}
	a.RequestID = "stale"
	if _, err = st.SaveReportSchedule(ctx, v, a); err != ErrEtagMismatch {
		t.Fatalf("etag %v", err)
	}
	now = now.Add(time.Second)
	first, err := st.ClaimApplicationReport(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.ClaimApplicationReport(ctx, now); err != ErrNotFound {
		t.Fatalf("double claim %v", err)
	}
	second, err := st.ClaimApplicationReport(ctx, now.Add(3*time.Minute))
	if err != nil || second.Claim == first.Claim {
		t.Fatal("expired claim", err)
	}
	body := json.RawMessage(`{"source":"operational_health_and_security_events","security_events":12,"blocked_security_events":2}`)
	if err = st.FinishApplicationReport(ctx, first, body, now.Add(3*time.Minute), true); err != ErrEtagMismatch {
		t.Fatalf("stale worker %v", err)
	}
	if err = st.FinishApplicationReport(ctx, second, body, now.Add(3*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	reports, err := st.ApplicationReports(ctx, v.ApplicationID, v.EnvironmentID, v.ScopeEtag, now)
	if err != nil || len(reports) != 1 {
		t.Fatalf("reports %+v %v", reports, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE applications SET etag='scope-next'`); err != nil {
		t.Fatal(err)
	}
	if rows, err := st.ApplicationReports(ctx, v.ApplicationID, v.EnvironmentID, "scope-next", now); err != nil || len(rows) != 0 {
		t.Fatal("old scope visible", err)
	}
	if err = st.RetainOperations(ctx, now.Add(31*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	reports, err = st.ApplicationReports(ctx, v.ApplicationID, v.EnvironmentID, v.ScopeEtag, now)
	if err != nil || len(reports) != 0 {
		t.Fatal("retention", err)
	}
	if err = st.RecordBackupObservation(ctx, false); err != nil {
		t.Fatal(err)
	}
	ok, _, err := st.BackupObservation(ctx)
	if err != nil || ok {
		t.Fatal("backup failure", err)
	}
}
