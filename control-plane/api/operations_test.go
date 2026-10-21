package api

import (
	"encoding/json"
	"github.com/strata/strata/control-plane/store"
	"strings"
	"testing"
	"time"
)

func TestOperationsScopeSchedulesAndDownloads(t *testing.T) {
	previous, st, _, events, _ := investigationFixture(t)
	s := NewServer(ServerConfig{Auth: previous.cfg.Auth, Applications: st}, events)
	base := "?application_id=example-api&environment_id=test"
	investigationRequest(t, s, "viewer", "GET", "/v1/incidents?application_id="+strings.Repeat("x", 64)+"&environment_id=test", nil, 400)
	investigationRequest(t, s, "outsider", "GET", "/v1/incidents"+base, nil, 403)
	investigationRequest(t, s, "viewer", "GET", "/v1/incidents", nil, 403)
	investigationRequest(t, s, "viewer", "GET", "/v1/incidents"+base, nil, 200)
	request := map[string]any{"schedule": map[string]any{"application_id": "example-api", "environment_id": "test", "enabled": true, "every_hours": 24}, "request_id": "schedule"}
	investigationRequest(t, s, "viewer", "PUT", "/v1/report-schedule", request, 403)
	rec := investigationRequest(t, s, "operator", "PUT", "/v1/report-schedule", request, 200)
	investigationRequest(t, s, "operator", "PUT", "/v1/report-schedule", request, 200)
	var reply struct {
		Schedule store.ReportSchedule `json:"schedule"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	a, err := st.GetApplication(t.Context(), "example-api")
	if err != nil {
		t.Fatal(err)
	}
	signal := store.Incident{ApplicationID: a.ID, EnvironmentID: "test", ScopeEtag: a.Etag, Kind: "heartbeat", SignalState: "degraded", Affected: 3, ObservedAt: time.Now().UTC()}
	if err = st.ObserveIncident(t.Context(), signal, false); err != nil {
		t.Fatal(err)
	}
	rows, err := st.Incidents(t.Context(), a.ID, "test", a.Etag)
	if err != nil || len(rows) != 1 {
		t.Fatal(err)
	}
	ack := map[string]any{"id": rows[0].ID, "application_id": a.ID, "environment_id": "test", "etag": rows[0].Etag, "request_id": "ack"}
	investigationRequest(t, s, "viewer", "POST", "/v1/incidents:acknowledge", ack, 403)
	investigationRequest(t, s, "operator", "POST", "/v1/incidents:acknowledge", ack, 200)
	now := time.Now().UTC().Add(time.Second)
	job, err := st.ClaimApplicationReport(t.Context(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.FinishApplicationReport(t.Context(), job, json.RawMessage(`{"source":"operational_health_and_security_events","signals":[],"security_events":2,"blocked_security_events":1,"event_status":"available","observed_at":"2026-10-21T00:00:00Z","truncated":false}`), now, false); err != nil {
		t.Fatal(err)
	}
	reports, err := st.ApplicationReports(t.Context(), a.ID, "test", a.Etag, now)
	if err != nil || len(reports) != 1 {
		t.Fatal(err)
	}
	path := "/v1/application-reports/" + reports[0].ID
	investigationRequest(t, s, "viewer", "GET", path+base, nil, 200)
	investigationRequest(t, s, "outsider", "GET", path+base, nil, 403)
	investigationRequest(t, s, "viewer", "GET", path+"?application_id=example-api&environment_id=other", nil, 404)
	investigationRequest(t, s, "viewer", "GET", "/v1/application-reports"+base, nil, 200)
}
