package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/investigation"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

type investigationAuth struct{ st *store.Store }

func (a investigationAuth) Authenticate(ctx context.Context, raw string) (*auth.Principal, error) {
	role := auth.RoleViewer
	if raw == "operator" || raw == "outsider" {
		role = auth.RoleOperator
	}
	return a.st.ResolveApplicationAccess(ctx, &auth.Principal{Subject: "oidc:" + raw, Name: raw, Roles: []auth.Role{role}})
}
func investigationFixture(t *testing.T) (*Server, *store.Store, *pgxpool.Pool, *ingest.MockEventStore, *investigation.Worker) {
	t.Helper()
	pool := localauthtest.Pool(t)
	ctx := t.Context()
	st := store.New(pool)
	a := store.Audit{Subject: "oidc:operator", Actor: "operator", Action: "policy.create"}
	if _, err := st.CreatePolicy(ctx, store.Policy{ID: "policy-api", Name: "example-api", Spec: []byte(`{"mode":"enforce"}`)}, a); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`INSERT INTO connector_groups(id,name) VALUES('example-group','Example')`, `INSERT INTO nodes(id,group_id) VALUES('node-a','example-group')`, `INSERT INTO applications(id,name,owner,etag,created_by) VALUES('example-api','Example','operator','e','operator')`, `INSERT INTO application_environments(application_id,id,name,group_id) VALUES('example-api','test','Test','example-group')`, `INSERT INTO application_routes(application_id,environment_id,id,host,path_prefix,policy_id) VALUES('example-api','test','api','api.example.test','/api','policy-api')`, `INSERT INTO application_subjects(subject) VALUES('oidc:operator'),('oidc:viewer'),('oidc:outsider')`, `INSERT INTO application_role_bindings(subject,role,application_id,environment_id,created_by) VALUES('oidc:operator','operator','example-api','test','test'),('oidc:viewer','viewer','example-api','test','test')`} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	events := ingest.NewMockEventStore()
	now := time.Now().UTC()
	fixtures := []ingest.Event{{BlockID: "STR-0000-0000-0000-0001", Timestamp: now, PolicyID: "example-api", NodeID: "node-a", HTTPHost: "api.example.test", HTTPMethod: "POST", HTTPPath: "/api/search", ClientIP: "203.0.113.17", Action: "block", MatchedRules: []uint32{942100}, CountryISO: "VN", ASN: 64500, GeoIPVersion: "synthetic-test"}, {BlockID: "STR-0000-0000-0000-0002", Timestamp: now, PolicyID: "example-api", NodeID: "node-a", HTTPHost: "api.example.test", HTTPMethod: "GET", HTTPPath: "/api/search", Action: "block", MatchedRules: []uint32{942100}}, {BlockID: "STR-0000-0000-0000-0003", Timestamp: now, PolicyID: "example-api", NodeID: "node-a", HTTPHost: "other.example.test", HTTPMethod: "POST", HTTPPath: "/api/search", Action: "block", MatchedRules: []uint32{942100}}, {BlockID: "STR-0000-0000-0000-0004", Timestamp: now, PolicyID: "example-api", NodeID: "node-a", HTTPHost: "api.example.test", HTTPMethod: "POST", HTTPPath: "/api/search", Action: "block", MatchedRules: []uint32{942100}}}
	if err := events.SaveEvents(ctx, fixtures); err != nil {
		t.Fatal(err)
	}
	objects, err := policy.NewFS(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objects.Close() })
	worker := &investigation.Worker{Store: st, Events: events, Objects: objects}
	server := NewServer(ServerConfig{Auth: investigationAuth{st}, Applications: st, Annotations: st, ReplayKick: func() {}, Evidence: worker}, events)
	return server, st, pool, events, worker
}
func investigationRequest(t *testing.T, s *Server, role, method, path string, body any, code int) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+role)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != code {
		t.Fatalf("%s %s as %s: %d want %d: %s", method, path, role, rec.Code, code, rec.Body.String())
	}
	return rec
}
func TestInvestigationHTTP(t *testing.T) {
	s, st, pool, _, worker := investigationFixture(t)
	ctx := t.Context()
	now := time.Now().UTC()
	filter := SearchEventsRequest{From: now.Add(-time.Hour), To: now.Add(time.Hour)}
	input := map[string]any{"search": map[string]any{"application_id": "example-api", "environment_id": "test", "title": "Shared case", "shared": true, "filter": filter}, "request_id": "save"}
	rec := investigationRequest(t, s, "operator", "POST", "/v1/saved-searches", input, 200)
	var reply struct {
		Search store.SavedSearch `json:"search"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	investigationRequest(t, s, "viewer", "GET", "/v1/saved-searches/"+reply.Search.ID, nil, 200)
	investigationRequest(t, s, "outsider", "GET", "/v1/saved-searches/"+reply.Search.ID, nil, 403)
	filter.ClientIP = "203.0.113.17"
	input["search"].(map[string]any)["filter"] = filter
	input["request_id"] = "sensitive"
	rec = investigationRequest(t, s, "operator", "POST", "/v1/saved-searches", input, 200)
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	investigationRequest(t, s, "viewer", "GET", "/v1/saved-searches/"+reply.Search.ID, nil, 404)
	investigationRequest(t, s, "viewer", "POST", "/v1/saved-searches", input, 403)
	investigationRequest(t, s, "operator", "GET", "/v1/saved-searches/not-a-uuid", nil, 404)
	path := "/v1/events/STR-0000-0000-0000-0001:case"
	body := map[string]any{"case": store.EventCase{BlockID: "STR-0000-0000-0000-0001", Assignee: "oidc:operator", Status: "investigating", Note: "Private context"}, "request_id": "case"}
	investigationRequest(t, s, "viewer", "POST", path, body, 403)
	investigationRequest(t, s, "outsider", "POST", path, body, 403)
	investigationRequest(t, s, "operator", "POST", path, body, 200)
	rec = investigationRequest(t, s, "viewer", "GET", path, nil, 200)
	if strings.Contains(rec.Body.String(), "Private context") {
		t.Fatal("viewer read note")
	}
	rec = investigationRequest(t, s, "operator", "GET", "/v1/events/STR-0000-0000-0000-0001", nil, 200)
	if strings.Contains(rec.Body.String(), `"false_positive":true`) {
		t.Fatal("case implicitly marked FP")
	}
	body["request_id"] = "stale"
	investigationRequest(t, s, "operator", "POST", path, body, 409)
	v := body["case"].(store.EventCase)
	v.Assignee = "oidc:outsider"
	body["case"] = v
	investigationRequest(t, s, "operator", "POST", path, body, 400)
	rec = investigationRequest(t, s, "viewer", "GET", "/v1/events/STR-0000-0000-0000-0001:similar", nil, 200)
	var similar SearchEventsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &similar); err != nil {
		t.Fatal(err)
	}
	if len(similar.Events) != 2 || similar.Events[0].ClientIP == "203.0.113.17" {
		t.Fatalf("similar scope/privacy: %+v", similar)
	}
	p, err := st.GetPolicy(ctx, "policy-api")
	if err != nil {
		t.Fatal(err)
	}
	rule := EventRuleRequest{Dimension: "country", Action: "log", Etag: p.Etag, RequestID: "rule"}
	investigationRequest(t, s, "viewer", "POST", "/v1/events/STR-0000-0000-0000-0001:propose-rule", rule, 403)
	rec = investigationRequest(t, s, "operator", "POST", "/v1/events/STR-0000-0000-0000-0001:propose-rule", rule, 200)
	investigationRequest(t, s, "operator", "POST", "/v1/events/STR-0000-0000-0000-0001:propose-rule", rule, 200)
	var draft EventRuleDraft
	if err := json.Unmarshal(rec.Body.Bytes(), &draft); err != nil {
		t.Fatal(err)
	}
	if draft.State != "DRAFT" || draft.PolicyVersion != 2 {
		t.Fatalf("not draft: %+v", draft)
	}
	var operations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM operations WHERE policy_id='policy-api'`).Scan(&operations); err != nil || operations != 1 {
		t.Fatalf("replay %d %v", operations, err)
	}
	filter.ClientIP = ""
	export := map[string]any{"application_id": "example-api", "environment_id": "test", "filter": filter, "request_id": "export"}
	rec = investigationRequest(t, s, "viewer", "POST", "/v1/evidence", export, 202)
	var receipt struct {
		Export store.EvidenceExport `json:"export"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	id := receipt.Export.ID
	investigationRequest(t, s, "operator", "GET", "/v1/evidence/"+id, nil, 404) // another owner
	investigationRequest(t, s, "viewer", "GET", "/v1/evidence/"+id+"/download", nil, 409)
	if err := worker.Once(ctx); err != nil {
		t.Fatal(err)
	}
	rec = investigationRequest(t, s, "viewer", "GET", "/v1/evidence/"+id+"/download", nil, 200)
	if strings.Contains(rec.Body.String(), "203.0.113.17") || strings.Contains(rec.Body.String(), "other.example.test") {
		t.Fatal("export leaked full IP or another route")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM application_role_bindings WHERE subject='oidc:viewer'`); err != nil {
		t.Fatal(err)
	}
	investigationRequest(t, s, "viewer", "GET", "/v1/evidence/"+id+"/download", nil, 403)
	// Background retries also refuse work after revocation and delete expired files.
	if _, err := pool.Exec(ctx, `UPDATE evidence_exports SET expires_at=now()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err := worker.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	files, err := worker.Objects.List(ctx, "evidence/")
	if err != nil || len(files) != 0 {
		t.Fatalf("retention files %v %v", files, err)
	}
}

func TestEvidenceBoundsAndLease(t *testing.T) {
	s, st, pool, events, worker := investigationFixture(t)
	ctx := t.Context()
	now := time.Now().UTC()
	fixtures := make([]ingest.Event, 10001)
	for i := range fixtures {
		fixtures[i] = ingest.Event{BlockID: fmt.Sprintf("STR-TEST-%04d-0000-0000", i), Timestamp: now, PolicyID: "example-api", NodeID: "node-a", HTTPHost: "api.example.test", HTTPMethod: "PATCH", HTTPPath: "/api/records", Action: "shadow"}
	}
	if err := events.SaveEvents(ctx, fixtures); err != nil {
		t.Fatal(err)
	}
	create := func(method, id string) store.EvidenceExport {
		t.Helper()
		rec := investigationRequest(t, s, "viewer", "POST", "/v1/evidence", map[string]any{"application_id": "example-api", "environment_id": "test", "filter": SearchEventsRequest{From: now.Add(-time.Hour), To: now.Add(time.Hour), HTTPMethod: method}, "request_id": id}, 202)
		var v struct {
			Export store.EvidenceExport `json:"export"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v.Export
	}
	job := create("PATCH", "row-bounds")
	// A crash leaves a lease; a later worker reclaims it with a new fencing etag.
	claimed, err := st.ClaimEvidence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE evidence_exports SET lease_until=now()-interval '1 second' WHERE id::text=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := worker.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishEvidence(ctx, claimed, true); err == nil {
		t.Fatal("stale lease completion succeeded")
	}
	done, err := st.EvidenceExport(ctx, job.ID)
	if err != nil || done.RowCount != 10000 || !done.Truncated || done.State != "done" {
		t.Fatalf("row bound: %+v %v", done, err)
	}
	// Large fields hit the byte cap without writing a partial CSV record.
	large := make([]ingest.Event, 300)
	for i := range large {
		large[i] = fixtures[0]
		large[i].BlockID = fmt.Sprintf("STR-BYTE-%04d-0000-0000", i)
		large[i].HTTPMethod = "PUT"
		large[i].HTTPPath = "/api/" + strings.Repeat("x", 60000)
	}
	if err := events.SaveEvents(ctx, large); err != nil {
		t.Fatal(err)
	}
	bytesJob := create("PUT", "byte-bounds")
	if err := worker.Once(ctx); err != nil {
		t.Fatal(err)
	}
	done, err = st.EvidenceExport(ctx, bytesJob.ID)
	if err != nil || !done.Truncated || done.RowCount >= 300 {
		t.Fatalf("byte bound: %+v %v", done, err)
	}
	data, err := worker.Objects.Get(ctx, done.ArtifactKey)
	if err != nil || len(data) > investigation.MaxBytes || !bytes.HasSuffix(data, []byte("\r\n")) {
		t.Fatalf("CSV incomplete: %d %v", len(data), err)
	}
	// Scope revoked before background execution produces no artifact.
	revoked := create("GET", "revoked-before-run")
	if _, err := pool.Exec(ctx, `DELETE FROM application_role_bindings WHERE subject='oidc:viewer'`); err != nil {
		t.Fatal(err)
	}
	if err := worker.Once(ctx); err == nil {
		t.Fatal("revoked job ran")
	}
	done, err = st.EvidenceExport(ctx, revoked.ID)
	if err != nil || done.State != "failed" || done.ArtifactKey != "" {
		t.Fatalf("revoked result: %+v %v", done, err)
	}
}

func TestInvestigationRejectsInvalidCommands(t *testing.T) {
	s, _, pool, _, _ := investigationFixture(t)
	now := time.Now().UTC()
	filter := SearchEventsRequest{From: now.Add(-time.Hour), To: now}
	command := map[string]any{"search": map[string]any{"application_id": "example-api", "environment_id": "test", "title": "Example", "shared": true, "filter": filter}, "request_id": "save"}
	if _, err := pool.Exec(t.Context(), `INSERT INTO application_environments(application_id,id,name,group_id) VALUES('example-api','production','Production','example-group')`); err != nil {
		t.Fatal(err)
	}
	command["search"].(map[string]any)["environment_id"] = "production"
	investigationRequest(t, s, "operator", "POST", "/v1/saved-searches", command, 404)
	command["search"].(map[string]any)["environment_id"] = "test"
	filter.To = now.Add(32 * 24 * time.Hour)
	command["search"].(map[string]any)["filter"] = filter
	investigationRequest(t, s, "operator", "POST", "/v1/saved-searches", command, 400)
	filter.To = now
	command["search"].(map[string]any)["filter"] = filter
	command["request_id"] = ""
	investigationRequest(t, s, "operator", "POST", "/v1/saved-searches", command, 400)
	command["request_id"] = "saved"
	rec := investigationRequest(t, s, "operator", "POST", "/v1/saved-searches", command, 200)
	var reply struct {
		Search store.SavedSearch `json:"search"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	// Execute the shared filter through the saved application/environment scope.
	rec = investigationRequest(t, s, "viewer", "POST", "/v1/saved-searches/"+reply.Search.ID+":search", map[string]string{"page_token": ""}, 200)
	if strings.Contains(rec.Body.String(), "other.example.test") {
		t.Fatal("saved query escaped application scope")
	}
	for _, text := range []string{`{} {}`, `{"search":{},"unknown":true}`, strings.Repeat("x", 257<<10)} {
		req := httptest.NewRequest("POST", "/v1/saved-searches", strings.NewReader(text))
		req.Header.Set("Authorization", "Bearer operator")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("invalid JSON: %d", rec.Code)
		}
	}
	// A local audit failure cannot persist a search or its idempotency receipt.
	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION fail_investigation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test failure'; END $$; CREATE TRIGGER fail_investigation_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_investigation_audit()`); err != nil {
		t.Fatal(err)
	}
	command["request_id"] = "rollback"
	investigationRequest(t, s, "operator", "POST", "/v1/saved-searches", command, 503)
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM investigation_requests WHERE request_id='rollback'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("receipt leaked: %d %v", count, err)
	}
}

func TestInvestigationUnshareAndArtifactIntegrity(t *testing.T) {
	s, st, _, _, worker := investigationFixture(t)
	ctx := t.Context()
	now := time.Now().UTC()
	filter := SearchEventsRequest{From: now.Add(-time.Hour), To: now}
	command := map[string]any{"search": map[string]any{"application_id": "example-api", "environment_id": "test", "title": "Shared example", "shared": true, "filter": filter}, "request_id": "create-shared"}
	rec := investigationRequest(t, s, "operator", "POST", "/v1/saved-searches", command, 200)
	var reply struct {
		Search store.SavedSearch `json:"search"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if !reply.Search.Editable {
		t.Fatal("owner cannot edit")
	}
	rec = investigationRequest(t, s, "viewer", "GET", "/v1/saved-searches/"+reply.Search.ID, nil, 200)
	var viewerReply struct {
		Search store.SavedSearch `json:"search"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &viewerReply); err != nil {
		t.Fatal(err)
	}
	if viewerReply.Search.Editable {
		t.Fatal("reader can edit")
	}
	reply.Search.Shared = false
	investigationRequest(t, s, "operator", "PUT", "/v1/saved-searches/"+reply.Search.ID, map[string]any{"search": reply.Search, "request_id": "unshare"}, 200)
	investigationRequest(t, s, "viewer", "GET", "/v1/saved-searches/"+reply.Search.ID, nil, 404)
	investigationRequest(t, s, "viewer", "POST", "/v1/saved-searches/"+reply.Search.ID+":search", map[string]string{}, 404)
	rec = investigationRequest(t, s, "operator", "POST", "/v1/evidence", map[string]any{"application_id": "example-api", "environment_id": "test", "filter": filter, "request_id": "integrity"}, 202)
	var receipt struct {
		Export store.EvidenceExport `json:"export"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if err := worker.Once(ctx); err != nil {
		t.Fatal(err)
	}
	done, err := st.EvidenceExport(ctx, receipt.Export.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Objects.Delete(ctx, done.ArtifactKey); err != nil {
		t.Fatal(err)
	}
	if err := worker.Objects.Put(ctx, done.ArtifactKey, []byte("corrupt"), ""); err != nil {
		t.Fatal(err)
	}
	investigationRequest(t, s, "operator", "GET", "/v1/evidence/"+done.ID+"/download", nil, 503)
}
