package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
	"github.com/strata/strata/control-plane/store"
)

func TestEventAnnotationAPIInPostgres(t *testing.T) {
	p := localauthtest.Pool(t)
	pg := store.New(p)
	_, events := setupTestServer(t)
	s := NewServer(ServerConfig{Auth: tokenRoles{}, Annotations: pg}, events)
	const block = "STR-8F3K-Q2VD-7XNM-A1PC"
	const endpoint = "/v1/events/" + block + ":markFalsePositive"
	for _, tc := range []struct {
		role string
		want int
	}{{"viewer", 403}, {"approver", 403}, {"operator", 200}, {"admin", 200}} {
		if _, err := p.Exec(t.Context(), `TRUNCATE event_annotations,event_annotation_requests,audit_log`); err != nil {
			t.Fatal(err)
		}
		code, body := do(t, s, http.MethodPost, endpoint, tc.role, map[string]string{"reason": "legitimate login", "request_id": "matrix"})
		if code != tc.want {
			t.Fatalf("%s: %d %v", tc.role, code, body)
		}
		rows, err := pg.EventAnnotations(t.Context(), []string{block})
		if err != nil {
			t.Fatal(err)
		}
		if (len(rows) == 1) != (tc.want == 200) {
			t.Fatalf("%s unexpectedly wrote: %+v", tc.role, rows)
		}
	}
	if _, err := p.Exec(t.Context(), `TRUNCATE event_annotations,event_annotation_requests,audit_log`); err != nil {
		t.Fatal(err)
	}
	code, body := do(t, s, http.MethodPost, endpoint, "operator", map[string]string{"reason": "normal request", "request_id": "persist"})
	if code != 200 || body["marked_by"] != "user-operator" || body["etag"] == "" {
		t.Fatalf("mark: %d %v", code, body)
	}
	etag := body["etag"]
	var bundle string
	if err := p.QueryRow(t.Context(), `SELECT report_bundle_version::text FROM rule_annotation_context WHERE block_id=$1`, block).Scan(&bundle); err != nil || bundle != "1" {
		t.Fatalf("API did not bind server bundle: %s %v", bundle, err)
	}
	// New server/store, same databases: both point lookup and search expose annotation.
	s = NewServer(ServerConfig{Auth: tokenRoles{}, Annotations: store.New(p)}, events)
	code, body = do(t, s, http.MethodGet, "/v1/events/"+block, "viewer", nil)
	if code != 200 {
		t.Fatalf("get: %d %v", code, body)
	}
	event := body["event"].(map[string]any)
	if event["false_positive"] != true || event["annotation_etag"] != etag || event["client_ip"] == "192.0.2.42" {
		t.Fatalf("overlay/privacy: %v", event)
	}
	code, body = do(t, s, http.MethodPost, "/v1/events:search", "operator", map[string]any{})
	if code != 200 {
		t.Fatalf("search: %d %v", code, body)
	}
	found := false
	for _, item := range body["events"].([]any) {
		e := item.(map[string]any)
		if e["block_id"] == block {
			found = e["false_positive"] == true
		}
	}
	if !found {
		t.Fatal("search lost annotation")
	}
	code, _ = do(t, s, http.MethodPost, endpoint, "operator", map[string]string{"reason": "normal request", "request_id": "persist"})
	if code != 200 {
		t.Fatal("retry lost idempotency")
	}
	code, _ = do(t, s, http.MethodPost, endpoint, "operator", map[string]string{"reason": "changed reason"})
	if code != 409 {
		t.Fatalf("missing etag=%d", code)
	}
	code, _ = do(t, s, http.MethodPost, endpoint, "operator", map[string]any{"reason": "changed reason", "etag": etag})
	if code != 200 {
		t.Fatalf("etag edit=%d", code)
	}
	if events.Count() != 3 {
		t.Fatalf("annotation rewrote raw events: %d", events.Count())
	}
	for _, raw := range []string{"", `{`, `{"reason":""}`, `{"reason":"ok","unknown":1}`, `{"reason":"ok"} {}`, `{"reason":"` + strings.Repeat("x", 501) + `"}`, strings.Repeat("x", 4097)} {
		req := httptest.NewRequest("POST", endpoint, strings.NewReader(raw))
		w := httptest.NewRecorder()
		serve(s, w, req)
		if w.Code != 400 {
			t.Fatalf("malformed body accepted: %d", w.Code)
		}
	}
	code, _ = do(t, s, http.MethodPost, "/v1/events/STR-0000-0000-0000-9999:markFalsePositive", "operator", map[string]string{"reason": "normal"})
	if code != 404 {
		t.Fatalf("missing event=%d", code)
	}
	code, _ = do(t, s, http.MethodGet, endpoint, "operator", nil)
	if code != 405 {
		t.Fatalf("GET mark=%d", code)
	}
	noPG := NewServer(ServerConfig{Auth: tokenRoles{}}, events)
	code, _ = do(t, noPG, http.MethodPost, endpoint, "operator", map[string]string{"reason": "normal"})
	if code != 503 {
		t.Fatalf("no persistence=%d", code)
	}
}
