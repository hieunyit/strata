package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A client-chosen role header must not unmask IPs or snippets.
func TestGetEvent_RoleHeaderDoesNotUnmask(t *testing.T) {
	server, _ := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/events/STR-8F3K-Q2VD-7XNM-A1PC", nil)
	req.Header.Set("X-User-Role", "admin")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp GetEventResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Event.ClientIP != "192.0.2.0/24" {
		t.Errorf("client_ip = %q, want masked 192.0.2.0/24", resp.Event.ClientIP)
	}
	for _, v := range resp.Event.Violations {
		if v.Snippet != "[REDACTED]" {
			t.Errorf("snippet = %q, want [REDACTED]", v.Snippet)
		}
	}
}

// The unauthenticated ingest endpoint is gone; events arrive over Fleet only.
func TestIngestEndpointRemoved(t *testing.T) {
	server, store := setupTestServer(t)
	before := store.Count()

	req := httptest.NewRequest(http.MethodPost, "/v1/events:ingest", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("POST /v1/events:ingest returned 200")
	}
	if store.Count() != before {
		t.Fatalf("store changed: %d -> %d", before, store.Count())
	}
}
