package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func getEvent(t *testing.T, server *Server, token string, header map[string]string) (*httptest.ResponseRecorder, GetEventResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/events/STR-8F3K-Q2VD-7XNM-A1PC", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	var resp GetEventResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rec, resp
}

func TestEvents_NoTokenIs401(t *testing.T) {
	server, _ := setupTestServer(t)
	for _, token := range []string{"", "not-a-role"} {
		rec, _ := getEvent(t, server, token, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: status = %d, want 401", token, rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("token %q: no WWW-Authenticate header", token)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/events:search", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("search without token: status = %d, want 401", rec.Code)
	}
}

// Every role reads events; only viewer gets them masked, whatever role a
// header claims.
func TestEvents_MaskingByRole(t *testing.T) {
	server, _ := setupTestServer(t)
	for _, tc := range []struct {
		role   string
		masked bool
	}{{"viewer", true}, {"operator", false}, {"approver", false}, {"admin", false}} {
		rec, resp := getEvent(t, server, tc.role, map[string]string{"X-User-Role": "admin"})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d: %s", tc.role, rec.Code, rec.Body.String())
		}
		ipMasked := resp.Event.ClientIP == "192.0.2.0/24"
		if ipMasked != tc.masked {
			t.Errorf("%s: client_ip = %q, masked = %v", tc.role, resp.Event.ClientIP, tc.masked)
		}
		for _, v := range resp.Event.Violations {
			if (v.Snippet == "[REDACTED]") != tc.masked {
				t.Errorf("%s: snippet = %q, masked = %v", tc.role, v.Snippet, tc.masked)
			}
		}
	}
}

// The unauthenticated ingest endpoint is gone; events arrive over Fleet only.
func TestIngestEndpointRemoved(t *testing.T) {
	server, store := setupTestServer(t)
	before := store.Count()

	req := httptest.NewRequest(http.MethodPost, "/v1/events:ingest", nil)
	req.Header.Set("Authorization", "Bearer admin")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("POST /v1/events:ingest returned 200")
	}
	if store.Count() != before {
		t.Fatalf("store changed: %d -> %d", before, store.Count())
	}
}

func TestHealthzNeedsNoToken(t *testing.T) {
	server, _ := setupTestServer(t)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}
