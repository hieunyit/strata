package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

type mockAuditStore struct {
	entries []store.Audit
}

func (m *mockAuditStore) AuditEntries(_ context.Context, limit int) ([]store.Audit, error) {
	if limit > len(m.entries) {
		return m.entries, nil
	}
	return m.entries[:limit], nil
}

func TestAuditEndpoint_RBAC(t *testing.T) {
	now := time.Now().UTC()
	mock := &mockAuditStore{
		entries: []store.Audit{
			{
				At:       now,
				Actor:    "admin",
				Channel:  "ui",
				Action:   "/strata.admin.v1.FleetAdminService/RevokeNode",
				Resource: "nodes/node-1",
			},
		},
	}

	h := NewServer(ServerConfig{
		Auth:  tokenRoles{},
		Audit: mock,
	}, ingest.NewMockEventStore()).Handler()

	// 1. Viewer token -> 403 Forbidden
	req := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer viewer")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer got %d, want 403", rec.Code)
	}

	// 2. Admin token -> 200 OK with audit entries
	req = httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer admin")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin got %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		Entries []store.Audit `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(res.Entries))
	}
	if res.Entries[0].Resource != "nodes/node-1" {
		t.Fatalf("got resource %q, want nodes/node-1", res.Entries[0].Resource)
	}

	// 3. POST method -> 405 Method Not Allowed
	req = httptest.NewRequest(http.MethodPost, "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer admin")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST got %d, want 405", rec.Code)
	}
}
