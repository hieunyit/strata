package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

type unavailableAudit struct{}

func (unavailableAudit) AuditEntries(context.Context, int) ([]store.Audit, error) {
	return nil, errors.New("postgres://private-db:5432: synthetic database details")
}

func TestAuditRejectsInvalidQueryAndHidesStoreErrors(t *testing.T) {
	h := NewServer(ServerConfig{Auth: tokenRoles{}, Audit: unavailableAudit{}}, ingest.NewMockEventStore()).Handler()
	for _, query := range []string{"limit=501", "limit=-1", "limit=abc", "from=not-a-date", "from=2026-10-18T00:00:00Z&to=2026-10-17T00:00:00Z", "actor=a&actor=b", "actor=%00", "actor=%zz", "unknown=value", "actor=" + strings.Repeat("x", 257)} {
		r := httptest.NewRequest(http.MethodGet, "/v1/audit?"+query, nil)
		r.Header.Set("Authorization", "Bearer admin")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("query %q: got %d, want 400", query, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	r.Header.Set("Authorization", "Bearer admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "private-db") {
		t.Fatalf("store failure exposed internal details: %d %s", w.Code, w.Body.String())
	}
}

func TestAuditFiltersNeverFallBackToRecentRows(t *testing.T) {
	h := NewServer(ServerConfig{Auth: tokenRoles{}, Audit: &mockAuditStore{}}, ingest.NewMockEventStore()).Handler()
	r := httptest.NewRequest(http.MethodGet, "/v1/audit?actor=example-admin", nil)
	r.Header.Set("Authorization", "Bearer admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("silently ignored unsupported filter: %d %s", w.Code, w.Body.String())
	}
}
