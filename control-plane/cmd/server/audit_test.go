package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/store"
)

type auditAdmin struct{}

func (auditAdmin) Authenticate(context.Context, string) (*auth.Principal, error) {
	return &auth.Principal{Subject: "example-admin", Roles: []auth.Role{auth.RoleAdmin}}, nil
}

func TestAuditWithoutPostgresDoesNotRegisterNilReader(t *testing.T) {
	h := api.NewServer(api.ServerConfig{Auth: auditAdmin{}, Audit: auditReader(nil)}, ingest.NewMockEventStore()).Handler()
	req := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer fixture-admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("audit without a database returned %d, want 404", w.Code)
	}
}

func TestConfiguredAuditReaderIsKept(t *testing.T) {
	pg := &store.Store{}
	if auditReader(pg) != pg {
		t.Fatal("configured reader was lost")
	}
}
