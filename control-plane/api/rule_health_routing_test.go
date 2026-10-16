package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	"github.com/strata/strata/control-plane/ingest"
)

func TestHealthRouteDoesNotShadowAdminRuleActions(t *testing.T) {
	issuer := authtest.New(t)
	verifier, err := auth.NewVerifier(context.Background(), auth.Config{Issuer: issuer.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv := api.NewServer(api.ServerConfig{Auth: verifier, Admin: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		// The actual gateway performs Fleet RBAC/audit. Verify dispatch and principal survive.
		if auth.FromContext(r.Context()).Subject != "route-test" {
			t.Error("missing principal")
		}
		w.WriteHeader(http.StatusAccepted)
	})}, ingest.NewMockEventStore())
	token := issuer.Token(t, authtest.Claims{Subject: "route-test", Roles: []string{"admin"}})
	for _, path := range []string{"/v1/rules/942100:emergencyDisable", "/v1/rules/942100:emergencyEnable", "/v1/rules/942100/details", "/v1/rules/942100/health/extra"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Errorf("%s: got %d, want gateway response", path, rec.Code)
		}
	}
	if calls != 4 {
		t.Fatalf("gateway calls=%d, want 4", calls)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/rules/942100/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || calls != 4 {
		t.Fatalf("health dispatch: %d, gateway calls=%d", rec.Code, calls)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/rules/942100:emergencyDisable", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || calls != 4 {
		t.Fatalf("unauthenticated action: %d, gateway calls=%d", rec.Code, calls)
	}
	for _, id := range []string{"0", "-1", "4294967296", "abc"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/rules/"+id+"/health", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("invalid ID %s: %d", id, rec.Code)
		}
	}

}
