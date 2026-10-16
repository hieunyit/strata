package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
)

func TestServiceAccountAPI_LifecycleAndScoping(t *testing.T) {
	saStore := auth.NewMemoryServiceAccountStore()
	saAuthn := auth.NewServiceAccountAuthenticator(saStore)

	dispatch := auth.Dispatch{
		LocalPrefix:          "stl_",
		ServiceAccountPrefix: auth.ServiceAccountTokenPrefix,
		ServiceAccount:       saAuthn,
		OIDC:                 tokenRoles{}, // maps "admin" -> RoleAdmin, "viewer" -> RoleViewer
	}

	server := NewServer(ServerConfig{
		Auth:            dispatch,
		ServiceAccounts: saStore,
	}, ingest.NewMockEventStore())
	handler := server.Handler()

	// 1. Viewer attempts to create SA -> 403 Forbidden
	body, _ := json.Marshal(CreateServiceAccountRequest{
		ID:   "sa-deployer",
		Name: "Deployer Bot",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/service-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer viewer")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer got status %d, want 403", rec.Code)
	}

	// 2. Admin creates SA -> 201 Created
	req = httptest.NewRequest(http.MethodPost, "/v1/service-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin got status %d, want 201: %s", rec.Code, rec.Body.String())
	}

	// 3. Issue scoped token for sa-deployer (scope: events:read only)
	tokenReqBody, _ := json.Marshal(CreateTokenRequest{
		Scopes:     []auth.Permission{auth.PermEventsRead},
		TTLSeconds: 3600,
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/service-accounts/sa-deployer/tokens", bytes.NewReader(tokenReqBody))
	req.Header.Set("Authorization", "Bearer admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("token creation got %d, want 201: %s", rec.Code, rec.Body.String())
	}

	var tokenResp CreateTokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token resp: %v", err)
	}
	rawToken := tokenResp.RawToken
	if rawToken == "" {
		t.Fatalf("expected non-empty raw_token")
	}

	// 4. Use the issued service account token to call /v1/events:search -> should succeed (200 OK)
	searchBody, _ := json.Marshal(map[string]any{"limit": 10})
	req = httptest.NewRequest(http.MethodPost, "/v1/events:search", bytes.NewReader(searchBody))
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("search with SA token got %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// 5. Use the SA token to create another SA -> should fail with 403 (serviceaccounts:write not in scopes)
	req = httptest.NewRequest(http.MethodPost, "/v1/service-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SA token got %d, want 403 Forbidden for out-of-scope operation", rec.Code)
	}

	// 6. Revoke token
	req = httptest.NewRequest(http.MethodDelete, "/v1/service-accounts/sa-deployer/tokens/"+tokenResp.Token.ID, nil)
	req.Header.Set("Authorization", "Bearer admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke token got %d, want 204", rec.Code)
	}

	// 7. Call with revoked token -> 401 Unauthorized
	req = httptest.NewRequest(http.MethodPost, "/v1/events:search", bytes.NewReader(searchBody))
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked SA token got %d, want 401", rec.Code)
	}
}
