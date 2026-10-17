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

	// 2b. Attempt to create SA with malicious / invalid ID -> 400 Bad Request
	badBody, _ := json.Marshal(CreateServiceAccountRequest{
		ID:   "../malicious/sa",
		Name: "Bad SA",
	})
	badReq := httptest.NewRequest(http.MethodPost, "/v1/service-accounts", bytes.NewReader(badBody))
	badReq.Header.Set("Authorization", "Bearer admin")
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("malicious ID got status %d, want 400", badRec.Code)
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

func TestServiceAccountAPI_AuditLogging(t *testing.T) {
	saStore := auth.NewMemoryServiceAccountStore()
	mockAudit := &mockAuditStore{}

	dispatch := auth.Dispatch{
		OIDC: tokenRoles{}, // maps "admin" -> RoleAdmin
	}

	server := NewServer(ServerConfig{
		Auth:            dispatch,
		ServiceAccounts: saStore,
		Audit:           mockAudit,
	}, ingest.NewMockEventStore())
	handler := server.Handler()

	// 1. Create SA
	body, _ := json.Marshal(CreateServiceAccountRequest{
		ID:   "sa-audited",
		Name: "Audited Bot",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/service-accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create SA got status %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Issue Token
	tokBody, _ := json.Marshal(CreateTokenRequest{
		Scopes:     []auth.Permission{auth.PermPoliciesRead},
		TTLSeconds: 3600,
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/service-accounts/sa-audited/tokens", bytes.NewReader(tokBody))
	req.Header.Set("Authorization", "Bearer admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create token got status %d: %s", rec.Code, rec.Body.String())
	}
	var resp CreateTokenResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	// 3. Revoke Token
	req = httptest.NewRequest(http.MethodDelete, "/v1/service-accounts/sa-audited/tokens/"+resp.Token.ID, nil)
	req.Header.Set("Authorization", "Bearer admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke token got status %d", rec.Code)
	}

	// 4. Delete SA
	req = httptest.NewRequest(http.MethodDelete, "/v1/service-accounts/sa-audited", nil)
	req.Header.Set("Authorization", "Bearer admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete SA got status %d", rec.Code)
	}

	// Verify Audit entries
	if len(mockAudit.entries) != 4 {
		t.Fatalf("expected 4 audit entries, got %d", len(mockAudit.entries))
	}
	expectedActions := []string{
		"/v1/service-accounts:create",
		"/v1/service-accounts/tokens:create",
		"/v1/service-accounts/tokens:revoke",
		"/v1/service-accounts:delete",
	}
	for i, exp := range expectedActions {
		if mockAudit.entries[i].Action != exp {
			t.Errorf("entry %d action: got %q, want %q", i, mockAudit.entries[i].Action, exp)
		}
		if mockAudit.entries[i].Actor != "user-admin" {
			t.Errorf("entry %d actor: got %q, want 'user-admin'", i, mockAudit.entries[i].Actor)
		}
	}
}
