package auth

import (
	"context"
	"testing"
	"time"
)

func TestServiceAccountAuth(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryServiceAccountStore()
	authn := NewServiceAccountAuthenticator(store)

	sa := ServiceAccount{
		ID:        "sa-ci-cd-bot",
		Name:      "CI/CD Deployer Bot",
		Roles:     []Role{RoleOperator},
		CreatedAt: time.Now(),
		CreatedBy: "admin@strata.internal",
	}
	if err := store.CreateServiceAccount(ctx, sa); err != nil {
		t.Fatalf("failed to create sa: %v", err)
	}

	// 1. Issue scoped token
	scopes := []Permission{PermPoliciesRead, PermPoliciesWrite}
	rawToken, tok, err := GenerateToken(sa.ID, scopes, 2*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if err := store.CreateToken(ctx, tok); err != nil {
		t.Fatalf("failed to store token: %v", err)
	}

	// 2. Authenticate with valid token
	p, err := authn.Authenticate(ctx, rawToken)
	if err != nil {
		t.Fatalf("authentication failed: %v", err)
	}

	if p.Subject != "sa:sa-ci-cd-bot" {
		t.Errorf("expected subject sa:sa-ci-cd-bot, got %q", p.Subject)
	}
	if !p.Can(PermPoliciesRead) {
		t.Errorf("expected Can(PermPoliciesRead) to be true")
	}
	if !p.Can(PermPoliciesWrite) {
		t.Errorf("expected Can(PermPoliciesWrite) to be true")
	}
	// PermAuditRead is NOT in scopes
	if p.Can(PermAuditRead) {
		t.Errorf("expected Can(PermAuditRead) to be false")
	}

	// 3. Expired token
	_, expTok, err := GenerateToken(sa.ID, scopes, -1*time.Minute)
	if err == nil {
		t.Errorf("expected error for negative TTL")
	}

	rawExpToken, expTok, err := GenerateToken(sa.ID, scopes, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("generate token failed: %v", err)
	}
	expTok.ExpiresAt = time.Now().Add(-1 * time.Second) // Force expired
	_ = store.CreateToken(ctx, expTok)

	if _, err := authn.Authenticate(ctx, rawExpToken); err == nil {
		t.Errorf("expected authentication to fail for expired token")
	}

	// 4. Revoked token
	if err := store.RevokeToken(ctx, tok.ID); err != nil {
		t.Fatalf("failed to revoke token: %v", err)
	}

	if _, err := authn.Authenticate(ctx, rawToken); err == nil {
		t.Errorf("expected authentication to fail for revoked token")
	}
}

func TestDispatchWithServiceAccount(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryServiceAccountStore()
	saAuthn := NewServiceAccountAuthenticator(store)

	sa := ServiceAccount{ID: "sa-test", Name: "Test SA", Roles: []Role{RoleViewer}}
	_ = store.CreateServiceAccount(ctx, sa)
	rawTok, tok, _ := GenerateToken(sa.ID, []Permission{PermVersionRead}, 1*time.Hour)
	_ = store.CreateToken(ctx, tok)

	dispatch := Dispatch{
		ServiceAccountPrefix: ServiceAccountTokenPrefix,
		ServiceAccount:       saAuthn,
	}

	p, err := dispatch.Authenticate(ctx, rawTok)
	if err != nil {
		t.Fatalf("dispatch auth failed: %v", err)
	}
	if p.Subject != "sa:sa-test" {
		t.Errorf("expected subject sa:sa-test, got %q", p.Subject)
	}
}
