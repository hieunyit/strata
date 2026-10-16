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

func TestServiceAccount_ScopeCeilingAdminRole(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryServiceAccountStore()
	authn := NewServiceAccountAuthenticator(store)

	// SA has RoleAdmin (which allows everything)
	sa := ServiceAccount{
		ID:    "sa-admin-bot",
		Name:  "Admin Bot",
		Roles: []Role{RoleAdmin},
	}
	_ = store.CreateServiceAccount(ctx, sa)

	// Issue token with ONLY PermPoliciesRead
	rawTok, tok, err := GenerateToken(sa.ID, []Permission{PermPoliciesRead}, 1*time.Hour)
	if err != nil {
		t.Fatalf("generate token failed: %v", err)
	}
	_ = store.CreateToken(ctx, tok)

	p, err := authn.Authenticate(ctx, rawTok)
	if err != nil {
		t.Fatalf("auth failed: %v", err)
	}

	// PermPoliciesRead is allowed (both by scope and by admin role)
	if !p.Can(PermPoliciesRead) {
		t.Errorf("expected Can(PermPoliciesRead) to be true")
	}

	// PermPoliciesWrite MUST BE DENIED despite RoleAdmin, because it's not in scopes!
	if p.Can(PermPoliciesWrite) {
		t.Errorf("SECURITY FLAW: Can(PermPoliciesWrite) should be false when not in token scopes, even if role is admin")
	}

	// PermAuditRead MUST BE DENIED
	if p.Can(PermAuditRead) {
		t.Errorf("SECURITY FLAW: Can(PermAuditRead) should be false when not in token scopes")
	}
}

func TestServiceAccount_SoftRevocationAndTokenCount(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryServiceAccountStore()
	authn := NewServiceAccountAuthenticator(store)

	sa := ServiceAccount{
		ID:    "sa-ops",
		Name:  "Ops Bot",
		Roles: []Role{RoleOperator},
	}
	_ = store.CreateServiceAccount(ctx, sa)

	// Issue 2 tokens
	raw1, tok1, _ := GenerateToken(sa.ID, []Permission{PermPoliciesRead}, 1*time.Hour)
	_ = store.CreateToken(ctx, tok1)

	_, tok2, _ := GenerateToken(sa.ID, []Permission{PermPoliciesRead}, 1*time.Hour)
	_ = store.CreateToken(ctx, tok2)

	// Check token count
	saList, err := store.ListServiceAccounts(ctx)
	if err != nil || len(saList) != 1 {
		t.Fatalf("unexpected list: %v", err)
	}
	if saList[0].TokenCount != 2 {
		t.Errorf("expected TokenCount=2, got %d", saList[0].TokenCount)
	}

	// Revoke tok1
	if err := store.RevokeToken(ctx, tok1.ID); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	// Token 1 cannot authenticate
	if _, err := authn.Authenticate(ctx, raw1); err == nil {
		t.Errorf("expected authentication failure for revoked token")
	}

	// ListTokens preserves revoked token for audit visibility
	tokens, err := store.ListTokens(ctx, sa.ID)
	if err != nil {
		t.Fatalf("list tokens failed: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens in list, got %d", len(tokens))
	}
	var revTok *ServiceAccountToken
	for i := range tokens {
		if tokens[i].ID == tok1.ID {
			revTok = &tokens[i]
			break
		}
	}
	if revTok == nil || !revTok.Revoked || revTok.RevokedAt == nil {
		t.Errorf("expected revoked token with Revoked=true and RevokedAt!=nil, got %+v", revTok)
	}

	// Active token count decremented to 1
	saAfter, err := store.GetServiceAccount(ctx, sa.ID)
	if err != nil {
		t.Fatalf("get sa failed: %v", err)
	}
	if saAfter.TokenCount != 1 {
		t.Errorf("expected active TokenCount=1 after revocation, got %d", saAfter.TokenCount)
	}
}
