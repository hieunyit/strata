package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCredentialTransportRejectsQueryTokens(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "/v1/stats/geo:watch?token=example-secret", nil)
			if got := TokenFromRequest(r); got != "" {
				t.Fatal("query credentials must not authenticate")
			}
			r.Header.Set("Authorization", "Bearer header-example")
			if got := TokenFromRequest(r); got != "header-example" {
				t.Fatal("header credential was not retained")
			}
		})
	}
}

func TestServiceAccountRejectsUnboundedScopesAndTTL(t *testing.T) {
	for _, scopes := range [][]Permission{nil, {}, {"*"}, {"unknown:write"}} {
		if _, _, err := GenerateToken("example-account", scopes, time.Hour); err == nil {
			t.Errorf("accepted scopes %v", scopes)
		}
	}
	if _, _, err := GenerateToken("example-account", []Permission{PermPoliciesRead}, 366*24*time.Hour); err == nil {
		t.Error("accepted TTL beyond one year")
	}
}

func TestServiceAccountRejectsLegacyUnscopedCredentials(t *testing.T) {
	ctx := context.Background()
	s := newTestCredentialStore()
	if err := s.CreateServiceAccount(ctx, ServiceAccount{ID: "example-account", Roles: []Role{RoleAdmin}}); err != nil {
		t.Fatal(err)
	}
	raw, tok, err := GenerateToken("example-account", []Permission{PermPoliciesRead}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok.Scopes = nil
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServiceAccountAuthenticator(s).Authenticate(ctx, raw); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("legacy empty scopes must fail closed: %v", err)
	}
}

func TestServiceAccountScopeOwnership(t *testing.T) {
	ctx := context.Background()
	s := newTestCredentialStore()
	roles := []Role{RoleViewer}
	if err := s.CreateServiceAccount(ctx, ServiceAccount{ID: "example-account", Roles: roles}); err != nil {
		t.Fatal(err)
	}
	roles[0] = RoleAdmin
	scopes := []Permission{PermPoliciesRead}
	raw, tok, err := GenerateToken("example-account", scopes, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	scopes[0] = PermPoliciesWrite
	if tok.Scopes[0] != PermPoliciesRead {
		t.Fatal("token aliases caller scopes")
	}
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	tok.Scopes[0] = PermPoliciesWrite
	p, err := NewServiceAccountAuthenticator(s).Authenticate(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Can(PermPoliciesRead) || p.Can(PermPoliciesWrite) {
		t.Fatal("caller-owned slices changed credential privileges")
	}
	p.Scopes[0] = PermPoliciesWrite
	p.Roles[0] = RoleAdmin
	again, err := NewServiceAccountAuthenticator(s).Authenticate(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Can(PermPoliciesRead) || again.Can(PermPoliciesWrite) {
		t.Fatal("principal aliases credential storage")
	}
	if strings.Contains(tok.TokenHash, raw) {
		t.Fatal("plaintext secret stored")
	}
}

func TestExplicitScopesNeverBroadenRolePrivileges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		principal *Principal
		want      bool
	}{
		{"legacy roles", &Principal{Roles: []Role{RoleViewer}}, true},
		{"empty explicit ceiling", &Principal{Roles: []Role{RoleAdmin}, Scopes: []Permission{}}, false},
		{"wildcard ceiling", &Principal{Roles: []Role{RoleAdmin}, Scopes: []Permission{"*"}}, false},
		{"scope without role", &Principal{Scopes: []Permission{PermEventsRead}}, false},
		{"intersection", &Principal{Roles: []Role{RoleViewer}, Scopes: []Permission{PermEventsRead}}, true},
		{"scope excludes permission", &Principal{Roles: []Role{RoleAdmin}, Scopes: []Permission{PermPoliciesWrite}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.principal.Can(PermEventsRead); got != tc.want {
				t.Fatalf("permission=%v want %v", got, tc.want)
			}
		})
	}
}
