package auth_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
)

// CP-A06: a token issued, or valid from, further in the future than the
// allowed clock skew is refused; within it, accepted.
func TestVerifier_ClockSkew(t *testing.T) {
	is := authtest.New(t)
	v := newVerifier(t, is)
	soon := time.Now().Add(auth.MaxClockSkew / 2)
	late := time.Now().Add(auth.MaxClockSkew + time.Minute)
	for name, tc := range map[string]struct {
		c    authtest.Claims
		want bool
	}{
		"issued now":               {authtest.Claims{Roles: []string{"viewer"}}, true},
		"issued within the skew":   {authtest.Claims{IssuedAt: soon}, true},
		"issued in the future":     {authtest.Claims{IssuedAt: late, Expiry: late.Add(5 * time.Minute)}, false},
		"valid from within skew":   {authtest.Claims{NotBefore: soon}, true},
		"valid only in the future": {authtest.Claims{NotBefore: time.Now().Add(4 * time.Minute)}, false},
	} {
		_, err := v.Authenticate(context.Background(), is.Token(t, tc.c))
		if (err == nil) != tc.want {
			t.Errorf("%s: accepted=%v %v", name, err == nil, err)
		}
	}
}

// CP-A06: role mapping never grants a role from a claim of another shape:
// missing, not an object, not a list, entries that are not strings,
// unknown or differently cased names.
func TestVerifier_RoleMappingShapes(t *testing.T) {
	is := authtest.New(t)
	v := newVerifier(t, is)
	for name, tc := range map[string]struct {
		extra map[string]any
		want  string
	}{
		"roles list":          {map[string]any{"realm_access": map[string]any{"roles": []any{"approver", "uma_authorization"}}}, "[approver]"},
		"no realm_access":     {map[string]any{"realm_access": nil}, "[]"},
		"realm_access string": {map[string]any{"realm_access": "admin"}, "[]"},
		"roles a string":      {map[string]any{"realm_access": map[string]any{"roles": "admin"}}, "[]"},
		"roles an object":     {map[string]any{"realm_access": map[string]any{"roles": map[string]any{"admin": true}}}, "[]"},
		"empty list":          {map[string]any{"realm_access": map[string]any{"roles": []any{}}}, "[]"},
		"non-string entries":  {map[string]any{"realm_access": map[string]any{"roles": []any{1, true, map[string]any{"name": "admin"}, "viewer"}}}, "[viewer]"},
		"other case":          {map[string]any{"realm_access": map[string]any{"roles": []any{"Admin", "ADMIN"}}}, "[]"},
		"roles elsewhere":     {map[string]any{"realm_access": map[string]any{}, "roles": []any{"admin"}}, "[]"},
	} {
		p, err := v.Authenticate(context.Background(), is.Token(t, authtest.Claims{Extra: tc.extra}))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := fmt.Sprint(p.Roles); got != tc.want {
			t.Errorf("%s: roles %s, want %s", name, got, tc.want)
		}
	}
	// another path, configured (e.g. a client role of another IdP layout)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nested, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience, RolesClaim: "resource_access.strata-api.roles"})
	if err != nil {
		t.Fatal(err)
	}
	tok := is.Token(t, authtest.Claims{Roles: []string{"admin"},
		Extra: map[string]any{"resource_access": map[string]any{"strata-api": map[string]any{"roles": []any{"operator"}}}}})
	if p, err := nested.Authenticate(context.Background(), tok); err != nil || fmt.Sprint(p.Roles) != "[operator]" {
		t.Fatalf("configured path: %v %v", p, err)
	}
}
