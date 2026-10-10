package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
)

func newVerifier(t *testing.T, is *authtest.Issuer) *auth.Verifier {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifier_AcceptsValidToken(t *testing.T) {
	is := authtest.New(t)
	v := newVerifier(t, is)
	p, err := v.Authenticate(context.Background(), is.Token(t, authtest.Claims{
		Subject: "alice", Roles: []string{"operator", "viewer", "offline_access", "operator"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "alice" || p.Name != "alice" {
		t.Errorf("principal = %+v", p)
	}
	// Unknown roles are dropped, duplicates removed, order stable.
	if got := p.Roles; len(got) != 2 || got[0] != auth.RoleOperator || got[1] != auth.RoleViewer {
		t.Errorf("roles = %v", got)
	}
}

func TestVerifier_RejectsBadTokens(t *testing.T) {
	is := authtest.New(t)
	v := newVerifier(t, is)
	for name, tok := range map[string]string{
		"empty":          "",
		"garbage":        "not.a.jwt",
		"expired":        is.Token(t, authtest.Claims{Expiry: time.Now().Add(-time.Minute)}),
		"wrong audience": is.Token(t, authtest.Claims{Audience: "account"}),
		"wrong issuer":   is.Token(t, authtest.Claims{Issuer: "https://evil.example.test"}),
		"foreign key":    is.ForeignToken(t, "admin"),
		"alg none":       unsigned(is.Token(t, authtest.Claims{Roles: []string{"admin"}})),
	} {
		if _, err := v.Authenticate(context.Background(), tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// unsigned rewrites a token's header to alg=none and drops the signature.
func unsigned(tok string) string {
	parts := strings.Split(tok, ".")
	return "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + parts[1] + "."
}

func TestVerifier_DiscoveryURL(t *testing.T) {
	is := authtest.New(t)
	// The control plane reads metadata at is.URL, but tokens name the
	// public issuer, which it cannot reach.
	const public = "https://sso.example.test/realms/strata"
	v, err := auth.NewVerifier(context.Background(), auth.Config{Issuer: public, DiscoveryURL: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Authenticate(context.Background(), is.Token(t, authtest.Claims{Issuer: public, Roles: []string{"viewer"}})); err != nil {
		t.Errorf("token from the public issuer: %v", err)
	}
	if _, err := v.Authenticate(context.Background(), is.Token(t, authtest.Claims{Roles: []string{"viewer"}})); err == nil {
		t.Error("token naming the discovery URL as issuer accepted")
	}
}

// A registered method without a permission is refused, even for admin.
func TestInterceptor_UnlistedMethodDenied(t *testing.T) {
	is := authtest.New(t)
	v := newVerifier(t, is)
	perms := auth.MethodPermissions{"/x.v1.S/Listed": auth.PermVersionRead}
	icpt := auth.UnaryInterceptor(v, perms)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+is.Token(t, authtest.Claims{Roles: []string{"admin"}})))
	called := false
	h := func(ctx context.Context, _ any) (any, error) {
		called = auth.FromContext(ctx) != nil
		return nil, nil
	}
	if _, err := icpt(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x.v1.S/Unlisted"}, h); status.Code(err) != codes.PermissionDenied || called {
		t.Fatalf("unlisted: err = %v, handler called = %v", err, called)
	}
	if _, err := icpt(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x.v1.S/Listed"}, h); err != nil || !called {
		t.Fatalf("listed: err = %v, handler saw principal = %v", err, called)
	}
}

func TestRoleMatrix(t *testing.T) {
	want := map[auth.Permission][]auth.Role{
		auth.PermVersionRead:         auth.Roles,
		auth.PermEventsRead:          auth.Roles,
		auth.PermPoliciesRead:        auth.Roles,
		auth.PermNodesRead:           auth.Roles,
		auth.PermEventsReadSensitive: {auth.RoleOperator, auth.RoleApprover, auth.RoleAdmin},
		auth.PermPoliciesWrite:       {auth.RoleOperator, auth.RoleAdmin},
		auth.PermPoliciesDeploy:      {auth.RoleOperator, auth.RoleAdmin},
		auth.PermExceptionsWrite:     {auth.RoleOperator, auth.RoleAdmin},
		auth.PermPoliciesApprove:     {auth.RoleApprover, auth.RoleAdmin},
		auth.PermNodesWrite:          {auth.RoleAdmin},
		auth.PermRoleBindingsRead:    {auth.RoleAdmin},
		auth.PermRoleBindingsWrite:   {auth.RoleAdmin},
		auth.PermAuditRead:           {auth.RoleAdmin},
		"unknown:perm":               nil,
	}
	for perm, roles := range want {
		for _, r := range auth.Roles {
			expected := false
			for _, x := range roles {
				expected = expected || x == r
			}
			if r.Allows(perm) != expected {
				t.Errorf("%s allows %s = %v, want %v", r, perm, !expected, expected)
			}
		}
	}
}

// Over HTTP: no or bad token -> 401; each of the four roles gets 403 on a
// route whose permission it lacks and 200 otherwise.
func TestHTTP_401And403ForEachRole(t *testing.T) {
	is := authtest.New(t)
	v := newVerifier(t, is)
	mux := http.NewServeMux()
	perms := []auth.Permission{auth.PermEventsRead, auth.PermEventsReadSensitive, auth.PermPoliciesDeploy, auth.PermPoliciesApprove, auth.PermAuditRead}
	for _, p := range perms {
		mux.HandleFunc("/v1/"+string(p), auth.RequireHTTP(p, func(w http.ResponseWriter, _ *http.Request) {}))
	}
	h := auth.Middleware(v, mux)
	do := func(path, token string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, tok := range []string{"", "x", is.ForeignToken(t, "admin")} {
		if c := do("/v1/events:read", tok); c != http.StatusUnauthorized {
			t.Errorf("bad token: %d, want 401", c)
		}
	}
	saw403 := map[auth.Role]bool{}
	for _, r := range auth.Roles {
		tok := is.Token(t, authtest.Claims{Roles: []string{string(r)}})
		for _, p := range perms {
			want := http.StatusOK
			if !r.Allows(p) {
				want = http.StatusForbidden
				saw403[r] = true
			}
			if c := do("/v1/"+string(p), tok); c != want {
				t.Errorf("%s on %s: %d, want %d", r, p, c, want)
			}
		}
	}
	for _, r := range auth.Roles {
		if r != auth.RoleAdmin && !saw403[r] {
			t.Errorf("no route refused %s", r)
		}
	}
	// A token without any known role is authenticated but may do nothing.
	if c := do("/v1/events:read", is.Token(t, authtest.Claims{Roles: []string{"offline_access"}})); c != http.StatusForbidden {
		t.Errorf("no role: %d, want 403", c)
	}
}
