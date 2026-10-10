package admin_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/api"
	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/auth/authtest"
	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
	"github.com/strata/strata/control-plane/ingest"
)

type env struct {
	is   *authtest.Issuer
	rest http.Handler
	conn *grpc.ClientConn
}

func setup(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	is := authtest.New(t)
	v, err := auth.NewVerifier(ctx, auth.Config{Issuer: is.URL, Audience: authtest.Audience})
	if err != nil {
		t.Fatal(err)
	}
	a, err := admin.New(ctx, v, admin.BuildInfo{Version: "0.1.0-test", Commit: "abc123"}, admin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = a.GRPC.Serve(lis) }()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	srv := api.NewServer(api.ServerConfig{Auth: v, Admin: a.Gateway}, ingest.NewMockEventStore())
	return &env{is: is, rest: srv.Handler(), conn: conn}
}

func (e *env) get(t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.rest.ServeHTTP(rec, req)
	return rec
}

func TestVersion_REST(t *testing.T) {
	e := setup(t)
	if rec := e.get(t, "/v1/version", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", rec.Code)
	}
	for _, r := range auth.Roles {
		rec := e.get(t, "/v1/version", e.is.Token(t, authtest.Claims{Roles: []string{string(r)}}))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", r, rec.Code, rec.Body.String())
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["version"] != "0.1.0-test" || body["commit"] != "abc123" || body["api_version"] != "v1" {
			t.Fatalf("%s: body = %v", r, body)
		}
	}
	// Authenticated but without any role: the gRPC interceptor refuses it
	// and the gateway turns that into 403.
	if rec := e.get(t, "/v1/version", e.is.Token(t, authtest.Claims{Roles: []string{"offline_access"}})); rec.Code != http.StatusForbidden {
		t.Fatalf("no role: %d, want 403", rec.Code)
	}
}

func TestVersion_GRPC(t *testing.T) {
	e := setup(t)
	c := adminv1.NewVersionServiceClient(e.conn)
	call := func(token string) (*adminv1.GetVersionResponse, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		}
		return c.GetVersion(ctx, &adminv1.GetVersionRequest{})
	}
	if _, err := call(""); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v, want Unauthenticated", err)
	}
	if _, err := call(e.is.ForeignToken(t, "admin")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("foreign token: %v, want Unauthenticated", err)
	}
	if _, err := call(e.is.Token(t, authtest.Claims{Roles: []string{"offline_access"}})); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no role: %v, want PermissionDenied", err)
	}
	resp, err := call(e.is.Token(t, authtest.Claims{Roles: []string{"viewer"}}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetVersion() != "0.1.0-test" || resp.GetApiVersion() != "v1" {
		t.Fatalf("resp = %v", resp)
	}
}

// Every method the server registers has a permission.
func TestEveryMethodHasPermission(t *testing.T) {
	for _, sd := range []grpc.ServiceDesc{adminv1.VersionService_ServiceDesc, adminv1.FleetAdminService_ServiceDesc, adminv1.PolicyService_ServiceDesc, adminv1.RolloutService_ServiceDesc} {
		for _, m := range sd.Methods {
			full := "/" + sd.ServiceName + "/" + m.MethodName
			if _, ok := admin.Permissions[full]; !ok {
				t.Errorf("%s has no permission", full)
			}
		}
	}
}
