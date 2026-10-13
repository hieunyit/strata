package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
)

// localServer: local accounts on a real PostgreSQL (skipped without
// STRATA_TEST_POSTGRES_DSN), next to the test OIDC stand-in tokenRoles.
func localServer(t *testing.T) *Server {
	t.Helper()
	st := localauth.NewStore(localauthtest.Pool(t))
	svc, err := localauth.NewService(st, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Bootstrap(t.Context(), "admin", "first admin password"); err != nil {
		t.Fatal(err)
	}
	return NewServer(ServerConfig{
		Auth:  auth.Dispatch{LocalPrefix: localauth.TokenPrefix, Local: svc, OIDC: tokenRoles{}},
		Local: &localauth.Handler{Service: svc, Store: st},
		OIDC:  true,
	}, ingest.NewMockEventStore())
}

func do(t *testing.T, s *Server, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "192.0.2.10:5555"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func login(t *testing.T, s *Server, user, pw string) string {
	t.Helper()
	code, body := do(t, s, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": user, "password": pw})
	if code != http.StatusOK {
		t.Fatalf("login %s: %d %v", user, code, body)
	}
	return body["token"].(string)
}

func TestLocalAuth_HTTP(t *testing.T) {
	s := localServer(t)

	code, body := do(t, s, http.MethodGet, "/v1/auth/methods", "", nil)
	if code != http.StatusOK || body["local"] != true || body["oidc"] != true {
		t.Fatalf("methods: %d %v", code, body)
	}
	code, body = do(t, s, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": "admin", "password": "wrong password!"})
	if code != http.StatusUnauthorized || !strings.Contains(body["error"].(string), "invalid username or password") {
		t.Fatalf("wrong password: %d %v", code, body)
	}
	if code, _ := do(t, s, http.MethodPost, "/v1/auth/login", "", map[string]any{"username": "admin", "password": "x", "admin": true}); code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", code)
	}
	if code, _ := do(t, s, http.MethodGet, "/v1/auth/login", "", nil); code != http.StatusMethodNotAllowed {
		t.Errorf("GET login: %d", code)
	}
	admin := login(t, s, "admin", "first admin password")

	code, body = do(t, s, http.MethodGet, "/v1/auth/me", admin, nil)
	if code != http.StatusOK || body["username"] != "admin" || body["local"] != true {
		t.Fatalf("me: %d %v", code, body)
	}
	// An SSO caller is not local and has no password here.
	code, body = do(t, s, http.MethodGet, "/v1/auth/me", "operator", nil)
	if code != http.StatusOK || body["local"] != false {
		t.Errorf("me for SSO: %d %v", code, body)
	}
	if code, _ := do(t, s, http.MethodPost, "/v1/auth/password", "operator", map[string]string{"current_password": "a", "new_password": "b"}); code != http.StatusBadRequest {
		t.Errorf("SSO password change: %d", code)
	}

	// Accounts: admins only.
	for _, tok := range []string{"operator", "viewer", "approver"} {
		if code, _ := do(t, s, http.MethodGet, "/v1/users", tok, nil); code != http.StatusForbidden {
			t.Errorf("%s lists users: %d", tok, code)
		}
	}
	if code, _ := do(t, s, http.MethodGet, "/v1/users", "", nil); code != http.StatusUnauthorized {
		t.Errorf("anonymous lists users: %d", code)
	}
	code, body = do(t, s, http.MethodPost, "/v1/users", admin, map[string]any{"username": "Helpdesk.1", "password": "helpdesk password", "roles": []string{"viewer"}})
	if code != http.StatusOK || body["user"].(map[string]any)["username"] != "helpdesk.1" {
		t.Fatalf("create: %d %v", code, body)
	}
	if _, has := body["user"].(map[string]any)["password_hash"]; has {
		t.Error("the API returned a password hash")
	}
	for name, req := range map[string]map[string]any{
		"weak":      {"username": "x1", "password": "short", "roles": []string{"viewer"}},
		"bad name":  {"username": "a b", "password": "long enough pw", "roles": []string{"viewer"}},
		"bad role":  {"username": "x2", "password": "long enough pw", "roles": []string{"root"}},
		"duplicate": {"username": "helpdesk.1", "password": "long enough pw", "roles": []string{"viewer"}},
	} {
		code, _ := do(t, s, http.MethodPost, "/v1/users", admin, req)
		want := http.StatusBadRequest
		if name == "duplicate" {
			want = http.StatusConflict
		}
		if code != want {
			t.Errorf("%s: %d, want %d", name, code, want)
		}
	}
	code, body = do(t, s, http.MethodGet, "/v1/users", admin, nil)
	if code != http.StatusOK || len(body["users"].([]any)) != 2 {
		t.Fatalf("list: %d %v", code, body)
	}

	// The new viewer signs in and reads statistics, not accounts.
	viewer := login(t, s, "helpdesk.1", "helpdesk password")
	if code, _ := do(t, s, http.MethodGet, "/v1/stats/overview", viewer, nil); code != http.StatusOK {
		t.Errorf("viewer overview: %d", code)
	}
	if code, _ := do(t, s, http.MethodGet, "/v1/users", viewer, nil); code != http.StatusForbidden {
		t.Errorf("viewer lists users: %d", code)
	}
	if code, _ := do(t, s, http.MethodPost, "/v1/auth/password", viewer, map[string]string{"current_password": "helpdesk password", "new_password": "helpdesk password 2"}); code != http.StatusNoContent {
		t.Errorf("own password change: %d", code)
	}

	// The last admin stays; disabling the viewer ends its session.
	if code, _ := do(t, s, http.MethodPatch, "/v1/users/admin", admin, map[string]any{"roles": []string{"viewer"}}); code != http.StatusConflict {
		t.Errorf("demote last admin: %d", code)
	}
	if code, _ := do(t, s, http.MethodPatch, "/v1/users/helpdesk.1", admin, map[string]any{"disabled": true}); code != http.StatusOK {
		t.Errorf("disable: %d", code)
	}
	if code, _ := do(t, s, http.MethodGet, "/v1/auth/me", viewer, nil); code != http.StatusUnauthorized {
		t.Errorf("disabled account's session: %d", code)
	}
	if code, _ := do(t, s, http.MethodDelete, "/v1/users/helpdesk.1", admin, nil); code != http.StatusNoContent {
		t.Errorf("delete: %d", code)
	}
	if code, _ := do(t, s, http.MethodDelete, "/v1/users/helpdesk.1", admin, nil); code != http.StatusNotFound {
		t.Errorf("delete again: %d", code)
	}

	// Logout.
	if code, _ := do(t, s, http.MethodPost, "/v1/auth/logout", admin, nil); code != http.StatusNoContent {
		t.Errorf("logout: %d", code)
	}
	if code, _ := do(t, s, http.MethodGet, "/v1/auth/me", admin, nil); code != http.StatusUnauthorized {
		t.Errorf("after logout: %d", code)
	}
}

func TestAuthMethodsWithoutLocal(t *testing.T) {
	s := NewServer(ServerConfig{Auth: tokenRoles{}, OIDC: true}, ingest.NewMockEventStore())
	code, body := do(t, s, http.MethodGet, "/v1/auth/methods", "", nil)
	if code != http.StatusOK || body["local"] != false || body["oidc"] != true {
		t.Errorf("methods: %d %v", code, body)
	}
	if code, _ := do(t, s, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": "a", "password": "b"}); code != http.StatusUnauthorized {
		t.Errorf("login without local accounts: %d (the route must not exist outside the auth middleware)", code)
	}
}
