package localauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
)

func newService(t *testing.T) (*Service, *Store) {
	t.Helper()
	st := NewStore(localauthtest.Pool(t))
	svc, err := NewService(st, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return svc, st
}

func TestBootstrapLoginAndSessions(t *testing.T) {
	svc, st := newService(t)
	ctx := context.Background()

	if _, err := svc.Bootstrap(ctx, "admin", "short"); err == nil {
		t.Fatal("bootstrap with a weak password")
	}
	if ok, err := svc.Bootstrap(ctx, "Admin", "first admin password"); !ok || err != nil {
		t.Fatalf("bootstrap: %v %v", ok, err)
	}
	if ok, _ := svc.Bootstrap(ctx, "admin2", "another long password"); ok {
		t.Fatal("bootstrap ran again with an account present")
	}

	s, err := svc.Login(ctx, " ADMIN ", "first admin password", "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	if s.Username != "admin" || len(s.Roles) != 1 || s.Roles[0] != "admin" || len(s.Token) < 40 {
		t.Fatalf("session %+v", s)
	}
	p, err := svc.Authenticate(ctx, s.Token)
	if err != nil || p.Name != "admin" || !p.Can(auth.PermRoleBindingsWrite) || LocalUsername(p) != "admin" {
		t.Fatalf("principal %+v, %v", p, err)
	}
	for _, bad := range []string{"", "stl_", "stl_unknown", s.Token + "x", "eyJ.not.local"} {
		if _, err := svc.Authenticate(ctx, bad); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Errorf("token %q: %v", bad, err)
		}
	}
	// Only the hash of the token is stored.
	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM local_sessions WHERE token_sha256 = $1`, []byte(s.Token)).Scan(&n); err != nil || n != 0 {
		t.Errorf("raw token stored: %d %v", n, err)
	}

	// An expired session is refused.
	if _, err := st.pool.Exec(ctx, `UPDATE local_sessions SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, s.Token); err == nil {
		t.Error("expired session accepted")
	}
	if n, _ := st.DeleteExpired(ctx); n != 1 {
		t.Errorf("DeleteExpired removed %d", n)
	}

	// Logout ends it.
	s2, _ := svc.Login(ctx, "admin", "first admin password", "192.0.2.1", "test")
	if err := svc.Logout(ctx, s2.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, s2.Token); err == nil {
		t.Error("session works after logout")
	}
	// a second logout of the same token is not an error, nor audited again
	if err := svc.Logout(ctx, s2.Token); err != nil {
		t.Fatal(err)
	}

	// Sign-ins and sign-outs are audited, without any token.
	audited := func(action string) int {
		var n int
		if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1 AND actor = 'admin'
			AND resource = 'local_users/admin'`, action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := audited("local_sessions.start"); got != 2 {
		t.Errorf("%d sign-ins audited, want 2", got)
	}
	if got := audited("local_sessions.end"); got != 1 {
		t.Errorf("%d sign-outs audited, want 1", got)
	}
	var ip string
	if err := st.pool.QueryRow(ctx, `SELECT after->>'client_ip' FROM audit_log WHERE action = 'local_sessions.start' LIMIT 1`).Scan(&ip); err != nil || ip != "192.0.2.1" {
		t.Errorf("sign-in client_ip %q, %v", ip, err)
	}
	for _, tok := range []string{s.Token, s2.Token, s.Token[len(TokenPrefix):]} {
		if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE coalesce(before::text, '') || coalesce(after::text, '') LIKE '%' || $1 || '%'`, tok).Scan(&n); err != nil || n != 0 {
			t.Errorf("a session token reached the audit log (%d rows, %v)", n, err)
		}
	}
}

func TestLockoutAndUnknownUsers(t *testing.T) {
	svc, st := newService(t)
	ctx := context.Background()
	h, _ := HashPassword("operator password")
	if _, err := st.CreateUser(ctx, "op", h, []string{"operator"}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, "nobody", "whatever password", "198.51.100.1", ""); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("unknown user: %v", err)
	}
	for i := 0; i < MaxFailures; i++ {
		if _, err := svc.Login(ctx, "op", "wrong password!", "198.51.100.2", ""); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// Locked: even the right password is refused, with the same answer.
	if _, err := svc.Login(ctx, "op", "operator password", "198.51.100.3", ""); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("locked account signed in: %v", err)
	}
	if u, _ := st.GetUser(ctx, "op"); !u.Locked {
		t.Error("account not shown as locked")
	}
	if _, err := st.UpdateUser(ctx, "op", Patch{Unlock: true}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, "op", "operator password", "198.51.100.3", ""); err != nil {
		t.Fatalf("after unlock: %v", err)
	}

	// The per-address limit, whatever the accounts.
	var last error
	for i := 0; i <= IPAttempts; i++ {
		_, last = svc.Login(ctx, "nobody", "whatever password", "203.0.113.9", "")
	}
	if !errors.Is(last, ErrThrottled) {
		t.Errorf("attempt %d from one address: %v", IPAttempts+1, last)
	}
}

func TestAccountChanges(t *testing.T) {
	svc, st := newService(t)
	ctx := context.Background()
	if _, err := svc.Bootstrap(ctx, "admin", "first admin password"); err != nil {
		t.Fatal(err)
	}
	h, _ := HashPassword("viewer password 1")
	if _, err := st.CreateUser(ctx, "viewer1", h, []string{"viewer"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, "viewer1", h, nil, "admin"); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate: %v", err)
	}

	// The last enabled admin cannot be demoted, disabled or deleted.
	none, yes := []string{"viewer"}, true
	if _, err := st.UpdateUser(ctx, "admin", Patch{Roles: &none}, "admin"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demote last admin: %v", err)
	}
	if _, err := st.UpdateUser(ctx, "admin", Patch{Disabled: &yes}, "admin"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disable last admin: %v", err)
	}
	if err := st.DeleteUser(ctx, "admin", "admin"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("delete last admin: %v", err)
	}
	admin := []string{"admin"}
	if _, err := st.UpdateUser(ctx, "viewer1", Patch{Roles: &admin}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateUser(ctx, "admin", Patch{Roles: &none}, "viewer1"); err != nil {
		t.Errorf("demote with another admin: %v", err)
	}

	// Disabling ends sessions; a new password ends them too.
	s, err := svc.Login(ctx, "admin", "first admin password", "192.0.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateUser(ctx, "admin", Patch{Disabled: &yes}, "viewer1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, s.Token); err == nil {
		t.Error("a disabled account's session still works")
	}
	if _, err := svc.Login(ctx, "admin", "first admin password", "192.0.2.1", ""); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("disabled account signed in: %v", err)
	}

	// Changing one's own password keeps the current session, ends the others.
	a, _ := svc.Login(ctx, "viewer1", "viewer password 1", "192.0.2.1", "")
	b, _ := svc.Login(ctx, "viewer1", "viewer password 1", "192.0.2.1", "")
	if err := svc.ChangeOwnPassword(ctx, "viewer1", "wrong current pw", "viewer password 2", a.Token); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("wrong current password: %v", err)
	}
	if err := svc.ChangeOwnPassword(ctx, "viewer1", "viewer password 1", "short", a.Token); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("weak new password: %v", err)
	}
	if err := svc.ChangeOwnPassword(ctx, "viewer1", "viewer password 1", "viewer password 2", a.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, a.Token); err != nil {
		t.Errorf("the changing session ended: %v", err)
	}
	if _, err := svc.Authenticate(ctx, b.Token); err == nil {
		t.Error("another session survived the password change")
	}
	if _, err := svc.Login(ctx, "viewer1", "viewer password 2", "192.0.2.1", ""); err != nil {
		t.Errorf("new password: %v", err)
	}

	// Every change is audited, without the hash.
	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE resource LIKE 'local_users/%'`).Scan(&n); err != nil || n < 6 {
		t.Errorf("%d audit rows, %v", n, err)
	}
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE after::text LIKE '%argon2id%' OR before::text LIKE '%argon2id%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a password hash reached the audit log (%d rows)", n)
	}
	if err := st.DeleteUser(ctx, "admin", "viewer1"); err != nil {
		t.Errorf("delete a disabled admin: %v", err)
	}
	if _, err := st.GetUser(ctx, "admin"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted user: %v", err)
	}
}

// Two users behind the same trusted proxy (the UI) have their own login
// limits: one client's failures do not throttle the other.
func TestThrottlingPerClientBehindAProxy(t *testing.T) {
	svc, st := newService(t)
	ctx := context.Background()
	if ok, err := svc.Bootstrap(ctx, "admin", "first admin password"); !ok || err != nil {
		t.Fatalf("bootstrap: %v %v", ok, err)
	}
	p, _ := ParseTrustedProxies("192.0.2.80")
	h := &Handler{Service: svc, Store: st, TrustedProxies: p}
	mux := http.NewServeMux()
	h.Public(mux)
	login := func(client, password string) int {
		r := httptest.NewRequest(http.MethodPost, "/v1/auth/login",
			strings.NewReader(`{"username":"nobody","password":"`+password+`"}`))
		r.RemoteAddr = "192.0.2.80:40000"
		r.Header.Set("X-Forwarded-For", client)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < IPAttempts; i++ {
		if code := login("203.0.113.1", "wrong password one"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, code)
		}
	}
	if code := login("203.0.113.1", "wrong password one"); code != http.StatusTooManyRequests {
		t.Fatalf("client A not throttled: %d", code)
	}
	if code := login("203.0.113.2", "wrong password two"); code != http.StatusUnauthorized {
		t.Fatalf("client B shares client A's limit: %d", code)
	}
}
