package localauth

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
)

func TestMFALocksBadCodesExpiresEnrollmentAndScopesSessions(t *testing.T) {
	s, st := newService(t)
	ctx := context.Background()
	if err := s.ConfigureMFA(bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(30 * time.Second)
	s.now = func() time.Time { return now }
	const password = "example security password"
	if _, err := s.Bootstrap(ctx, "admin", password); err != nil {
		t.Fatal(err)
	}
	login, err := s.Login(ctx, "admin", password, "192.0.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.BeginMFA(ctx, "admin", password, login.Token, "enroll-expire")
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(pending.Secret)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if _, err := s.ConfirmMFA(ctx, "admin", login.Token, pending.Etag, hotp(seed, now.Unix()/30, 6)); !errors.Is(err, ErrMFAConflict) {
		t.Fatal("expired enrollment accepted", err)
	}
	pending, err = s.BeginMFA(ctx, "admin", password, login.Token, "enroll-active")
	if err != nil {
		t.Fatal(err)
	}
	seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(pending.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmMFA(ctx, "admin", login.Token, pending.Etag, hotp(seed, now.Unix()/30, 6)); err != nil {
		t.Fatal(err)
	}
	for range MaxFailures {
		if _, err := s.LoginMFA(ctx, "admin", password, "bad", false, "192.0.2.1", ""); !errors.Is(err, ErrBadCredentials) {
			t.Fatal("bad code accepted", err)
		}
	}
	now = now.Add(30 * time.Second)
	if _, err := s.LoginMFA(ctx, "admin", password, hotp(seed, now.Unix()/30, 6), false, "192.0.2.1", ""); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("locked account signed in", err)
	}
	if err := st.ResetMFA(ctx, "admin", "system:recover"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, login.Token); err == nil {
		t.Fatal("host reset retained session")
	}
	var count int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='local_users.mfa_host_reset' AND subject='system:recover'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("host reset not audited", err)
	}
}

func TestSecurityRoutesRejectNonLocalIdentityAndThrottleCardinality(t *testing.T) {
	h := Handler{}
	for _, subject := range []string{"serviceaccount:example-account", "oidc:admin"} {
		request := httptest.NewRequest("GET", "/v1/auth/mfa", nil)
		request.Header.Set("Authorization", "Bearer stsa_example-token")
		request = request.WithContext(auth.WithPrincipal(request.Context(), &auth.Principal{Subject: subject, Name: "admin", Roles: []auth.Role{auth.RoleAdmin}}))
		response := httptest.NewRecorder()
		h.security(response, request)
		if response.Code != 403 {
			t.Fatal("non-local credential reached MFA", response.Code)
		}
	}
	request := httptest.NewRequest("POST", "/v1/auth/mfa:confirm", strings.NewReader(`{} {}`))
	if decode(httptest.NewRecorder(), request, &struct{}{}) {
		t.Fatal("trailing JSON accepted")
	}
	limiter := newIPLimiter(20, time.Hour)
	for i := range 10000 {
		limiter.seen[strings.Repeat("x", i%20)+string(rune(i+100))] = &ipWindow{start: time.Now(), count: 1}
	}
	// audit 22/10/2026: full, a new address takes the oldest window's place
	if !limiter.allow("192.0.2.77", time.Now()) || len(limiter.seen) > 10000 {
		t.Fatal("limiter refused a new address or grew beyond cap")
	}
}
