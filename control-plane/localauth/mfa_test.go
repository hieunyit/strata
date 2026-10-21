package localauth

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMFAEnrollmentLoginRecoveryAndSessions(t *testing.T) {
	s, st := newService(t)
	ctx := context.Background()
	if err := s.ConfigureMFA(bytes.Repeat([]byte{3}, 32)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(30 * time.Second)
	s.now = func() time.Time { return now }
	const password = "example admin password"
	if _, err := s.Bootstrap(ctx, "admin", password); err != nil {
		t.Fatal(err)
	}
	first, err := s.Login(ctx, "admin", password, "192.0.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Login(ctx, "admin", password, "192.0.2.2", "")
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := s.BeginMFA(ctx, "admin", password, first.Token, "enroll-1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.BeginMFA(ctx, "admin", password, first.Token, "enroll-1")
	if err != nil || again.Secret != enrollment.Secret || again.URI != enrollment.URI || again.Etag != enrollment.Etag || !again.ExpiresAt.Equal(enrollment.ExpiresAt) {
		t.Fatal("enrollment retry changed secret", err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmMFA(ctx, "admin", other.Token, enrollment.Etag, hotp(seed, now.Unix()/30, 6)); !errors.Is(err, ErrMFAConflict) {
		t.Fatal("enrollment moved sessions", err)
	}
	codes, err := s.ConfirmMFA(ctx, "admin", first.Token, enrollment.Etag, hotp(seed, now.Unix()/30, 6))
	if err != nil || len(codes) != 8 {
		t.Fatal("confirmation", err)
	}
	if _, err := s.Authenticate(ctx, other.Token); err == nil {
		t.Fatal("pre-MFA session survived")
	}
	if _, err := s.Authenticate(ctx, first.Token); err != nil {
		t.Fatal("confirmed session revoked", err)
	}
	if _, err := s.Login(ctx, "admin", password, "192.0.2.1", ""); !errors.Is(err, ErrMFARequired) {
		t.Fatal("password bypass", err)
	}
	if _, err := s.LoginMFA(ctx, "admin", password, hotp(seed, now.Unix()/30, 6), false, "192.0.2.1", ""); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("confirmation OTP reused", err)
	}
	now = now.Add(30 * time.Second)
	code := hotp(seed, now.Unix()/30, 6)
	var wg sync.WaitGroup
	wins := make(chan *Session, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session, err := s.LoginMFA(ctx, "admin", password, code, false, "192.0.2.1", "")
			if err == nil {
				wins <- session
			}
		}()
	}
	wg.Wait()
	close(wins)
	if len(wins) != 1 {
		t.Fatal("concurrent OTP successes", len(wins))
	}
	logged := <-wins
	items, err := s.Sessions(ctx, "admin", logged.Token)
	if err != nil || len(items) != 2 {
		t.Fatal("session list", err, len(items))
	}
	for _, item := range items {
		if item.Current {
			if err := s.RevokeSession(ctx, "admin", item.ID, item.Etag); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := s.Authenticate(ctx, logged.Token); err == nil {
		t.Fatal("revoked session accepted")
	}
	if _, err := s.LoginMFA(ctx, "admin", password, codes[0], true, "192.0.2.3", ""); err != nil {
		t.Fatal("recovery", err)
	}
	if _, err := s.LoginMFA(ctx, "admin", password, codes[0], true, "192.0.2.3", ""); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("recovery reused", err)
	}
	state, err := s.MFAStatus(ctx, "admin")
	if err != nil || state.RecoveryRemaining != 7 || !state.Enabled {
		t.Fatal("state", state, err)
	}
	var raw string
	if err := st.pool.QueryRow(ctx, `SELECT string_agg(coalesce(before::text,'')||coalesce(after::text,''),' ') FROM audit_log`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	for _, secret := range append(codes, enrollment.Secret, first.Token, code) {
		if strings.Contains(raw, secret) {
			t.Fatal("MFA secret in audit")
		}
	}
	var sealed []byte
	if err := st.pool.QueryRow(ctx, `SELECT seed FROM local_mfa WHERE username='admin'`).Scan(&sealed); err != nil || bytes.Contains(sealed, seed) {
		t.Fatal("seed not encrypted", err)
	}
	// A restarted service without the key cannot downgrade to password-only login.
	missing, err := NewService(st, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missing.LoginMFA(ctx, "admin", password, code, false, "192.0.2.4", ""); !errors.Is(err, ErrMFAUnavailable) {
		t.Fatal("missing key bypass", err)
	}
	if _, err := s.ChangeMFA(ctx, "admin", password, first.Token, state.Etag, codes[1], true, true); err != nil {
		t.Fatal("disable with recovery", err)
	}
	if _, err := s.Login(ctx, "admin", password, "192.0.2.1", ""); err != nil {
		t.Fatal("password after disable", err)
	}
}
