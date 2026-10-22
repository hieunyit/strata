package localauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("hash %q: not the expected PHC string", h)
	}
	if ok, err := VerifyPassword(h, "correct horse battery"); !ok || err != nil {
		t.Errorf("right password: %v %v", ok, err)
	}
	if ok, _ := VerifyPassword(h, "correct horse batterY"); ok {
		t.Error("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Error("two hashes of one password are equal: the salt is not random")
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=999999999,t=2,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=19456,t=2,p=1$!!$aGFzaA"} {
		if ok, err := VerifyPassword(bad, "x"); ok || err == nil {
			t.Errorf("malformed hash %q: ok=%v err=%v", bad, ok, err)
		}
	}
}

func TestPasswordAndNameRules(t *testing.T) {
	for pw, ok := range map[string]bool{
		"short":                  false,
		"exactly12chr":           true,
		"mật khẩu dài":           true, // 12 characters, more bytes
		strings.Repeat("a", 256): true,
		strings.Repeat("a", 257): false,
		strings.Repeat("ạ", 100): false, // 300 bytes: the byte limit holds
	} {
		if got := CheckPassword(pw) == nil; got != ok {
			t.Errorf("CheckPassword(%q...) ok=%v, want %v", pw[:min(len(pw), 12)], got, ok)
		}
	}
	for in, want := range map[string]string{" Alice ": "alice", "ops.team-1": "ops.team-1", "a": "", "-x": "", "a b": "", "admin@example": ""} {
		got, err := NormalizeUsername(in)
		if (want == "") != (err != nil) || got != want {
			t.Errorf("NormalizeUsername(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if r, err := CheckRoles([]string{"viewer", "admin", "viewer"}); err != nil || strings.Join(r, ",") != "admin,viewer" {
		t.Errorf("CheckRoles = %v, %v", r, err)
	}
	if _, err := CheckRoles([]string{"root"}); err == nil {
		t.Error("unknown role accepted")
	}
}

// audit 22/10/2026: the addresses of one IPv6 /64 share a window.
func TestIPLimiterIPv6Prefix(t *testing.T) {
	l := newIPLimiter(2, time.Minute)
	now := time.Now()
	for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2"} {
		if !l.allow(ip, now) {
			t.Fatal(ip)
		}
	}
	if l.allow("2001:db8:1:2:aaaa::3", now) {
		t.Fatal("a third address of the same /64 got a new window")
	}
	if !l.allow("2001:db8:1:3::1", now) {
		t.Fatal("another /64 shares the window")
	}
}

func TestIPLimiter(t *testing.T) {
	l := newIPLimiter(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.allow("192.0.2.1", now) {
			t.Fatalf("attempt %d refused", i+1)
		}
	}
	if l.allow("192.0.2.1", now) {
		t.Error("fourth attempt in the window allowed")
	}
	if !l.allow("192.0.2.2", now) {
		t.Error("another address refused")
	}
	if !l.allow("192.0.2.1", now.Add(time.Minute)) {
		t.Error("refused after the window")
	}
}

type fixed struct{ name string }

func (f fixed) Authenticate(context.Context, string) (*auth.Principal, error) {
	return &auth.Principal{Subject: f.name}, nil
}

func TestDispatchAndLocalUsername(t *testing.T) {
	d := auth.Dispatch{LocalPrefix: TokenPrefix, Local: fixed{"local:alice"}, OIDC: fixed{"oidc-sub"}}
	if p, _ := d.Authenticate(context.Background(), "stl_abc"); p.Subject != "local:alice" || LocalUsername(p) != "alice" {
		t.Errorf("local token went to %+v", p)
	}
	if p, _ := d.Authenticate(context.Background(), "eyJhbGciOi"); p.Subject != "oidc-sub" || LocalUsername(p) != "" {
		t.Errorf("JWT went to %+v", p)
	}
	if _, err := (auth.Dispatch{LocalPrefix: TokenPrefix, Local: fixed{"x"}}).Authenticate(context.Background(), "eyJ"); err == nil {
		t.Error("a JWT without OIDC configured was accepted")
	}
	if LocalUsername(nil) != "" {
		t.Error("nil principal")
	}
}
