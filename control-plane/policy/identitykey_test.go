package policy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strata/strata/control-plane/localauth/localauthtest"
)

func TestParseIdentityKey(t *testing.T) {
	if k, err := ParseIdentityKey(strings.Repeat("ab", 32) + "\n"); err != nil || len(k) != 32 {
		t.Fatalf("%x %v", k, err)
	}
	for _, bad := range []string{"", "ab", strings.Repeat("zz", 32), strings.Repeat("00", 32), strings.Repeat("ab", 33)} {
		if _, err := ParseIdentityKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := (IdentityKeys{}).Key(context.Background()); err == nil {
		t.Error("no env and no PostgreSQL: a key")
	}
}

// The key is made once and kept: the same for every bundle and every
// control plane on the database. Skipped without STRATA_TEST_POSTGRES_DSN.
func TestIdentityKeyKeptInPostgres(t *testing.T) {
	pool := localauthtest.Pool(t)
	ctx := context.Background()
	k := IdentityKeys{Pool: pool}
	a, err := k.Key(ctx)
	if err != nil || len(a) != IdentityKeyLen {
		t.Fatalf("%x %v", a, err)
	}
	b, err := IdentityKeys{Pool: pool}.Key(ctx)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("second call: %x %v, want %x", b, err, a)
	}
	env := strings.Repeat("cd", 32)
	c, err := IdentityKeys{Env: env, Pool: pool}.Key(ctx)
	if err != nil || bytes.Equal(c, a) || c[0] != 0xcd {
		t.Fatalf("the env key wins: %x %v", c, err)
	}
}

// Only bundles with an identity: hmac policy get the key, as a 0600 file.
func TestCompilerPassesTheIdentityKey(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-compile")
	got := filepath.Join(dir, "got")
	body := "#!/bin/sh\n: > " + got + "\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n" +
		"    --identity-key) stat -c %a \"$2\" >> " + got + "; cat \"$2\" >> " + got + "; shift 2 ;;\n" +
		"    --out) printf bundle > \"$2\"; shift 2 ;;\n    *) shift ;;\n  esac\ndone\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	calls := 0
	c := &Compiler{Binary: script, KeyFile: "/keys/seed", IdentityKey: func(context.Context) ([]byte, error) {
		calls++
		return bytes.Repeat([]byte{0xab}, 32), nil
	}}
	plain := []Named{{Name: "a", Spec: Spec{Mode: "shadow", Privacy: &Privacy{SensitiveFields: []string{"x"}}}}}
	if _, err := c.Build(context.Background(), 1, plain); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(got); len(b) != 0 || calls != 0 {
		t.Fatalf("a key for a bundle without identity hmac: %q, %d calls", b, calls)
	}
	hmac := append(plain, Named{Name: "b", Spec: Spec{Mode: "enforce", Privacy: &Privacy{Identity: "hmac"}}})
	if _, err := c.Build(context.Background(), 2, hmac); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(got); string(b) != "600\n"+strings.Repeat("ab", 32) {
		t.Fatalf("key file %q", b)
	}
	c.IdentityKey = nil
	if _, err := c.Build(context.Background(), 3, hmac); err == nil || !strings.Contains(err.Error(), "identity key") {
		t.Fatalf("no key source: %v", err)
	}
}
