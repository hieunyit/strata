package localauth

import (
	"bytes"
	"testing"
	"time"
)

func TestRFCOTPAndAuthenticatedSeedEncryption(t *testing.T) {
	seed := []byte("12345678901234567890")
	for i, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		if got := hotp(seed, int64(i), 6); got != want {
			t.Fatalf("RFC4226 %d: %s", i, got)
		}
	}
	for _, tc := range []struct {
		at   int64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if hotp(seed, tc.at/30, 8) != tc.want {
			t.Fatal("RFC6238 vector", tc.at)
		}
	}
	now := time.Unix(1234567890, 0)
	code := hotp(seed, now.Unix()/30, 6)
	step, ok := totpStep(seed, code, now, -1)
	if !ok {
		t.Fatal("valid code refused")
	}
	if _, ok := totpStep(seed, code, now, step); ok {
		t.Fatal("reused timestep accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "-12345", "abcdef", "+12345"} {
		if _, ok := totpStep(seed, bad, now, -1); ok {
			t.Fatal("malformed code accepted")
		}
	}
	key := bytes.Repeat([]byte{7}, 32)
	sealed, err := sealSeed(key, seed, "example-admin")
	if err != nil || bytes.Contains(sealed, seed) {
		t.Fatal("seed encryption", err)
	}
	got, err := openSeed(key, sealed, "example-admin")
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatal("seed round trip", err)
	}
	for _, name := range []string{"other-admin", ""} {
		if _, err := openSeed(key, sealed, name); err == nil {
			t.Fatal("seed moved between accounts")
		}
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := openSeed(key, sealed, "example-admin"); err == nil {
		t.Fatal("corrupted seed accepted")
	}
	if _, err := openSeed(nil, sealed, "example-admin"); err == nil {
		t.Fatal("missing key accepted")
	}
}
