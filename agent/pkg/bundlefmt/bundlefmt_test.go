package bundlefmt

import (
	"crypto/ed25519"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func build(t *testing.T, priv ed25519.PrivateKey, version uint64) []byte {
	t.Helper()
	b := make([]byte, 4096)
	copy(b, magic)
	binary.LittleEndian.PutUint16(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], 3)
	binary.LittleEndian.PutUint64(b[16:], version)
	return append(b, ed25519.Sign(priv, b)...)
}

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	data := build(t, priv, 7)
	h, err := Verify(data, pub)
	if err != nil || h.Version != 7 || h.Policies != 3 {
		t.Fatalf("%+v %v", h, err)
	}
	tampered := append([]byte(nil), data...)
	tampered[100] ^= 1
	if _, err := Verify(tampered, pub); err == nil {
		t.Fatal("a changed byte verified")
	}
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(data, otherPub); err == nil {
		t.Fatal("verified with another key")
	}
	if _, err := Verify(data[:50], pub); err == nil {
		t.Fatal("truncated bundle verified")
	}
}

// Bundles made by strata-compile (the NGINX test fixtures) verify here
// too: Go and Rust agree on the format; the corrupted fixture does not.
func TestCompilerFixtures(t *testing.T) {
	dir := "../../../connectors/nginx/t/fixtures"
	pub, err := os.ReadFile(filepath.Join(dir, "bundle.pub"))
	if err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(filepath.Join(dir, "bundle", "bundle-1.sbn"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := Verify(good, pub)
	if err != nil || h.Version != 1 {
		t.Fatalf("fixture bundle: %+v %v", h, err)
	}
	bad, err := os.ReadFile(filepath.Join(dir, "bad", "bundle-1.sbn"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bad, pub); err == nil {
		t.Fatal("the corrupted fixture verified")
	}
}

// Key rotation: two trusted keys, a bundle signed by either verifies.
func TestVerifyTwoKeys(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(nil)
	newPub, newPriv, _ := ed25519.GenerateKey(nil)
	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)
	both := append(append([]byte{}, oldPub...), newPub...)
	for _, priv := range []ed25519.PrivateKey{oldPriv, newPriv} {
		if _, err := Verify(build(t, priv, 1), both); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Verify(build(t, otherPriv, 1), both); err == nil {
		t.Fatal("signed by a key not trusted")
	}
	three := append(append([]byte{}, both...), otherPub...)
	if _, err := Verify(build(t, otherPriv, 1), three); err == nil {
		t.Fatal("three keys accepted")
	}
	if _, err := Verify(build(t, oldPriv, 1), both[:40]); err == nil {
		t.Fatal("a 40-byte key file accepted")
	}
}
