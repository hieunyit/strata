package bundlefmt

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyPolicyBoundsAndMode(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := make([]byte, 4096)
	copy(base, magic)
	binary.LittleEndian.PutUint16(base[8:], 1)
	binary.LittleEndian.PutUint32(base[12:], 1)
	binary.LittleEndian.PutUint64(base[32:], 4096)
	copy(base[64:], "example-api")
	base[120] = 1
	for _, tt := range []struct {
		name, policy string
		enforce, ok  bool
		change       func([]byte) []byte
	}{
		{"enforce", "example-api", true, true, nil},
		{"missing", "missing-api", false, false, nil},
		{"empty", "", false, false, nil},
		{"hostile", "example-api;", false, false, nil},
		{"max-name", strings.Repeat("a", 55), true, true, func(b []byte) []byte { clear(b[64:120]); copy(b[64:], strings.Repeat("a", 55)); return b }},
		{"long-name", strings.Repeat("a", 56), false, false, nil},
		{"uppercase", "Example-api", false, false, nil},
		{"utf8", "example-é", false, false, nil},
		{"too-many", "example-api", false, false, func(b []byte) []byte { binary.LittleEndian.PutUint32(b[12:], 4097); return b }},
		{"overflow-count", "example-api", false, false, func(b []byte) []byte { binary.LittleEndian.PutUint32(b[12:], ^uint32(0)); return b }},
		{"truncated", "example-api", false, false, func(b []byte) []byte { return b[:100] }},
		{"section-overlap", "example-api", false, false, func(b []byte) []byte { binary.LittleEndian.PutUint64(b[32:], 64); return b }},
		{"section-outside", "example-api", false, false, func(b []byte) []byte { binary.LittleEndian.PutUint64(b[32:], ^uint64(0)); return b }},
		{"section-overflow", "example-api", false, false, func(b []byte) []byte { binary.LittleEndian.PutUint64(b[40:], ^uint64(0)); return b }},
		{"nonzero-padding", "example-api", false, false, func(b []byte) []byte { b[80] = 1; return b }},
		{"unterminated-name", "example-api", false, false, func(b []byte) []byte {
			for i := 64; i < 120; i++ {
				b[i] = 'a'
			}
			return b
		}},
		{"duplicate", "example-api", false, false, func(b []byte) []byte { binary.LittleEndian.PutUint32(b[12:], 2); copy(b[128:192], b[64:128]); return b }},
		{"bad-mode", "example-api", false, false, func(b []byte) []byte { b[120] = 2; return b }},
		{"shadow", "example-api", false, true, func(b []byte) []byte { b[120] = 0; return b }},
		{"shadow-enforce", "example-api", true, false, func(b []byte) []byte { b[120] = 0; return b }},
		{"canary", "example-api", false, true, func(b []byte) []byte { binary.LittleEndian.PutUint16(b[123:], 100); return b }},
		{"canary-enforce", "example-api", true, false, func(b []byte) []byte { binary.LittleEndian.PutUint16(b[123:], 100); return b }},
		{"bad-canary", "example-api", false, false, func(b []byte) []byte { binary.LittleEndian.PutUint16(b[123:], 10000); return b }},
		{"shadow-canary", "example-api", false, false, func(b []byte) []byte { b[120] = 0; binary.LittleEndian.PutUint16(b[123:], 100); return b }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := append([]byte(nil), base...)
			if tt.change != nil {
				data = tt.change(data)
			}
			signed := append(data, ed25519.Sign(priv, data)...)
			_, err := VerifyPolicy(signed, pub, tt.policy, tt.enforce)
			if (err == nil) != tt.ok {
				t.Fatalf("err=%v want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestVerifyPolicyCompilerFixture(t *testing.T) {
	dir := "../../../connectors/nginx/t/fixtures"
	data, err := os.ReadFile(filepath.Join(dir, "bundle/bundle-1.sbn"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := os.ReadFile(filepath.Join(dir, "rotation.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPolicy(data, keys, "example-api", true); err != nil {
		t.Fatal(err)
	}
	data[64] ^= 1
	if _, err := VerifyPolicy(data, keys, "example-api", true); err == nil {
		t.Fatal("accepted altered policy table")
	}
}

func TestVerifyPolicyMaxTable(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, (64+4096*64+4095)/4096*4096)
	copy(body, magic)
	binary.LittleEndian.PutUint16(body[8:], 1)
	binary.LittleEndian.PutUint32(body[12:], 4096)
	binary.LittleEndian.PutUint64(body[32:], uint64(len(body)))
	for i := 0; i < 4096; i++ {
		copy(body[64+i*64:], fmt.Sprintf("example-%04d", i))
	}
	if _, err := VerifyPolicy(append(body, ed25519.Sign(priv, body)...), pub, "example-4095", false); err != nil {
		t.Fatal(err)
	}
}

func FuzzVerifyPolicy(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Fatal(err)
	}
	// Keep the seed focused on policy bytes, not large Hyperscan sections.
	body := make([]byte, 4096)
	copy(body, magic)
	binary.LittleEndian.PutUint16(body[8:], 1)
	binary.LittleEndian.PutUint32(body[12:], 1)
	binary.LittleEndian.PutUint64(body[32:], 4096)
	copy(body[64:], "example-api")
	body[120] = 1
	f.Add(body, "example-api", true)
	f.Fuzz(func(t *testing.T, input []byte, name string, enforce bool) {
		if len(input) > 262144 {
			t.Skip()
		}
		size := (max(len(input), 64) + 4095) / 4096 * 4096
		data := make([]byte, size)
		copy(data, input)
		copy(data, magic)
		binary.LittleEndian.PutUint16(data[8:], 1)
		binary.LittleEndian.PutUint64(data[32:], uint64(size))
		binary.LittleEndian.PutUint64(data[40:], 0)
		_, _ = VerifyPolicy(append(data, ed25519.Sign(priv, data)...), pub, name, enforce)
	})
}
