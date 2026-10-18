package standalone

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyBundlePreflight(t *testing.T) {
	b, pub, _ := makeTestBundle(7, 1)
	_, other, _ := makeTestBundle(8, 2)
	for _, tt := range []struct {
		name      string
		data, key []byte
		ok        bool
	}{
		{"valid", b, pub, true},
		{"rotated", b, append(append([]byte{}, other...), pub...), true},
		{"untrusted", b, other, false},
		{"short", b[:20], pub, false},
		{"empty-key", b, nil, false},
		{"oversized-key", b, make([]byte, 65), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := t.TempDir()
			file, key := filepath.Join(d, "bundle.sbn"), filepath.Join(d, "key")
			if err := os.WriteFile(file, tt.data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(key, tt.key, 0600); err != nil {
				t.Fatal(err)
			}
			h, err := VerifyBundle(context.Background(), file, key)
			if (err == nil) != tt.ok {
				t.Fatalf("header=%+v err=%v", h, err)
			}
			if tt.ok && h.Version != 7 {
				t.Fatalf("wrong signed version: %d", h.Version)
			}
			entries, err := os.ReadDir(d)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 2 {
				t.Fatal("verification activated or installed files")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyBundle(ctx, "missing", "missing"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}
