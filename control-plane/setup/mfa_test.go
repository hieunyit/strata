package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMFAKeyIsPrivateStableAndNotRegenerated(t *testing.T) {
	dir := t.TempDir()
	var r Result
	if err := MFAKey(dir, true, &r); err == nil {
		t.Fatal("lost encryption key regenerated")
	}
	if err := MFAKey(dir, false, &r); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, MFAKeyFile)
	first, err := os.ReadFile(path)
	if err != nil || len(first) != 64 {
		t.Fatal("key format", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("key mode", err)
	}
	if err := MFAKey(dir, true, &r); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("key changed", err)
	}
}
