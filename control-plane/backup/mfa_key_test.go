package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndependentMFAKeySurvivesEncryptedBackup(t *testing.T) {
	dir := dataDir(t)
	key := strings.Repeat("7a", 32)
	write(t, filepath.Join(dir, "keys/local-mfa.key"), key, 0o600)
	var archive bytes.Buffer
	if _, err := Create(t.Context(), Source{DataDir: dir, ObjectsDir: filepath.Join(dir, "objects"), Dump: dump, Product: "test", PostgresMigration: 36}, pass, &archive); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(archive.Bytes(), []byte(key)) {
		t.Fatal("MFA encryption key visible in encrypted backup")
	}
	staged := filepath.Join(t.TempDir(), "staged")
	manifest, err := Extract(bytes.NewReader(archive.Bytes()), pass, staged)
	if err != nil {
		t.Fatal(err)
	}
	restored, objects := filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "objects")
	if err := Install(staged, manifest, restored, objects); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(restored, "keys/local-mfa.key")
	data, err := os.ReadFile(path)
	if err != nil || string(data) != key {
		t.Fatal("MFA key changed during restore", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("restored MFA key permissions", err)
	}
}
