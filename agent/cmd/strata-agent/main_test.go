package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestEnrollDryRun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "id")
	out, err := execute(t, "enroll", "--dry-run", "--identity-dir", dir)
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(out, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Fatalf("no CSR printed: %s", out)
	}
	st, err := os.Stat(filepath.Join(dir, "node.key"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key: %v %v", err, st)
	}
	// A second dry run keeps the key.
	if _, err := execute(t, "enroll", "--dry-run", "--identity-dir", dir); err == nil {
		t.Fatal("second dry run replaced the key")
	}
}

func TestEnrollNeedsAToken(t *testing.T) {
	t.Setenv("STRATA_ENROLL_TOKEN", "")
	dir := filepath.Join(t.TempDir(), "id")
	if _, err := execute(t, "enroll", "--identity-dir", dir, "--server", "127.0.0.1:1", "--tls-ca", "/dev/null"); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node.key")); err == nil {
		t.Fatal("key written although enrollment could not start")
	}
}

func TestRunNeedsServerAndNode(t *testing.T) {
	if _, err := execute(t, "run"); err == nil {
		t.Fatal("run without --server accepted")
	}
}

func TestRunStandaloneFlags(t *testing.T) {
	// Without bundle flags, standalone errors with bundle requirement, NOT server requirement
	_, err := execute(t, "run", "--standalone")
	if err == nil {
		t.Fatal("run --standalone without bundle accepted")
	}
	if !strings.Contains(err.Error(), "bundle-file") {
		t.Fatalf("expected bundle requirement error, got: %v", err)
	}
}

