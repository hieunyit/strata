package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyBundlePolicyCommand(t *testing.T) {
	fixtures := "../../../connectors/nginx/t/fixtures"
	file := filepath.Join(fixtures, "bundle", "bundle-1.sbn")
	key := filepath.Join(fixtures, "bundle.pub")
	for _, tt := range []struct {
		name string
		args []string
		ok   bool
	}{
		{"enforce", []string{"--policy=example-api", "--require-enforce"}, true},
		{"shadow", []string{"--policy=example-api-upload"}, true},
		{"shadow-not-enforce", []string{"--policy=example-api-upload", "--require-enforce"}, false},
		{"missing-policy", []string{"--policy=missing-api"}, false},
		{"invalid-policy", []string{"--policy=example-api;"}, false},
		{"empty-policy", []string{"--policy="}, false},
		{"enforce-without-policy", []string{"--require-enforce"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"verify-bundle", "--bundle-file=" + file, "--bundle-pubkey=" + key}, tt.args...)
			out, err := execute(t, args...)
			if (err == nil) != tt.ok {
				t.Fatalf("out=%q err=%v", out, err)
			}
			if tt.ok && !strings.Contains(out, "version 1") {
				t.Fatalf("out=%q", out)
			}
		})
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.sbn")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	data[64] ^= 1
	if err := os.WriteFile(bad, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(t, "verify-bundle", "--bundle-file="+bad, "--bundle-pubkey="+key, "--policy=example-api"); err == nil {
		t.Fatal("trusted altered policy table")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("verification activated files: %v %v", files, err)
	}
}
