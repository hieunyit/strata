package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCanaryThresholdConfigValidation(t *testing.T) {
	for _, value := range []string{"block_factor: .nan", "block_factor: 1", "error_delta: 0", "latency_delta: 0ms", "min_requests: 1"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte("version: 1\ncanary:\n  "+value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}
