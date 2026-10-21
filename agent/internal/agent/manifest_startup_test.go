package agent

import (
	"encoding/json"
	"github.com/strata/strata/agent/internal/control"
	"github.com/strata/strata/agent/internal/fleettest"
	"github.com/strata/strata/agent/internal/pusher"
	"os"
	"path/filepath"
	"testing"
)

func TestMissingManifestAllowsUnknownCapabilities(t *testing.T) {
	server, certs := fleettest.NewServer(t)
	cfg := testConfig(t, server, certs, pusher.Options{})
	cfg.ModuleManifest = filepath.Join(t.TempDir(), "missing.json")
	agent, err := New(cfg)
	if err != nil {
		t.Fatalf("missing optional manifest blocked startup: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatal(err)
	}
	// An existing manifest pointing at a missing binary is an invalid install,
	// not the optional-manifest case. Preserve its startup failure.
	manifest := control.ModuleManifest{ModulePath: filepath.Join(t.TempDir(), "missing.so"), ModuleVersion: "1.0", ABI: 0x10008}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.ModuleManifest, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if agent, err := New(cfg); err == nil {
		_ = agent.Close()
		t.Fatal("invalid existing manifest was silently ignored")
	}
}
