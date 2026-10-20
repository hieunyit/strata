package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
)

func TestModuleManifestChecksBinaryAndRuntime(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "module.so")
	file := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(binary, []byte("example module"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("example module"))
	m := ModuleManifest{ModulePath: binary, SHA256: hex.EncodeToString(sum[:]), ModuleVersion: "1.0", ABI: 0x10008, Capabilities: []string{"section.9"}}
	write := func() {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(file, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	loaded, err := ReadModuleManifest(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.For(&fleetv1.Connector{ModuleVersion: "1.0", AbiVersion: m.ABI})) != 1 {
		t.Fatal("matching manifest lost")
	}
	if len(loaded.For(&fleetv1.Connector{ModuleVersion: "other", AbiVersion: m.ABI})) != 0 {
		t.Fatal("mismatched runtime advertised")
	}
	if len(loaded.For(nil)) != 0 {
		t.Fatal("unknown runtime advertised")
	}
	m.SHA256 = "wrong"
	write()
	if _, err = ReadModuleManifest(file); err == nil {
		t.Fatal("wrong hash accepted")
	}
	m.Capabilities = []string{"../escape"}
	write()
	if _, err = ReadModuleManifest(file); err == nil {
		t.Fatal("bad capability accepted")
	}
	if err = os.WriteFile(file, []byte(`{"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadModuleManifest(file); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestManifestRefusesOversizedFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "manifest")
	if err := os.WriteFile(file, make([]byte, 16385), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadModuleManifest(file); err == nil {
		t.Fatal("oversized manifest accepted")
	}
}
