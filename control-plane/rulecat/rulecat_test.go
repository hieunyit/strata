package rulecat

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	ruleset := filepath.Join(dir, "sigma.yaml")
	_ = os.WriteFile(ruleset, []byte(`ir_version: 1
ruleset: { name: sigma-web, version: "1" }
rules:
  - id: 600001
    name: Webshell probe
    layer: managed
    severity: error
    metadata: { source: sigma, author: "A. Author (Example Org)", license: DRL-1.1 }
  - id: 942100
    name: SQL Injection via libinjection
    metadata: { source: owasp-crs, license: Apache-2.0 }
`), 0o644)
	authored := filepath.Join(dir, "one.json")
	_ = os.WriteFile(authored, []byte(`{"rule": {"id": 100013, "name": "NUL byte", "layer": "protocol", "metadata": {"source": "strata"}}}`), 0o644)
	c, err := Load([]string{ruleset, authored, ""})
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 3 {
		t.Fatalf("Len = %d", c.Len())
	}
	got := c.For([]uint32{600001, 100013, 1})
	if got["600001"].Author != "A. Author (Example Org)" || got["600001"].Source != "sigma" {
		t.Errorf("sigma rule: %+v", got["600001"])
	}
	if got["100013"].Name != "NUL byte" || got["100013"].Layer != "protocol" {
		t.Errorf("authored rule: %+v", got["100013"])
	}
	if _, ok := got["1"]; ok {
		t.Error("an unknown ID is in the result")
	}
	if (*Catalog)(nil).For([]uint32{1}) != nil {
		t.Error("nil catalog")
	}
	if _, err := Load([]string{filepath.Join(dir, "missing.yaml")}); err == nil {
		t.Error("a missing file loaded")
	}
}
