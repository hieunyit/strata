package policy

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// W17-S-01: the CRS paranoia levels of a spec reach the bundle through the
// real strata-compile (STRATA_COMPILE=<path>) as section PARANOIA ("SPL1"),
// and rules above every policy's levels are left out.
func TestCompilerCarriesParanoia(t *testing.T) {
	bin := os.Getenv("STRATA_COMPILE")
	if bin == "" {
		t.Skip("STRATA_COMPILE not set")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "seed")
	if err := os.WriteFile(key, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	ir := `{"ir_version": 1, "ruleset": {"name": "example-crs", "version": "1"}, "rules": [{"id": 942902,
	  "name": "level 2", "layer": "managed", "stage": "request_headers", "paranoia_level": 2,
	  "score": 100, "severity": "critical", "metadata": {"source": "strata", "license": "Apache-2.0"},
	  "match": {"all": [{"targets": [{"var": "args"}], "operator": {"type": "contains", "value": "beta"}}]}}]}`
	irFile := filepath.Join(dir, "ir.json")
	if err := os.WriteFile(irFile, []byte(ir), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Compiler{Binary: bin, KeyFile: key, Rules: []string{irFile}, Timeout: time.Minute}
	id := binary.LittleEndian.AppendUint32(nil, 942902)

	b, err := c.Build(t.Context(), 1, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", CRSParanoiaShadow: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("SPL1")) || !bytes.Contains(b, id) {
		t.Fatal("PL2 in shadow: bundle without section PARANOIA or without the PL2 rule")
	}
	b, err = c.Build(t.Context(), 2, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce"}}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("SPL1")) || bytes.Contains(b, id) {
		t.Fatal("default levels: the bundle carries section PARANOIA or the PL2 rule")
	}
}

// W17-S-01: a policy's crs_plugins reach the bundle (section EXCLUSIONS,
// "SXC1"); a plugin without rules in the rule set fails the build.
func TestCompilerCarriesPlugins(t *testing.T) {
	bin := os.Getenv("STRATA_COMPILE")
	if bin == "" {
		t.Skip("STRATA_COMPILE not set")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "seed")
	if err := os.WriteFile(key, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	ir := `{"ir_version": 1, "ruleset": {"name": "example-plugin", "version": "1"}, "rules": [{"id": 9507100,
	  "name": "login", "layer": "pre", "stage": "request_headers", "score": 0, "severity": "notice",
	  "exclude": [{"rules": [942100], "target": {"var": "args", "key": "pwd"}}],
	  "metadata": {"source": "strata", "license": "Apache-2.0", "plugin": "wordpress"},
	  "match": {"all": [{"targets": [{"var": "path"}], "operator": {"type": "ends_with", "value": "/wp-login.php"}}]}}]}`
	irFile := filepath.Join(dir, "ir.json")
	if err := os.WriteFile(irFile, []byte(ir), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Compiler{Binary: bin, KeyFile: key, Rules: []string{irFile}, Timeout: time.Minute}
	b, err := c.Build(t.Context(), 1, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", CRSPlugins: []string{"wordpress"}}}})
	if err != nil || !bytes.Contains(b, []byte("SXC1")) {
		t.Fatalf("plugin: section %v, %v", bytes.Contains(b, []byte("SXC1")), err)
	}
	if b, err = c.Build(t.Context(), 2, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce"}}}); err != nil || bytes.Contains(b, []byte("SXC1")) {
		t.Fatalf("no plugin: section %v, %v", bytes.Contains(b, []byte("SXC1")), err)
	}
	if _, err = c.Build(t.Context(), 3, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", CRSPlugins: []string{"drupal"}}}}); err == nil {
		t.Fatal("a plugin without rules compiled")
	}
}

// W19-G2-01: a policy's geo rules reach the bundle as rules scoped to it
// (section SCOPE) with the networks they name (section GEO).
func TestCompilerCarriesGeoRules(t *testing.T) {
	bin := os.Getenv("STRATA_COMPILE")
	if bin == "" {
		t.Skip("STRATA_COMPILE not set")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "seed")
	if err := os.WriteFile(key, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Compiler{Binary: bin, KeyFile: key, Timeout: time.Minute}
	c.Geo = func(_ context.Context, cs []string, as []uint32) ([]byte, error) {
		return []byte(`{"countries":{"VN":["198.51.100.0/25"]},"asns":{"64500":["203.0.113.0/24"]}}`), nil
	}
	b, err := c.Build(t.Context(), 1, []Named{
		{Name: "example-a", Spec: Spec{Mode: "enforce", GeoRules: []GeoRule{{ID: 190000, Countries: []string{"VN"}, Action: "block"}}}},
		{Name: "example-b", Spec: Spec{Mode: "enforce", GeoRules: []GeoRule{{ID: 190001, ASNs: []uint32{64500}, Not: true, Action: "log"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("SGE1")) || !bytes.Contains(b, []byte("SSC1")) {
		t.Fatal("bundle without sections GEO and SCOPE")
	}
	// the same id in two policies fails the build
	_, err = c.Build(t.Context(), 2, []Named{
		{Name: "example-a", Spec: Spec{Mode: "enforce", GeoRules: []GeoRule{{ID: 190000, Countries: []string{"VN"}, Action: "block"}}}},
		{Name: "example-b", Spec: Spec{Mode: "enforce", GeoRules: []GeoRule{{ID: 190000, Countries: []string{"VN"}, Action: "log"}}}},
	})
	if err == nil {
		t.Fatal("duplicate geo rule id compiled")
	}
}
