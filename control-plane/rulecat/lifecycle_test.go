package rulecat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogLifecycleAndChangedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	first := `ir_version: 1
ruleset: {name: example-pack, version: '1.2'}
rules:
- id: 700001
  name: Virtual patch CVE-2026-12345
  layer: managed
  metadata: {source: strata, attack_type: rce, owner: example-team, review_by: '2026-12-01', license: Apache-2.0}
  match: {value: old}
`
	if err := os.WriteFile(path, []byte(first), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := Load([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	entry := before.Entries()[0]
	if entry.Version != "1.2" || len(entry.CVEs) != 1 || entry.Owner != "example-team" || entry.Digest == "" || entry.Pack != "core" {
		t.Fatalf("metadata %+v", entry)
	}
	second := first + "- id: 400001\n  name: Example signature\n  metadata: {source: sigma}\n"
	if err := os.WriteFile(path, []byte(second), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := Load([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	changes := Diff(before.Entries(), after.Entries(), 0, 200)
	if changes.Added != 1 || changes.Removed != 0 || changes.Modified != 0 {
		t.Fatalf("added %+v", changes)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(first, "value: old", "value: new", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := Load([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	changes = Diff(before.Entries(), changed.Entries(), 0, 200)
	if changes.Modified != 1 || changed.Digest() == before.Digest() {
		t.Fatalf("same ID edit missed: %+v", changes)
	}
	found, next := before.Search("strata", "cve-2026-12345", "rce", 0, 200)
	if len(found) != 1 || next != 0 {
		t.Fatalf("filter %+v %d", found, next)
	}
	if _, err := Load(make([]string, 129)); err == nil {
		t.Fatal("unbounded input list")
	}
}
