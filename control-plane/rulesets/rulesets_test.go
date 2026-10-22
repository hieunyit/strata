package rulesets

import (
	"bytes"
	"os"
	"testing"
)

// The built-in copy is rules/sets/catalog.yaml, byte for byte: the compiler
// tests check that one against the rule packs.
func TestCatalogIsTheRepositorys(t *testing.T) {
	repo, err := os.ReadFile("../../rules/sets/catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(repo, catalogYAML) {
		t.Fatal("control-plane/rulesets/catalog.yaml differs from rules/sets/catalog.yaml: copy it again")
	}
}

func TestSetsAndFilters(t *testing.T) {
	if len(All()) < 10 {
		t.Fatalf("%d sets", len(All()))
	}
	s, ok := Get("bots-scanners")
	if !ok || s.Group != "bot" || s.Class != "malicious" || s.Title["vi"] == "" {
		t.Fatalf("bots-scanners: %+v", s)
	}
	if _, ok := Get("no-such-set"); ok {
		t.Fatal("unknown set found")
	}
	for _, tc := range []struct {
		f    Filter
		id   uint32
		src  string
		at   string
		tags []string
		want bool
	}{
		{Filter{Sources: []string{"crawler-user-agents"}, Tags: []string{"scanner"}}, 500300, "crawler-user-agents", "bot", []string{"scanner"}, true},
		{Filter{Sources: []string{"crawler-user-agents"}, Tags: []string{"scanner"}}, 500300, "crawler-user-agents", "bot", []string{"seo"}, false},
		{Filter{Sources: []string{"crawler-user-agents"}, Tags: []string{"scanner"}}, 500300, "et-open", "bot", []string{"scanner"}, false},
		{Filter{AttackTypes: []string{"xss", "sql-injection"}}, 942100, "crs", "sql-injection", nil, true},
		{Filter{IDs: []uint32{500001}}, 500001, "strata", "bot", nil, true},
		{Filter{IDs: []uint32{500001}}, 500002, "strata", "bot", nil, false},
		{Filter{}, 1, "crs", "xss", nil, false},
	} {
		if got := tc.f.Matches(tc.id, tc.src, tc.at, tc.tags); got != tc.want {
			t.Errorf("%+v on %d %s %s %v: %v", tc.f, tc.id, tc.src, tc.at, tc.tags, got)
		}
	}
}
