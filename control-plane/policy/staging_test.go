package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagingRequiresExplicitScopedDelegation(t *testing.T) {
	ps := []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", AutoStaging: exampleAutoStaging()}}}
	c := Compiler{StagedRules: map[string][]uint32{"example-api": {942100, 700011}}}
	got, err := c.stagingFor(ps)
	if err != nil || got["example-api"][0] != 700011 {
		t.Fatalf("canonical map: %v %v", got, err)
	}
	c.StagedRules["example-api"][0] = 42
	if got["example-api"][1] != 942100 {
		t.Fatal("overlay shares caller slice")
	}
	for _, tc := range []struct {
		ids  map[string][]uint32
		spec Spec
	}{
		{map[string][]uint32{"other-api": {942100}}, ps[0].Spec},
		{map[string][]uint32{"example-api": {42}}, ps[0].Spec},
		{map[string][]uint32{"example-api": {942100, 942100}}, ps[0].Spec},
		{map[string][]uint32{"example-api": {942100}}, Spec{Mode: "enforce"}},
		{map[string][]uint32{"example-api": {942100}}, Spec{Mode: "enforce", AutoStaging: &AutoStaging{Enabled: false}}},
		{map[string][]uint32{"example-api": {942100}}, Spec{Mode: "shadow", AutoStaging: exampleAutoStaging()}},
		{map[string][]uint32{"example-api": make([]uint32, 17)}, ps[0].Spec},
	} {
		c.StagedRules = tc.ids
		if _, err := c.Build(t.Context(), 1, []Named{{Name: "example-api", Spec: tc.spec}}); err == nil || !strings.Contains(err.Error(), "staging") {
			t.Fatalf("unauthorized overlay reached compiler: %v", err)
		}
	}
	c.StagedRules = map[string][]uint32{"example-api": {}}
	if out, err := c.stagingFor(ps); err != nil || out != nil {
		t.Fatalf("empty overlay: %v %v", out, err)
	}
}
func TestStagingGlobalBounds(t *testing.T) {
	ids := make([]uint32, 16)
	for i := range ids {
		ids[i] = 700001 + uint32(i)
	}
	a := exampleAutoStaging()
	a.RuleIDs = ids
	c := Compiler{StagedRules: make(map[string][]uint32)}
	var ps []Named
	for i := range 257 {
		name := fmt.Sprintf("example-%d", i)
		ps = append(ps, Named{Name: name, Spec: Spec{Mode: "enforce", AutoStaging: a}})
		c.StagedRules[name] = ids
	}
	if _, err := c.stagingFor(ps); err == nil {
		t.Fatal("global rule cap exceeded")
	}
	for i := len(ps); i < 4097; i++ {
		ps = append(ps, Named{Name: fmt.Sprintf("example-%d", i), Spec: Spec{Mode: "enforce", AutoStaging: a}})
	}
	c.StagedRules = map[string][]uint32{"example-0": {700001}}
	if _, err := c.stagingFor(ps); err == nil {
		t.Fatal("policy cap exceeded for otherwise valid input")
	}

}

func TestSnapshotCapturesAndHashesEffectiveStaging(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "compiler")
	script := `#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
 case "$1" in --policies) policies_file=$2;; --out) bundle_file=$2;; esac
 shift 2
done
cat "$policies_file" > "$bundle_file"
`
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	c := Compiler{Binary: bin, StagedRules: map[string][]uint32{"example-api": {942100, 700011}}}
	ps := []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", AutoStaging: exampleAutoStaging()}}}
	first, err := c.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	c.StagedRules["example-api"] = []uint32{700011, 942100}
	same, err := c.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer same.Close()
	if same.Digest != first.Digest {
		t.Fatal("noncanonical staging digest")
	}
	c.StagedRules["example-api"] = []uint32{942100}
	changed, err := c.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer changed.Close()
	if changed.Digest == first.Digest {
		t.Fatal("staging change did not invalidate replay digest")
	}
	c.StagedRules = nil
	raw, err := first.Build(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Policies []struct {
			StagedRules []uint32 `json:"staged_rules"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Policies) != 1 || len(doc.Policies[0].StagedRules) != 2 || doc.Policies[0].StagedRules[0] != 700011 {
		t.Fatalf("captured overlay changed: %s %v", raw, err)
	}
}
