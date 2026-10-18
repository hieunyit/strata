package policy

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/strata/strata/agent/pkg/bundlefmt"
)

// Optional real subprocess boundary; no network or production signing key.
func TestStagingAdapterWithRealCompiler(t *testing.T) {
	binary := os.Getenv("STRATA_TEST_COMPILER")
	if binary == "" {
		t.Skip("STRATA_TEST_COMPILER not set")
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "example.key")
	rulesFile := filepath.Join(dir, "rules.yaml")
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	if err := os.WriteFile(keyFile, seed, 0600); err != nil {
		t.Fatal(err)
	}
	source := `ir_version: 1
ruleset: {name: example, version: '1'}
rules:
 - id: 700011
   name: example SQLi
   layer: managed
   stage: request_headers
   score: 100
   severity: critical
   match:
     all:
      - targets: [{var: args}]
        operator: {type: detect_sqli}
   metadata: {source: organization, license: Apache-2.0}
`
	if err := os.WriteFile(rulesFile, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	c := Compiler{Binary: binary, KeyFile: keyFile, Rules: []string{rulesFile}, CostBudget: DefaultCostBudget, StagedRules: map[string][]uint32{"example-api": {700011}}}
	ps := []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", AutoStaging: exampleAutoStaging()}}, {Name: "example-web", Spec: Spec{Mode: "enforce"}}}
	prepared, err := c.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	blob, err := prepared.Build(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	h, err := bundlefmt.Verify(blob, pub)
	if err != nil || h.Version != 7 || h.Policies != 2 || len(blob) < 256 {
		t.Fatalf("signed compiler artifact: %+v %v", h, err)
	}
	if blob[64+62]&32 == 0 || blob[64+64+62]&32 != 0 {
		t.Fatal("staging flag missing or expanded to other policy")
	}
}
