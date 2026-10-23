package policy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/strata/strata/agent/pkg/bundlefmt"
)

// RS-5: a policy whose rule sets change a rule's action gives a bundle
// with section OVERRIDE (17): a deploy needs nodes whose module declares
// section.17 (B02), so an older module is refused rather than ignoring the
// overrides. Without any change, the bundle needs nothing new.
func TestRuleSetsNeedSection17(t *testing.T) {
	binary := os.Getenv("STRATA_TEST_COMPILER")
	if binary == "" {
		t.Skip("STRATA_TEST_COMPILER not set")
	}
	dir := t.TempDir()
	keyFile, rulesFile := filepath.Join(dir, "example.key"), filepath.Join(dir, "rules.yaml")
	seed := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(keyFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	rules := `ir_version: 1
ruleset: {name: example, version: '1'}
rules:
 - id: 500100
   name: Known scanner user agent
   layer: managed
   stage: request_headers
   score: 20
   severity: warning
   match:
     all:
      - targets: [{var: request_headers, key: User-Agent}]
        operator: {type: pm, value: [sqlmap]}
   metadata: {source: crawler-user-agents, license: MIT, upstream_id: scanners, upstream_version: '1', author: example, attack_type: scanner, tags: [scanner]}
`
	if err := os.WriteFile(rulesFile, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	c := Compiler{Binary: binary, KeyFile: keyFile, Rules: []string{rulesFile}, IdentityKey: func(context.Context) ([]byte, error) { return seed, nil }}
	needs := func(spec Spec) []string {
		t.Helper()
		blob, err := c.Build(t.Context(), 1, []Named{{Name: "example-api", Spec: spec}})
		if err != nil {
			t.Fatal(err)
		}
		req, err := bundlefmt.Requirements(blob, pub)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}
	if got := needs(Spec{Mode: "enforce", RuleSets: []RuleSetRef{{Set: "bots-scanners", Action: "block"}}}); !slices.Contains(got, "section.17") {
		t.Fatalf("block scanners: %v", got)
	}
	// logging the scanners is what the rule does anyway: no override
	if got := needs(Spec{Mode: "enforce", RuleSets: []RuleSetRef{{Set: "bots-scanners", Action: "log"}}}); slices.Contains(got, "section.17") {
		t.Fatalf("log scanners: %v", got)
	}
}
