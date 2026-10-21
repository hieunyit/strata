package policy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/strata/strata/agent/pkg/bundlefmt"
)

func TestNativePrivacySectionMatchesGoSink(t *testing.T) {
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
	if err := os.WriteFile(rulesFile, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Compiler{Binary: binary, KeyFile: keyFile, Rules: []string{rulesFile}, IdentityKey: func(context.Context) ([]byte, error) { return seed, nil }}
	blob, err := c.Build(t.Context(), 7, []Named{{Name: "example-api", Spec: Spec{Mode: "shadow", Privacy: &Privacy{SensitiveFields: []string{"customer_id"}, MaskPatterns: []string{`PRIVATE-[0-9]+`}, Identity: "hmac"}}}})
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	filters, err := bundlefmt.PrivacyFilters(blob, pub)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := filters["example-api"]
	if !ok || f == nil || f.Field("ARGS:customer_id", "secret") != "[MASKED]" || f.Text("PRIVATE-123") != "[MASKED]" || f.Identity("example-user") == "example-user" {
		t.Fatal("native privacy not applied to Go sink")
	}
}
