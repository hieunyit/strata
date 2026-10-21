package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

const repo = "../../../.."

// one IR ruleset with two rules, enough to compile a real bundle.
const ruleset = `ir_version: 1
ruleset: { name: rel-test, version: "1" }
rules:
  - id: 800500
    name: union select
    layer: managed
    stage: request_headers
    score: 40
    action_mode: score
    severity: critical
    match: { all: [ { targets: [ { var: args } ], operator: { type: rx, value: 'union\s+select' } } ] }
    metadata: { source: organization, license: Apache-2.0 }
  - id: 700500
    name: virtual patch sample
    layer: managed
    stage: request_headers
    score: 100
    action_mode: block_alone
    severity: critical
    match: { all: [ { targets: [ { var: uri_raw } ], operator: { type: contains, value: "/x/exploit" } } ] }
    metadata: { source: strata, license: Apache-2.0 }
`

func requireTools(t *testing.T) {
	t.Helper()
	if _, err := runner.Find(repo); err != nil {
		if os.Getenv("STRATA_RULES_REQUIRE_TOOLS") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
}

func seedFile(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "sign.key")
	if err := os.WriteFile(f, priv.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	return f, pub
}

func TestBuildPackage(t *testing.T) {
	requireTools(t)
	rulesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rulesDir, "rel.yaml"), []byte(ruleset), 0o644); err != nil {
		t.Fatal(err)
	}
	key, pub := seedFile(t)
	out := t.TempDir()

	m, err := Build(Options{
		Repo: repo, RulesDir: rulesDir, Version: "2026.w42",
		BundleVersion: 7, KeyFile: key, Out: out,
	})
	if err != nil {
		t.Fatal(err)
	}

	if m.Rules != 2 || m.BundleVersion != 7 || m.Version != "2026.w42" {
		t.Fatalf("manifest: %+v", m)
	}
	if m.SHA256 == "" || len(m.RuleIDs) != 2 {
		t.Fatalf("manifest sums/ids: %+v", m)
	}
	if m.ByActionMode["block_alone"] != 1 || m.ByActionMode["score"] != 1 {
		t.Errorf("action modes: %v", m.ByActionMode)
	}
	if m.BySource["organization"] != 1 || m.BySource["strata"] != 1 {
		t.Errorf("sources: %v", m.BySource)
	}

	for _, f := range []string{"strata-signatures-2026.w42.sbn", "strata-signatures-2026.w42.pub", "strata-signatures-2026.w42.rules.json", "cost.json", "manifest.json", "manifest.json.sig", "CHANGELOG.md", "NOTICE"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	// the written public key matches the signing seed
	gotPub, _ := os.ReadFile(filepath.Join(out, "strata-signatures-2026.w42.pub"))
	if string(gotPub) != string(pub) {
		t.Error("published public key does not match the key")
	}
	// changelog carries the version and the counts
	cl, _ := os.ReadFile(filepath.Join(out, "CHANGELOG.md"))
	for _, want := range []string{"Strata signatures 2026.w42", "Bundle version: 7", "block_alone"} {
		if !strings.Contains(string(cl), want) {
			t.Errorf("CHANGELOG lacks %q:\n%s", want, cl)
		}
	}
	// the signed manifest covers the whole package: verify passes, and
	// fails once any file (or the manifest) is changed
	if _, err := Verify(out, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := Verify(out, make([]byte, 32)); err == nil {
		t.Error("verify accepted another public key")
	}
	for _, f := range []string{"NOTICE", "CHANGELOG.md", "strata-signatures-2026.w42.sbn", "strata-signatures-2026.w42.rules.json", "cost.json", "manifest.json"} {
		p := filepath.Join(out, f)
		orig, _ := os.ReadFile(p)
		if err := os.WriteFile(p, append(append([]byte{}, orig...), ' '), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(out, pub); err == nil {
			t.Errorf("verify accepted a changed %s", f)
		}
		_ = os.WriteFile(p, orig, 0o644)
	}

	// NOTICE comes from the repo and records the sources
	notice, _ := os.ReadFile(filepath.Join(out, "NOTICE"))
	if !strings.Contains(string(notice), "OWASP CRS") {
		t.Error("NOTICE not copied from the repo")
	}
}

func TestChangelogDiffsBaseline(t *testing.T) {
	requireTools(t)
	rulesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rulesDir, "rel.yaml"), []byte(ruleset), 0o644); err != nil {
		t.Fatal(err)
	}
	key, _ := seedFile(t)

	// first release: both rules
	out1 := t.TempDir()
	if _, err := Build(Options{Repo: repo, RulesDir: rulesDir, Version: "2026.w41", KeyFile: key, Out: out1}); err != nil {
		t.Fatal(err)
	}

	// second release with one rule removed, against the first manifest
	one := strings.SplitN(ruleset, "  - id: 700500", 2)[0]
	if err := os.WriteFile(filepath.Join(rulesDir, "rel.yaml"), []byte(one), 0o644); err != nil {
		t.Fatal(err)
	}
	out2 := t.TempDir()
	if _, err := Build(Options{
		Repo: repo, RulesDir: rulesDir, Version: "2026.w42", KeyFile: key, Out: out2,
		Baseline: filepath.Join(out1, "manifest.json"),
	}); err != nil {
		t.Fatal(err)
	}
	cl, _ := os.ReadFile(filepath.Join(out2, "CHANGELOG.md"))
	if !strings.Contains(string(cl), "Changes since 2026.w41") || !strings.Contains(string(cl), "Removed: 1 rules (700500)") {
		t.Errorf("changelog diff wrong:\n%s", cl)
	}
}

// --policies is compiled into the bundle: a valid file builds, a broken one
// fails the release instead of being ignored.
func TestBuildWithPolicies(t *testing.T) {
	requireTools(t)
	rulesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rulesDir, "rel.yaml"), []byte(ruleset), 0o644); err != nil {
		t.Fatal(err)
	}
	key, _ := seedFile(t)
	pol := filepath.Join(t.TempDir(), "policies.yaml")
	if err := os.WriteFile(pol, []byte("policies:\n  - { name: example-api, mode: enforce }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(Options{Repo: repo, RulesDir: rulesDir, Version: "p1", KeyFile: key, Out: t.TempDir(), Policies: pol}); err != nil {
		t.Fatalf("valid policies: %v", err)
	}
	if err := os.WriteFile(pol, []byte("policies:\n  - { name: example-api, mode: nonsense }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(Options{Repo: repo, RulesDir: rulesDir, Version: "p2", KeyFile: key, Out: t.TempDir(), Policies: pol}); err == nil {
		t.Fatal("a broken policies file was not compiled in")
	}
}

// RV-S-01: one release run per pack; each package holds only its rules.
func TestBuildTwoPacks(t *testing.T) {
	requireTools(t)
	rulesDir := t.TempDir()
	sig := `ir_version: 1
ruleset: { name: rel-sig, version: "1" }
rules:
  - id: 400500
    name: et-open sample
    layer: managed
    stage: request_headers
    score: 100
    action_mode: block_alone
    severity: critical
    match: { all: [ { targets: [ { var: path } ], operator: { type: ends_with, value: /c99.php } } ] }
    metadata: { source: et-open, license: BSD-3-Clause, upstream_id: "2000500", upstream_version: "1", author: Example ET Author }
`
	for f, body := range map[string]string{"rel.yaml": ruleset, "sig.yaml": sig} {
		if err := os.WriteFile(filepath.Join(rulesDir, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	key, pub := seedFile(t)
	for _, c := range []struct {
		pack, bundle string
		ids          []int
	}{
		{PackCore, "strata-core-2026.w43.sbn", []int{700500, 800500}},
		{PackSignature, "strata-signatures-2026.w43.sbn", []int{400500}},
		{"", "strata-signatures-2026.w43.sbn", []int{400500, 700500, 800500}},
	} {
		out := t.TempDir()
		m, err := Build(Options{Repo: repo, RulesDir: rulesDir, Version: "2026.w43", KeyFile: key, Out: out, Pack: c.pack})
		if err != nil {
			t.Fatalf("%q: %v", c.pack, err)
		}
		if m.Pack != c.pack || m.Bundle != c.bundle || !equalInts(m.RuleIDs, c.ids) {
			t.Fatalf("%q: pack %q bundle %s ids %v", c.pack, m.Pack, m.Bundle, m.RuleIDs)
		}
		if _, err := Verify(out, pub); err != nil {
			t.Fatalf("%q: verify: %v", c.pack, err)
		}
	}
	if _, err := Build(Options{Repo: repo, RulesDir: rulesDir, Version: "x", KeyFile: key, Out: t.TempDir(), Pack: "bots"}); err == nil {
		t.Fatal("unknown pack accepted")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The engine flags the same sources (the policy's signatures setting).
func TestSignatureSourcesMatchTheEngine(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repo, "engine/src/rules.rs"))
	if err != nil {
		t.Fatal(err)
	}
	line := ""
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "pub const SIGNATURE_SOURCES") {
			line = l
		}
	}
	want := `pub const SIGNATURE_SOURCES: &[&str] = &["` + strings.Join(SignatureSources, `", "`) + `"];`
	if line != want {
		t.Fatalf("engine/src/rules.rs:\n  %s\nwant\n  %s", line, want)
	}
	for src, pack := range map[string]string{"crs": PackCore, "strata": PackCore, "organization": PackCore,
		"sigma": PackSignature, "et-open": PackSignature, "crawler-user-agents": PackSignature} {
		if !InPack(pack, src) || InPack(map[string]string{PackCore: PackSignature, PackSignature: PackCore}[pack], src) {
			t.Fatalf("%s is not only in %s", src, pack)
		}
	}
}

func TestChangelogDetectsChangedRulesAndLegacyUnknown(t *testing.T) {
	before := &Manifest{Version: "v1", RuleIDs: []int{700001, 700002}, RuleDigests: map[string]string{"700001": "old", "700002": "same"}}
	after := &Manifest{Version: "v2", RuleIDs: []int{700001, 700002, 700003}, RuleDigests: map[string]string{"700001": "new", "700002": "same", "700003": "added"}}
	changed, unknown := changedIDs(before, after)
	if len(changed) != 1 || changed[0] != 700001 || unknown != 0 {
		t.Fatalf("change detection %v %d", changed, unknown)
	}
	base := filepath.Join(t.TempDir(), "manifest.json")
	if err := writeJSON(base, before); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := writeChangelog(out, after, base); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Added: 1 rules (700003)", "Modified: 1 rules (700001)"} {
		if !strings.Contains(string(text), want) {
			t.Fatalf("missing %q: %s", want, text)
		}
	}
	before.RuleDigests = nil
	if err := writeJSON(base, before); err != nil {
		t.Fatal(err)
	}
	if err := writeChangelog(out, after, base); err != nil {
		t.Fatal(err)
	}
	text, err = os.ReadFile(out)
	if err != nil || !strings.Contains(string(text), "Content comparison unavailable for 2 retained rules") {
		t.Fatalf("legacy silently unchanged: %s %v", text, err)
	}
}
