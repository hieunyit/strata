package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/strata/strata/control-plane/store"
)

func TestSpecValidate(t *testing.T) {
	good := []Spec{{Mode: "shadow"}, {Mode: "enforce", Oversize: "block", Response: &Response{DataGuard: []string{"cccd", "jwt", "pan"}}},
		{Mode: "shadow", MaxSnippetSize: 128}, {Mode: "shadow", MaxSnippetSize: 2048}, {Mode: "enforce", MaxSnippetSize: 4096},
		{Mode: "shadow", Privacy: &Privacy{SensitiveFields: []string{"ma_khach_hang"}, MaskPatterns: []string{"KH[0-9]{8}"}}},
		{Mode: "shadow", Privacy: &Privacy{Identity: "hmac"}}, {Mode: "shadow", Privacy: &Privacy{Identity: "plain"}},
		{Mode: "enforce", CanaryPercent: 1}, {Mode: "enforce", CanaryPercent: 0.01}, {Mode: "enforce", CanaryPercent: 99.99}, {Mode: "enforce", CanaryPercent: 12.34},
		// #28: max_args 1..1020
		{Mode: "enforce", MaxArgs: 1}, {Mode: "enforce", MaxArgs: 1020},
		// #98: fail_on_findings
		{Mode: "enforce", FailOnFindings: "pass"}, {Mode: "enforce", FailOnFindings: "block"}}
	for _, s := range good {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	bad := []Spec{{}, {Mode: "block"}, {Mode: "shadow", Oversize: "drop"},
		{Mode: "shadow", Response: &Response{DataGuard: []string{"ssn"}}},
		{Mode: "shadow", Response: &Response{DataGuard: []string{"jwt", "jwt"}}},
		{Mode: "shadow", MaxSnippetSize: 1000}, {Mode: "shadow", MaxSnippetSize: 8192}, {Mode: "shadow", MaxSnippetSize: -1},
		{Mode: "shadow", Privacy: &Privacy{MaskPatterns: []string{"a*"}}},
		{Mode: "shadow", Privacy: &Privacy{MaskPatterns: []string{"(unclosed"}}},
		{Mode: "shadow", Privacy: &Privacy{SensitiveFields: []string{"has space"}}},
		{Mode: "shadow", Privacy: &Privacy{Identity: "sha1"}},
		// W12-G2-01: canary only on enforce, 0.01..99.99, two decimals
		{Mode: "shadow", CanaryPercent: 5}, {Mode: "enforce", CanaryPercent: 100}, {Mode: "enforce", CanaryPercent: -1},
		{Mode: "enforce", CanaryPercent: 0.005}, {Mode: "enforce", CanaryPercent: 1.234},
		{Mode: "enforce", MaxArgs: -1}, {Mode: "enforce", MaxArgs: 1021},
		{Mode: "enforce", FailOnFindings: "maybe"}}
	for _, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
}

// signed makes a bundle the way strata-compile lays out its header.
func signed(priv ed25519.PrivateKey, version uint64, policies uint32) []byte {
	b := make([]byte, 4096)
	copy(b, "STRBNDL\x00")
	binary.LittleEndian.PutUint16(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], policies)
	binary.LittleEndian.PutUint64(b[16:], version)
	return append(b, ed25519.Sign(priv, b)...)
}

type fakeStore struct {
	mu       sync.Mutex
	policies []store.Policy
	bundles  []store.Bundle
}

func (f *fakeStore) DeployablePolicies(context.Context) ([]store.Policy, error) {
	return f.policies, nil
}
func (f *fakeStore) WithBundleLock(_ context.Context, build func(uint64) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return build(uint64(len(f.bundles)) + 1)
}
func (f *fakeStore) RecordBundle(_ context.Context, b store.Bundle, _ store.Audit) (store.Bundle, error) {
	f.bundles = append(f.bundles, b)
	return b, nil
}

type fakeObjects struct{ puts map[string][]byte }

func (f *fakeObjects) Put(_ context.Context, key string, data []byte, sum string) error {
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != sum {
		return errors.New("sha256 metadata does not match")
	}
	f.puts[key] = data
	return nil
}
func (f *fakeObjects) Get(_ context.Context, key string) ([]byte, error) { return f.puts[key], nil }

type builderFunc func(version uint64, n int) []byte

func (b builderFunc) Build(_ context.Context, v uint64, ps []Named) ([]byte, error) {
	return b(v, len(ps)), nil
}

func TestDeploy(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	pols := []store.Policy{
		{ID: "api", Name: "example-api", CurrentVersion: 3, Spec: json.RawMessage(`{"mode":"enforce"}`)},
		{ID: "web", Name: "example-web", CurrentVersion: 1, Spec: json.RawMessage(`{"mode":"shadow"}`)},
	}
	cases := map[string]struct {
		build   builderFunc
		wantErr string
	}{
		"published":         {func(v uint64, n int) []byte { return signed(priv, v, uint32(n)) }, ""},
		"signed by another": {func(v uint64, n int) []byte { return signed(other, v, uint32(n)) }, "does not verify"},
		"wrong version":     {func(v uint64, n int) []byte { return signed(priv, v+5, uint32(n)) }, "says version"},
		"policy missing":    {func(v uint64, n int) []byte { return signed(priv, v, uint32(n-1)) }, "says version"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			st := &fakeStore{policies: pols}
			obj := &fakeObjects{puts: map[string][]byte{}}
			d := &Deployer{Store: st, Builder: tc.build, Objects: obj, PubKey: pub}
			dep, err := d.Deploy(context.Background(), store.Audit{Actor: "alice"})
			b := dep.Bundle
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if len(obj.puts) != 0 || len(st.bundles) != 0 {
					t.Fatal("a refused bundle was published")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data := obj.puts[ObjectKey(1)]
			sum := sha256.Sum256(data)
			if b.Version != 1 || hex.EncodeToString(b.SHA256) != hex.EncodeToString(sum[:]) || b.Contents["api"] != 3 || b.Contents["web"] != 1 {
				t.Fatalf("bundle %+v", b)
			}
		})
	}
}

// Build passes the policies, key, version and rules to the compiler, and
// reports its stderr when it fails.
func TestCompilerBuild(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-compile")
	argsFile := filepath.Join(dir, "args")
	body := `#!/bin/sh
echo "$@" > ` + argsFile + `
while [ $# -gt 0 ]; do
  case "$1" in
    --policies) cp "$2" ` + filepath.Join(dir, "policies.json") + `; shift 2 ;;
    --out) printf bundle > "$2"; shift 2 ;;
    *) shift ;;
  esac
done
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	page := filepath.Join(dir, "block.html")
	_ = os.WriteFile(page, []byte("<p>{{block_id}}</p>"), 0o644)
	c := &Compiler{Binary: script, KeyFile: "/keys/seed", Rules: []string{"a.yaml", "b.yaml"}, BlockPage: page, SupportContact: "ops@example.test"}
	out, err := c.Build(context.Background(), 7, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", Oversize: "block", CanaryPercent: 5, MaxArgs: 200, FailOnFindings: "block", Exceptions: []Exception{exampleException()}}}})
	if err != nil || string(out) != "bundle" {
		t.Fatalf("%q %v", out, err)
	}
	args, _ := os.ReadFile(argsFile)
	for _, want := range []string{"--key /keys/seed", "--version 7", "--rules a.yaml --rules b.yaml"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("args %q lack %q", args, want)
		}
	}
	pol, _ := os.ReadFile(filepath.Join(dir, "policies.json"))
	var doc struct {
		Policies  []map[string]any  `json:"policies"`
		BlockPage map[string]string `json:"block_page"`
	}
	if err := json.Unmarshal(pol, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Policies[0]["name"] != "example-api" || doc.Policies[0]["mode"] != "enforce" || doc.Policies[0]["oversize"] != "block" || doc.Policies[0]["canary_percent"] != 5.0 || doc.Policies[0]["max_args"] != 200.0 || doc.Policies[0]["fail_on_findings"] != "block" ||
		doc.BlockPage["html"] != "<p>{{block_id}}</p>" || doc.BlockPage["support_contact"] != "ops@example.test" {
		t.Fatalf("policies file %s", pol)
	}

	var entries []Exception
	rawEntries, err := json.Marshal(doc.Policies[0]["exceptions"])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawEntries, &entries); err != nil || len(entries) != 1 || entries[0] != exampleException() {
		t.Fatalf("compiler dropped/changed exception: %s %v", rawEntries, err)
	}

	failing := filepath.Join(dir, "failing")
	_ = os.WriteFile(failing, []byte("#!/bin/sh\necho 'rule 932220: pattern too large' >&2\nexit 1\n"), 0o755)
	c.Binary = failing
	if _, err := c.Build(context.Background(), 8, []Named{{Name: "x", Spec: Spec{Mode: "shadow"}}}); err == nil || !strings.Contains(err.Error(), "932220") {
		t.Fatalf("compiler failure: %v", err)
	}
	if _, err := c.Build(context.Background(), 8, nil); !errors.Is(err, ErrNoPolicies) {
		t.Fatalf("no policies: %v", err)
	}
}
