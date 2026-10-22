package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/strata/strata/control-plane/store"
)

// CP-SEC-02: names go into object keys and paths.
func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"example-api": true, "api.v2": true, ".hidden": true, "a..b": true, "x": true,
		".": false, "..": false, "...": false, "": false, "Example": false, "a/b": false,
		"a234567890123456789012345678901234567890123456789012345":  true,
		"a2345678901234567890123456789012345678901234567890123456": false,
	} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestSpecValidate(t *testing.T) {
	good := []Spec{{Mode: "shadow"}, {Mode: "enforce", Oversize: "block", Response: &Response{DataGuard: []string{"cccd", "jwt", "pan"}}},
		{Mode: "shadow", MaxSnippetSize: 128}, {Mode: "shadow", MaxSnippetSize: 2048}, {Mode: "enforce", MaxSnippetSize: 4096},
		{Mode: "shadow", Privacy: &Privacy{SensitiveFields: []string{"ma_khach_hang"}, MaskPatterns: []string{"KH[0-9]{8}"}}},
		{Mode: "shadow", Privacy: &Privacy{Identity: "hmac"}}, {Mode: "shadow", Privacy: &Privacy{Identity: "plain"}},
		{Mode: "enforce", CanaryPercent: 1}, {Mode: "enforce", CanaryPercent: 0.01}, {Mode: "enforce", CanaryPercent: 99.99}, {Mode: "enforce", CanaryPercent: 12.34},
		// #28: max_args 1..1020
		{Mode: "enforce", MaxArgs: 1}, {Mode: "enforce", MaxArgs: 1020},
		// #98: fail_on_findings
		{Mode: "enforce", FailOnFindings: "pass"}, {Mode: "enforce", FailOnFindings: "block"},
		// audit 22/10/2026: parse_error
		{Mode: "enforce", ParseError: "pass"}, {Mode: "enforce", ParseError: "block"},
		// W17-S-01: CRS paranoia levels
		{Mode: "enforce", CRSParanoia: 1}, {Mode: "enforce", CRSParanoia: 4}, {Mode: "enforce", CRSParanoiaShadow: 2},
		{Mode: "enforce", CRSParanoia: 2, CRSParanoiaShadow: 2}, {Mode: "shadow", CRSParanoia: 2, CRSParanoiaShadow: 4},
		{Mode: "shadow", CRSPlugins: []string{"wordpress", "nextcloud"}},
		// W19-G2-01: geo rules
		{Mode: "enforce", GeoRules: []GeoRule{{ID: 190000, Countries: []string{"VN"}, Action: "block"}, {ID: 199999, ASNs: []uint32{64500}, Not: true, Action: "log"}}}}
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
		{Mode: "enforce", FailOnFindings: "maybe"},
		{Mode: "enforce", ParseError: "maybe"},
		{Mode: "enforce", CRSParanoia: -1}, {Mode: "enforce", CRSParanoia: 5}, {Mode: "enforce", CRSParanoiaShadow: 5},
		{Mode: "enforce", CRSParanoiaShadow: -1}, {Mode: "enforce", CRSParanoia: 3, CRSParanoiaShadow: 2},
		{Mode: "shadow", CRSPlugins: []string{"WordPress"}}, {Mode: "shadow", CRSPlugins: []string{"wordpress", "wordpress"}},
		{Mode: "shadow", CRSPlugins: []string{""}}, {Mode: "shadow", CRSPlugins: []string{"../x"}},
		{Mode: "shadow", CRSPlugins: make([]string, 17)},
		{Mode: "shadow", GeoRules: []GeoRule{{ID: 189999, Countries: []string{"VN"}, Action: "block"}}},
		{Mode: "shadow", GeoRules: []GeoRule{{ID: 190000, Countries: []string{"VN"}, Action: "block"}, {ID: 190000, Countries: []string{"US"}, Action: "log"}}},
		{Mode: "shadow", GeoRules: []GeoRule{{ID: 190000, Action: "block"}}},
		{Mode: "shadow", GeoRules: []GeoRule{{ID: 190000, Countries: []string{"vn"}, Action: "block"}}},
		{Mode: "shadow", GeoRules: []GeoRule{{ID: 190000, Countries: []string{"VN", "VN"}, Action: "block"}}},
		{Mode: "shadow", GeoRules: []GeoRule{{ID: 190000, ASNs: []uint32{0}, Action: "block"}}},
		{Mode: "shadow", GeoRules: []GeoRule{{ID: 190000, Countries: []string{"VN"}, Action: "deny"}}},
		{Mode: "shadow", GeoRules: make([]GeoRule, 17)}}
	for _, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("%+v accepted", s)
		}
	}
}

func TestSpecParanoiaNormalize(t *testing.T) {
	for _, c := range []struct{ in, want Spec }{
		{Spec{Mode: "shadow"}, Spec{Mode: "shadow"}},
		{Spec{Mode: "shadow", CRSParanoia: 1, CRSParanoiaShadow: 1}, Spec{Mode: "shadow"}},
		{Spec{Mode: "shadow", CRSParanoia: 1, CRSParanoiaShadow: 2}, Spec{Mode: "shadow", CRSParanoiaShadow: 2}},
		{Spec{Mode: "shadow", CRSParanoia: 2, CRSParanoiaShadow: 2}, Spec{Mode: "shadow", CRSParanoia: 2}},
		{Spec{Mode: "shadow", CRSParanoia: 2, CRSParanoiaShadow: 3}, Spec{Mode: "shadow", CRSParanoia: 2, CRSParanoiaShadow: 3}},
	} {
		got := c.in
		got.Normalize()
		if got.CRSParanoia != c.want.CRSParanoia || got.CRSParanoiaShadow != c.want.CRSParanoiaShadow {
			t.Errorf("%+v normalized to %+v, want %+v", c.in, got, c.want)
		}
		e1, s1 := c.in.ParanoiaLevels()
		e2, s2 := got.ParanoiaLevels()
		if e1 != e2 || s1 != s2 {
			t.Errorf("%+v: levels changed (%d,%d) -> (%d,%d)", c.in, e1, s1, e2, s2)
		}
	}
	// plugins are sorted, none is absent
	s := Spec{Mode: "shadow", CRSPlugins: []string{"wordpress", "drupal"}}
	s.Normalize()
	if !reflect.DeepEqual(s.CRSPlugins, []string{"drupal", "wordpress"}) {
		t.Errorf("plugins %v", s.CRSPlugins)
	}
	s.CRSPlugins = []string{}
	s.Normalize()
	if s.CRSPlugins != nil {
		t.Errorf("empty plugins %v", s.CRSPlugins)
	}
	// geo rule lists are sorted; their keys, across specs
	g := Spec{Mode: "shadow", GeoRules: []GeoRule{{ID: 190000, Countries: []string{"VN", "CN"}, ASNs: []uint32{9, 3}, Action: "log"}}}
	g.Normalize()
	if !reflect.DeepEqual(g.GeoRules[0].Countries, []string{"CN", "VN"}) || !reflect.DeepEqual(g.GeoRules[0].ASNs, []uint32{3, 9}) {
		t.Errorf("geo rule %+v", g.GeoRules[0])
	}
	cs, as := GeoKeys(g, Spec{GeoRules: []GeoRule{{Countries: []string{"VN", "US"}, ASNs: []uint32{3}}}})
	if !reflect.DeepEqual(cs, []string{"CN", "US", "VN"}) || !reflect.DeepEqual(as, []uint32{3, 9}) {
		t.Errorf("keys %v %v", cs, as)
	}
	// the default stays out of the stored JSON
	raw, _ := json.Marshal(Spec{Mode: "shadow"})
	if strings.Contains(string(raw), "paranoia") {
		t.Errorf("default spec JSON %s", raw)
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
	out, err := c.Build(context.Background(), 7, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", Oversize: "block", CanaryPercent: 5, MaxArgs: 200, FailOnFindings: "block", ParseError: "pass", CRSParanoia: 2, CRSParanoiaShadow: 3, CRSPlugins: []string{"wordpress"}, Exceptions: []Exception{exampleException()}}}})
	if err != nil || string(out) != "bundle" {
		t.Fatalf("%q %v", out, err)
	}
	args, _ := os.ReadFile(argsFile)
	for _, want := range []string{"--key /keys/seed", "--version 7", "--rules a.yaml --rules b.yaml"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("args %q lack %q", args, want)
		}
	}
	// W19-G2-01: geo rules need the networks; they go in --geo
	geoSpec := []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", GeoRules: []GeoRule{{ID: 190000, Countries: []string{"VN"}, ASNs: []uint32{64500}, Action: "block"}}}}}
	if _, err := c.Build(context.Background(), 8, geoSpec); err == nil || !strings.Contains(err.Error(), "GeoIP database") {
		t.Errorf("geo rules without networks: %v", err)
	}
	var asked []string
	c.Geo = func(_ context.Context, cs []string, as []uint32) ([]byte, error) {
		asked = append(cs, fmt.Sprint(as))
		return []byte(`{"countries":{"VN":[]}}`), nil
	}
	if _, err := c.Build(context.Background(), 8, geoSpec); err != nil {
		t.Fatal(err)
	}
	if args, _ := os.ReadFile(argsFile); !strings.Contains(string(args), "--geo ") || !reflect.DeepEqual(asked, []string{"VN", "[64500]"}) {
		t.Errorf("geo args %q asked %v", args, asked)
	}
	c.Geo = nil
	if _, err := c.Build(context.Background(), 7, []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", Oversize: "block", CanaryPercent: 5, MaxArgs: 200, FailOnFindings: "block", CRSParanoia: 2, CRSParanoiaShadow: 3, CRSPlugins: []string{"wordpress"}, Exceptions: []Exception{exampleException()}}}}); err != nil {
		t.Fatal(err)
	}
	pol, _ := os.ReadFile(filepath.Join(dir, "policies.json"))
	var doc struct {
		Policies  []map[string]any  `json:"policies"`
		BlockPage map[string]string `json:"block_page"`
	}
	if err := json.Unmarshal(pol, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Policies[0]["name"] != "example-api" || doc.Policies[0]["mode"] != "enforce" || doc.Policies[0]["oversize"] != "block" || doc.Policies[0]["canary_percent"] != 5.0 || doc.Policies[0]["max_args"] != 200.0 || doc.Policies[0]["fail_on_findings"] != "block" || doc.Policies[0]["parse_error"] != "pass" ||
		doc.Policies[0]["crs_paranoia"] != 2.0 || doc.Policies[0]["crs_paranoia_shadow"] != 3.0 ||
		!reflect.DeepEqual(doc.Policies[0]["crs_plugins"], []any{"wordpress"}) ||
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
