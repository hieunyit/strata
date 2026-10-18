package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompilerSnapshotUsesHashedBytes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bin := write("compiler", `#!/bin/sh
set -eu
while [ $# -gt 0 ]; do
 case "$1" in
 --out) out=$2;;
 --rules) rules=$2;;
 --policies) policies=$2;;
 esac
 shift 2
done
cat "$rules" "$policies" > "$out"
`)
	rules := write("rules.json", "original rules\n")
	page := write("block.html", "original block page")
	identity := []byte(strings.Repeat("i", 32))
	c := &Compiler{Binary: bin, Rules: []string{rules}, BlockPage: page, IdentityKey: func(context.Context) ([]byte, error) { return identity, nil }}
	ps := []Named{{Name: "example-api", Spec: Spec{Mode: "enforce", AutoStaging: exampleAutoStaging(), Privacy: &Privacy{Identity: "hmac", SensitiveFields: []string{"secret"}}}}}
	first, err := c.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	same, err := c.Prepare(t.Context(), ps)
	if err != nil {
		t.Fatal(err)
	}
	defer same.Close()
	if len(first.Digest) != 64 || first.Digest != same.Digest {
		t.Fatalf("unstable digest: %s %s", first.Digest, same.Digest)
	}
	previous := first.Digest
	for _, change := range []func(){
		func() { write("rules.json", "changed rules") },
		func() { write("block.html", "changed page") },
		func() { ps[0].Spec.Mode = "shadow" },
		func() { ps[0].Spec.Privacy.SensitiveFields[0] = "other" },
		func() { identity[0] = 'x' },
		func() { c.CostBudget++ },
		func() { ps[0].Spec.AutoStaging.RuleIDs[0]++ },
		func() { ps[0].Spec.AutoStaging.Enabled = false },
		func() { ps[0].Spec.AutoStaging.WindowSeconds++ },
		func() { ps[0].Spec.AutoStaging.MinMatches++ },
		func() { ps[0].Spec.AutoStaging.MinReports++ },
		func() { ps[0].Spec.AutoStaging.FPThresholdBPS++ },
		func() { c.SupportContact = "support@example.test" },
		func() { write("compiler", "#!/bin/sh\nexit 99\n") },
	} {
		change()
		next, err := c.Prepare(t.Context(), ps)
		if err != nil {
			t.Fatal(err)
		}
		if next.Digest == previous {
			t.Fatal("input change did not change digest")
		}
		previous = next.Digest
		next.Close()
	}
	// Despite every original changing, the prepared compiler uses original bytes.
	got, err := first.Build(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if !strings.HasPrefix(text, "original rules\n") || !strings.Contains(text, "original block page") || !strings.Contains(text, `"mode":"enforce"`) || !strings.Contains(text, `"secret"`) {
		t.Fatalf("snapshot changed: %s", text)
	}
	key, err := first.compiler.IdentityKey(t.Context())
	if err != nil || key[0] != 'i' {
		t.Fatal("identity key not snapshotted")
	}
	if a := first.policies[0].Spec.AutoStaging; a == nil || !a.Enabled || a.RuleIDs[0] != 942100 {
		t.Fatal("approved delegation snapshot changed")
	}
	// Close removes private files, including the executable copy.
	snapdir := same.dir
	same.Close()
	if _, err := os.Stat(snapdir); !os.IsNotExist(err) {
		t.Fatal("snapshot not removed")
	}
}

func TestCompilerSnapshotRejectsInvalidInputs(t *testing.T) {
	c := &Compiler{Binary: "/bin/sh", Rules: []string{filepath.Join(t.TempDir(), "missing")}}
	ps := []Named{{Name: "example-api", Spec: Spec{Mode: "shadow"}}}
	if _, err := c.Prepare(t.Context(), ps); err == nil {
		t.Fatal("missing rules accepted")
	}
	c.Rules = []string{t.TempDir()}
	if _, err := c.Prepare(t.Context(), ps); err == nil {
		t.Fatal("directory accepted")
	}
	c.Rules = nil
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Prepare(ctx, ps); err == nil {
		t.Fatal("cancelled snapshot accepted")
	}
	large := filepath.Join(t.TempDir(), "large")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(513 << 20); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	c.Rules = []string{large}
	if _, err := c.Prepare(t.Context(), ps); err == nil {
		t.Fatal("oversize input accepted")
	}
}

func TestCompilerSnapshotPreservesRuleParser(t *testing.T) {
	dir := t.TempDir()
	digests := map[string]string{}
	for _, suffix := range []string{".json", ".yaml", ".yml", ""} {
		source := filepath.Join(dir, "rule"+suffix)
		if err := os.WriteFile(source, []byte(`{}`), 0600); err != nil {
			t.Fatal(err)
		}
		c := Compiler{Binary: "/bin/sh", Rules: []string{source}}
		p, err := c.Prepare(t.Context(), []Named{{Name: "example-api", Spec: Spec{Mode: "shadow"}}})
		if err != nil {
			t.Fatal(err)
		}
		want := suffix
		if want == "" {
			want = ".json"
		}
		if got := filepath.Ext(p.compiler.Rules[0]); got != want {
			t.Errorf("%q input: copied suffix %q, want %q", suffix, got, want)
		}
		content, err := os.ReadFile(p.compiler.Rules[0])
		if err != nil || string(content) != `{}` {
			t.Fatalf("snapshot bytes: %q %v", content, err)
		}
		digests[suffix] = p.Digest
		p.Close()
	}
	if digests[".json"] == digests[".yaml"] {
		t.Fatal("parser selection not bound to replay digest")
	}
	if digests[".yaml"] != digests[".yml"] || digests[".json"] != digests[""] {
		t.Fatal("equivalent parsers changed the input digest")
	}
}
