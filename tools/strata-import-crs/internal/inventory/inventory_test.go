package inventory

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// crsDir is the release pinned in crs.lock, fetched by fetch-crs.sh (make
// test-go does it), or STRATA_CRS_DIR.
func crsDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("STRATA_CRS_DIR"); d != "" {
		return d
	}
	lock, err := os.ReadFile("../../crs.lock")
	if err != nil {
		t.Fatal(err)
	}
	v := regexp.MustCompile(`(?m)^version=(.+)$`).FindSubmatch(lock)
	d := filepath.Join("../../../../build/crs", "coreruleset-"+string(v[1]))
	if _, err := os.Stat(filepath.Join(d, ".verified")); err != nil {
		t.Fatalf("CRS %s is not fetched: run tools/strata-import-crs/fetch-crs.sh", v[1])
	}
	return d
}

// W03-S-02: every .conf file of CRS 4.25 LTS parses, and no rule is lost.
func TestCRSParsesCompletely(t *testing.T) {
	dir := crsDir(t)
	inv, err := Read(dir)
	if err != nil {
		if pe, ok := err.(*ParseError); ok {
			t.Fatalf("%v: %v", err, pe.Errors)
		}
		t.Fatal(err)
	}
	if !strings.HasPrefix(inv.Version, "4.25.") {
		t.Fatalf("CRS version %q, want 4.25 LTS", inv.Version)
	}
	confs, _ := filepath.Glob(filepath.Join(dir, "rules", "*.conf"))
	if len(inv.Files) != len(confs)+1 {
		t.Fatalf("%d files read, %d .conf + crs-setup", len(inv.Files), len(confs))
	}

	// Count ids independently of the parser: id:<n> in rule actions, on
	// lines that are not comments.
	idRe := regexp.MustCompile(`"id:(\d+)|^\s*"?id:(\d+)`)
	want := 0
	for _, p := range append(confs, filepath.Join(dir, "crs-setup.conf.example")) {
		b, _ := os.ReadFile(p)
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			want += len(idRe.FindAllString(line, -1))
		}
	}
	if len(inv.Rules) != want {
		t.Fatalf("parsed %d rules, the files have %d ids", len(inv.Rules), want)
	}
	for _, r := range inv.Rules {
		if r.Directive == "SecRule" && len(r.Operators()) == 0 {
			t.Errorf("rule %d has no operator", r.ID)
		}
	}
}

// docs/crs-inventory.csv is what the importer writes for the pinned CRS.
func TestCommittedInventoryIsCurrent(t *testing.T) {
	inv, err := Read(crsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := inv.WriteCSV(&buf); err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile("../../../../docs/crs-inventory.csv")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), committed) {
		t.Fatal("docs/crs-inventory.csv is stale: run make crs-inventory")
	}
}

func TestReadFailsOnSyntaxErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "rules", "A.conf"), []byte(`SecRule ARGS "@rx a" "id:1,phase:2,deny`+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "crs-setup.conf.example"), []byte("# empty\n"), 0o644)
	if _, err := Read(dir); err == nil {
		t.Fatal("a file with a syntax error was accepted")
	}
}
