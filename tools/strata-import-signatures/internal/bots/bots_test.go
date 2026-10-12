package bots

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strata/strata/tools/strata-import-signatures/internal/irout"
)

func TestImport(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "crawler-user-agents.json")
	_ = os.WriteFile(src, []byte(`[
 {"pattern": "Googlebot\\/", "instances": ["Googlebot/2.1 (+http://www.google.com/bot.html)"]},
 {"pattern": "(?<=x)bot", "instances": ["xbot"]},
 {"pattern": "Mozilla", "instances": ["Mozilla/5.0"]},
 {"pattern": "curl", "instances": ["curl/8.5.0"]},
 {"pattern": "NoSample", "instances": []}
]`), 0o644)
	ids, _ := irout.LoadIDs(filepath.Join(dir, "ids.txt"), MinID, MaxID)
	res, err := Import(src, "test", ids, []string{"curl/8.5.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) != 1 || res.Rules[0]["score"] != 0 || res.Rules[0]["labels"].([]string)[0] != "bot" {
		t.Fatalf("%+v", res.Rules)
	}
	reasons := map[string]string{}
	for _, s := range res.Skipped {
		reasons[s.Upstream] = s.Reason
	}
	for p, want := range map[string]string{"(?<=x)bot": "not RE2", "Mozilla": "browser", "curl": "benign corpus", "NoSample": "no upstream"} {
		if !strings.Contains(reasons[p], want) {
			t.Errorf("%s: %q, want %q", p, reasons[p], want)
		}
	}
	if len(res.Tests) != 2 || res.Tests[1].Generated {
		t.Fatalf("tests %+v", res.Tests)
	}
}
