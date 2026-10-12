// Command strata-import-signatures imports signature sources into rule IR
// (W07-S-01), the way strata-import-crs imports CRS:
//
//	strata-import-signatures sigma --src <sigma checkout> --version <v> [--out rules/sigma] [--report docs/sigma-import-report.md]
//	strata-import-signatures et    --src <ET Open rules dir> --version <v> [--out rules/et-open] [--report docs/et-open-import-report.md]
//	strata-import-signatures bots  --src <crawler-user-agents.json> --version <v> [--corpus corpus/benign] [--out rules/bots] [--report docs/bots-import-report.md]
//
// Sources and versions are pinned in sources.lock; fetch.sh downloads and
// checks them. Each import writes <out>/*.yaml (IR rulesets), <out>/ids.txt
// (the rule id of each upstream rule, kept across imports: ids are never
// reused) and <out>/tests/*.jsonl (match / no_match requests for
// `strata-rules ftw --tests <out>/tests --rules <out>`).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/strata/strata/tools/strata-import-signatures/internal/bots"
	"github.com/strata/strata/tools/strata-import-signatures/internal/et"
	"github.com/strata/strata/tools/strata-import-signatures/internal/irout"
	"github.com/strata/strata/tools/strata-import-signatures/internal/sigma"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	src := fs.String("src", "", "source (see fetch.sh)")
	version := fs.String("version", "", "upstream version recorded in each rule")
	out := fs.String("out", "", "output directory")
	report := fs.String("report", "", "import report (Markdown)")
	corpusDir := fs.String("corpus", "corpus/benign", "bots: benign corpus whose user agents no pattern may match")
	_ = fs.Parse(os.Args[2:])
	if *src == "" || *version == "" {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "sigma":
		err = runSigma(*src, *version, def(*out, "rules/sigma"), def(*report, "docs/sigma-import-report.md"))
	case "et":
		err = runET(*src, *version, def(*out, "rules/et-open"), def(*report, "docs/et-open-import-report.md"))
	case "bots":
		err = runBots(*src, *version, *corpusDir, def(*out, "rules/bots"), def(*report, "docs/bots-import-report.md"))
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-import-signatures:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: strata-import-signatures sigma|et|bots --src <source> --version <v> [--out dir] [--report file]")
	os.Exit(2)
}

func def(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

const idsHeader = "# upstream id -> rule id, written by tools/strata-import-signatures: ids are never reused.\n"

// excluded reads exclude.txt (next to this command's sources, or given
// with STRATA_IMPORT_EXCLUDE): source -> upstream id -> reason.
func excluded(source string) (map[string]string, error) {
	path := os.Getenv("STRATA_IMPORT_EXCLUDE")
	if path == "" {
		path = "tools/strata-import-signatures/exclude.txt"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("exclusions: %w", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.SplitN(line, " ", 3)
		if len(f) != 3 {
			return nil, fmt.Errorf("exclusions: bad line %q", line)
		}
		if f[0] == source {
			out[f[1]] = f[2]
		}
	}
	return out, nil
}

// drop moves the excluded rules (and their tests) to skipped.
func drop(source string, rules []irout.Rule, tests []irout.Test, skipped []irout.Skipped) ([]irout.Rule, []irout.Test, []irout.Skipped, error) {
	ex, err := excluded(source)
	if err != nil {
		return nil, nil, nil, err
	}
	gone := map[int]bool{}
	var kept []irout.Rule
	for _, r := range rules {
		up, _ := r["metadata"].(map[string]any)["upstream_id"].(string)
		if why, ok := ex[up]; ok {
			gone[r["id"].(int)] = true
			skipped = append(skipped, irout.Skipped{Upstream: up, Name: r["name"].(string), Reason: why})
			continue
		}
		kept = append(kept, r)
	}
	var kt []irout.Test
	for _, t := range tests {
		if !gone[t.Rule] {
			kt = append(kt, t)
		}
	}
	return kept, kt, skipped, nil
}

func prepare(out string) error {
	if err := os.MkdirAll(filepath.Join(out, "tests"), 0o755); err != nil {
		return err
	}
	// generated files only: ids.txt is kept
	for _, pat := range []string{"*.yaml", "tests/*.jsonl"} {
		old, _ := filepath.Glob(filepath.Join(out, pat))
		for _, f := range old {
			if err := os.Remove(f); err != nil {
				return err
			}
		}
	}
	return nil
}

func write(out, base, header, ruleset, version string, rules []irout.Rule, tests []irout.Test) error {
	if len(rules) == 0 {
		return nil
	}
	b, err := irout.Marshal(header, ruleset, version, rules)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, base+".yaml"), b, 0o644); err != nil {
		return err
	}
	return irout.WriteTests(filepath.Join(out, "tests", base+".jsonl"), tests)
}

func runSigma(src, version, out, report string) error {
	ids, err := irout.LoadIDs(filepath.Join(out, "ids.txt"), sigma.MinID, sigma.MaxID)
	if err != nil {
		return err
	}
	res, err := sigma.Import(sigma.Source{Dir: src, Version: version}, ids)
	if err != nil {
		return err
	}
	if res.Rules, res.Tests, res.Skipped, err = drop("sigma", res.Rules, res.Tests, res.Skipped); err != nil {
		return err
	}
	if err := prepare(out); err != nil {
		return err
	}
	hdr := fmt.Sprintf("# SigmaHQ rules/web %s (DRL-1.1): generated by tools/strata-import-signatures, do not edit.\n", version)
	if err := write(out, "web", hdr, "sigma-web", version, res.Rules, res.Tests); err != nil {
		return err
	}
	if err := ids.Save(idsHeader); err != nil {
		return err
	}
	return writeReport(report, func(w io.Writer) {
		fmt.Fprintf(w, "# Sigma import report\n\nGenerated by `strata-import-signatures sigma` (W07-S-01) from SigmaHQ `rules/web` %s: rules the IR can express are in `rules/sigma/`, the others are listed with the reason.\n\n", version)
		fmt.Fprintf(w, "| Read | Imported | Left out |\n| ---: | ---: | ---: |\n| %d | %d | %d |\n\n", res.Read, len(res.Rules), len(res.Skipped))
		reasons(w, res.Skipped)
		table(w, "Left out", res.Skipped)
		table(w, "Imported with a change", res.Notes)
		generated(w, res.Tests)
	})
}

func runET(src, version, out, report string) error {
	ids, err := irout.LoadIDs(filepath.Join(out, "ids.txt"), et.MinID, et.MaxID)
	if err != nil {
		return err
	}
	results, err := et.Import(src, version, ids)
	if err != nil {
		return err
	}
	for _, r := range results {
		if r.Rules, r.Tests, r.Skipped, err = drop("et", r.Rules, r.Tests, r.Skipped); err != nil {
			return err
		}
	}
	if err := prepare(out); err != nil {
		return err
	}
	for _, r := range results {
		base := strings.TrimSuffix(strings.TrimPrefix(r.File, "emerging-"), ".rules")
		hdr := fmt.Sprintf("# ET Open %s, %s (BSD-3-Clause, SIDs %d-%d): generated by tools/strata-import-signatures, do not edit.\n", version, r.File, et.MinSID, et.MaxSID)
		if err := write(out, base, hdr, "et-open-"+base, version, r.Rules, r.Tests); err != nil {
			return err
		}
	}
	if err := ids.Save(idsHeader); err != nil {
		return err
	}
	return writeReport(report, func(w io.Writer) {
		fmt.Fprintf(w, "# ET Open import report\n\nGenerated by `strata-import-signatures et` (W07-S-01) from ET Open %s (Suricata 7.0.3 rules): only HTTP rules on requests with a SID in %d-%d, the BSD-licensed part; other SIDs are never imported. Rules the IR can express are in `rules/et-open/`, the others are listed with the reason.\n\n", version, et.MinSID, et.MaxSID)
		fmt.Fprintf(w, "| File | HTTP rules in the SID range | Imported | Loose (positional modifiers dropped) | Left out |\n| --- | ---: | ---: | ---: | ---: |\n")
		var all []irout.Skipped
		var tests []irout.Test
		read, imp, loose := 0, 0, 0
		for _, r := range results {
			fmt.Fprintf(w, "| %s | %d | %d | %d | %d |\n", r.File, r.Read, len(r.Rules), r.Loose, len(r.Skipped))
			read, imp, loose = read+r.Read, imp+len(r.Rules), loose+r.Loose
			all = append(all, r.Skipped...)
			tests = append(tests, r.Tests...)
		}
		fmt.Fprintf(w, "| **all** | %d | %d | %d | %d |\n\n", read, imp, loose, len(all))
		fmt.Fprintf(w, "Loose rules match a superset of what Suricata matches: Suricata's `distance`, `within`, `offset` and `depth` between contents have no IR equivalent, so every content is looked for anywhere in its buffer. Their score (at most 80) does not block alone.\n\n")
		reasons(w, all)
		generated(w, tests)
		table(w, "Left out", all)
	})
}

func runBots(src, version, corpusDir, out, report string) error {
	ids, err := irout.LoadIDs(filepath.Join(out, "ids.txt"), bots.MinID, bots.MaxID)
	if err != nil {
		return err
	}
	benign, err := benignUAs(corpusDir)
	if err != nil {
		return err
	}
	res, err := bots.Import(src, version, ids, benign)
	if err != nil {
		return err
	}
	if err := prepare(out); err != nil {
		return err
	}
	hdr := fmt.Sprintf("# crawler-user-agents %s (MIT): generated by tools/strata-import-signatures, do not edit.\n", version)
	if err := write(out, "crawler-user-agents", hdr, "crawler-user-agents", version, res.Rules, res.Tests); err != nil {
		return err
	}
	if err := ids.Save(idsHeader); err != nil {
		return err
	}
	return writeReport(report, func(w io.Writer) {
		fmt.Fprintf(w, "# crawler-user-agents import report\n\nGenerated by `strata-import-signatures bots` (W07-S-01) from monperrus/crawler-user-agents %s: one rule per pattern, on User-Agent, score 0 and label `bot` (identification, not blocking), tested with the user agents upstream lists for it. Patterns that are not RE2 or match a benign corpus user agent are left out.\n\n", version)
		fmt.Fprintf(w, "| Read | Imported | Left out |\n| ---: | ---: | ---: |\n| %d | %d | %d |\n\n", res.Read, len(res.Rules), len(res.Skipped))
		reasons(w, res.Skipped)
		table(w, "Left out", res.Skipped)
	})
}

// benignUAs: the User-Agent of every request of the benign corpus.
func benignUAs(dir string) ([]string, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		for sc.Scan() {
			var r struct {
				Headers map[string]any `json:"headers"`
			}
			if json.Unmarshal(sc.Bytes(), &r) != nil {
				continue
			}
			for k, v := range r.Headers {
				if s, ok := v.(string); ok && strings.EqualFold(k, "User-Agent") && !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
		fh.Close()
	}
	sort.Strings(out)
	return out, nil
}

func writeReport(path string, f func(io.Writer)) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}
	f(fh)
	return fh.Close()
}

func reasons(w io.Writer, sk []irout.Skipped) {
	if len(sk) == 0 {
		return
	}
	count := map[string]int{}
	for _, s := range sk {
		count[reasonClass(s.Reason)]++
	}
	keys := make([]string, 0, len(count))
	for k := range count {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if count[keys[i]] != count[keys[j]] {
			return count[keys[i]] > count[keys[j]]
		}
		return keys[i] < keys[j]
	})
	fmt.Fprintf(w, "## Why rules are left out\n\n| Reason | Rules |\n| --- | ---: |\n")
	for _, k := range keys {
		fmt.Fprintf(w, "| %s | %d |\n", k, count[k])
	}
	fmt.Fprintln(w)
}

// reasonClass groups reasons without their details (values, names).
func reasonClass(r string) string {
	for _, sep := range []string{": ", "\""} {
		if i := strings.Index(r, sep); i > 0 {
			r = r[:i]
		}
	}
	return strings.TrimSpace(r)
}

func table(w io.Writer, title string, rows []irout.Skipped) {
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(w, "## %s\n\n| Upstream | Name | Reason |\n| --- | --- | --- |\n", title)
	for _, s := range rows {
		fmt.Fprintf(w, "| %s | %s | %s |\n", cell(s.Upstream), cell(s.Name), cell(s.Reason))
	}
	fmt.Fprintln(w)
}

func generated(w io.Writer, tests []irout.Test) {
	gen, rules := 0, map[int]bool{}
	for _, t := range tests {
		if t.Expect == "match" {
			rules[t.Rule] = true
			if t.Generated {
				gen++
			}
		}
	}
	fmt.Fprintf(w, "Test requests: %d rules have a `match` request; %d of those requests are generated from the rule's literals (marked `generated`), since upstream has no test data. Every rule has a benign `no_match` request.\n\n", len(rules), gen)
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}
