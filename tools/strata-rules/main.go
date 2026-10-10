// Command strata-rules works on the rule repository.
//
//	strata-rules lint [--repo <root>] [dir]   schema, ids, RE2, licenses (default dir: rules)
//	strata-rules test [--repo <root>] [dir]   match / no_match requests through libstrata
//	strata-rules report [--repo <root>] [--rules dir] [--corpus dir] [--json file] [--baseline file]
//	                                          FP and recall on the corpus, as Markdown
//	strata-rules ftw [--repo <root>] [--group 942] [--min 90]  CRS go-ftw tests of rules/crs, as Markdown
//	strata-rules corpus fetch [--repo <root>]          corpus/attack from corpus/sources.yaml
//	strata-rules corpus benign [--repo <root>] [--n N] [--seed S]   corpus/benign/synthetic.jsonl
//
// test needs strata-compile and strata-eval: $STRATA_COMPILE / $STRATA_EVAL,
// <repo>/target/release, or PATH.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/strata/strata/tools/strata-rules/internal/corpus"
	"github.com/strata/strata/tools/strata-rules/internal/ftw"
	"github.com/strata/strata/tools/strata-rules/internal/lint"
	"github.com/strata/strata/tools/strata-rules/internal/report"
	"github.com/strata/strata/tools/strata-rules/internal/ruletest"
	"github.com/strata/strata/tools/strata-rules/internal/runner"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "lint":
		lintCmd()
	case "test":
		testCmd()
	case "report":
		reportCmd()
	case "corpus":
		corpusCmd()
	case "ftw":
		ftwCmd()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: strata-rules lint|test|report|ftw|corpus ... (see the package comment)")
	os.Exit(2)
}

func repoAndDir(name string) (string, string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	repo := fs.String("repo", ".", "repository root (where docs/spec and rules/schema are)")
	_ = fs.Parse(os.Args[2:])
	dir := filepath.Join(*repo, "rules")
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	return *repo, dir
}

func testCmd() {
	repo, dir := repoAndDir("test")
	tools, err := runner.Find(repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-rules:", err)
		os.Exit(2)
	}
	files, err := ruletest.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-rules:", err)
		os.Exit(2)
	}
	results, err := ruletest.Run(tools, files)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-rules:", err)
		os.Exit(2)
	}
	count := map[ruletest.Status]int{}
	for _, r := range results {
		count[r.Status]++
		switch r.Status {
		case ruletest.Pass:
			fmt.Printf("PASS %d (%d requests)\n", r.Rule, r.Cases)
		case ruletest.Skip:
			fmt.Printf("SKIP %d: %s\n", r.Rule, r.Reason)
		case ruletest.Fail:
			fmt.Printf("FAIL %d %s\n", r.Rule, r.File)
			for _, f := range r.Failures {
				fmt.Printf("     %s\n", f)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "strata-rules test: %d rules: %d pass, %d fail, %d skipped (engine lacks a feature)\n",
		len(results), count[ruletest.Pass], count[ruletest.Fail], count[ruletest.Skip])
	if count[ruletest.Fail] > 0 {
		os.Exit(1)
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "strata-rules:", err)
	os.Exit(2)
}

func reportCmd() {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository root")
	rules := fs.String("rules", "", "rules directory (default <repo>/rules)")
	corpusDir := fs.String("corpus", "", "corpus directory (default <repo>/corpus)")
	jsonOut := fs.String("json", "", "also write the report as JSON (a baseline for later runs)")
	baseline := fs.String("baseline", "", "JSON report to compare with")
	_ = fs.Parse(os.Args[2:])
	if *rules == "" {
		*rules = filepath.Join(*repo, "rules")
	}
	if *corpusDir == "" {
		*corpusDir = filepath.Join(*repo, "corpus")
	}
	tools, err := runner.Find(*repo)
	if err != nil {
		die(err)
	}
	c, err := corpus.Load(*corpusDir)
	if err != nil {
		die(err)
	}
	rep, err := report.Run(tools, *rules, c)
	if err != nil {
		die(err)
	}
	var base *report.Report
	if *baseline != "" {
		if base, err = report.LoadReport(*baseline); err != nil {
			die(err)
		}
	}
	rep.Markdown(os.Stdout, base)
	if *jsonOut != "" {
		if err := rep.Save(*jsonOut); err != nil {
			die(err)
		}
	}
}

func corpusCmd() {
	if len(os.Args) < 3 {
		usage()
	}
	fs := flag.NewFlagSet("corpus", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository root")
	n := fs.Int("n", 2000, "benign: number of requests")
	seed := fs.Uint64("seed", 1, "benign: random seed")
	_ = fs.Parse(os.Args[3:])
	switch os.Args[2] {
	case "fetch":
		counts, err := corpus.Fetch(filepath.Join(*repo, "corpus", "sources.yaml"), filepath.Join(*repo, "corpus", "attack"))
		if err != nil {
			die(err)
		}
		for t, c := range counts {
			fmt.Printf("%s: %d payloads\n", t, c)
		}
	case "benign":
		dir := filepath.Join(*repo, "corpus", "benign")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			die(err)
		}
		f, err := os.Create(filepath.Join(dir, "synthetic.jsonl"))
		if err != nil {
			die(err)
		}
		if err := corpus.Benign(*seed, *n, f); err != nil {
			die(err)
		}
		if err := f.Close(); err != nil {
			die(err)
		}
	default:
		usage()
	}
}

func lintCmd() {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository root (where docs/spec and rules/schema are)")
	_ = fs.Parse(os.Args[2:])
	dir := filepath.Join(*repo, "rules")
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	l, err := lint.New(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-rules:", err)
		os.Exit(2)
	}
	findings, files, err := l.Lint(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "strata-rules:", err)
		os.Exit(2)
	}
	for _, f := range findings {
		fmt.Println(f)
	}
	fmt.Fprintf(os.Stderr, "strata-rules lint: %d files, %d problems\n", files, len(findings))
	if len(findings) > 0 {
		os.Exit(1)
	}
}

// ftwCmd runs the CRS go-ftw tests; with --min, it fails when a group of
// --group is under that pass rate.
func ftwCmd() {
	fs := flag.NewFlagSet("ftw", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository root")
	groups := fs.String("group", "", "comma-separated CRS groups to run (930,942); default all")
	minRate := fs.Float64("min", 0, "fail when a group passes under this percentage")
	maxPL := fs.Int("pl", 1, "paranoia levels imported")
	_ = fs.Parse(os.Args[2:])
	tools, err := runner.Find(*repo)
	if err != nil {
		die(err)
	}
	tests, err := ftw.Load(filepath.Join(*repo, "corpus", "crs-ftw"))
	if err != nil {
		die(err)
	}
	if *groups != "" {
		want := strings.Split(*groups, ",")
		kept := tests[:0]
		for _, t := range tests {
			for _, g := range want {
				if strings.HasPrefix(t.Group, "REQUEST-"+strings.TrimSpace(g)+"-") {
					kept = append(kept, t)
					break
				}
			}
		}
		tests = kept
	}
	pl, err := ftw.ParanoiaLevels(filepath.Join(*repo, "docs", "crs-inventory.csv"))
	if err != nil {
		die(err)
	}
	results, err := ftw.Run(tools, filepath.Join(*repo, "rules", "crs"), tests, pl, *maxPL)
	if err != nil {
		die(err)
	}
	ftw.Markdown(os.Stdout, results, *maxPL)
	low := false
	for _, g := range ftw.Groups(results) {
		if *minRate > 0 && g.Tests > 0 && g.Rate() < *minRate {
			fmt.Fprintf(os.Stderr, "strata-rules ftw: %s passes %.1f%%, under %.0f%%\n", g.Name, g.Rate(), *minRate)
			low = true
		}
	}
	if low {
		os.Exit(1)
	}
}
