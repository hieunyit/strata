// Command strata-rules works on the rule repository.
//
//	strata-rules lint [--repo <root>] [dir]   schema, ids, RE2, licenses (default dir: rules)
//	strata-rules test [--repo <root>] [dir]   match / no_match requests through libstrata
//	strata-rules report [--repo <root>] [--rules dir] [--corpus dir] [--json file] [--baseline file] [--max-fp N]
//	                    [--max-fp-block-pct P] [--min-recall-block P]
//	                                          FP and recall on the corpus, as Markdown
//	strata-rules ftw [--repo <root>] [--group 942] [--min 90] [--min-total 95]  CRS go-ftw tests of rules/crs, as Markdown
//	strata-rules release --version <label> --key <seed> --out <dir> [--bundle-version N] [--baseline m.json] [--policies p.yaml]
//	                                          signed signature package: bundle + manifest (signed, sha256 of every file) + changelog + NOTICE
//	strata-rules verify --pub <key> <dir>     check a package: manifest signature and every file's sha256
//	strata-rules fp-report [--clickhouse <url>] [--database <db>] [--user <u>] [--password <p>] [--since <duration>] [--policy <p>] [--exclude-ips <file>]
//	                                          shadow FP candidates from ClickHouse, as Markdown
//	strata-rules corpus fetch [--repo <root>]          corpus/attack from corpus/sources.yaml
//	strata-rules corpus benign [--repo <root>] [--n N] [--seed S]   corpus/benign/synthetic.jsonl
//
// test needs strata-compile and strata-eval: $STRATA_COMPILE / $STRATA_EVAL,
// <repo>/target/release, or PATH.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/strata/strata/tools/strata-rules/internal/corpus"
	"github.com/strata/strata/tools/strata-rules/internal/fpreport"
	"github.com/strata/strata/tools/strata-rules/internal/ftw"
	"github.com/strata/strata/tools/strata-rules/internal/lint"
	"github.com/strata/strata/tools/strata-rules/internal/release"
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
	case "release":
		releaseCmd()
	case "verify":
		verifyCmd()
	case "fp-report":
		fpReportCmd()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: strata-rules lint|test|report|ftw|release|verify|corpus|fp-report ... (see the package comment)")
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
	maxFP := fs.Int("max-fp", -1, "fail when more benign requests than this match some rule (-1: no limit)")
	maxFPBlock := fs.Float64("max-fp-block-pct", -1, "fail unless benign requests blocked stay under this percentage (Gate A: 1; -1: not checked)")
	minRecall := fs.Float64("min-recall-block", -1, "fail unless SQLi, XSS, CMDi and LFI payloads are each blocked at least this percentage (Gate A: 70; -1: not checked)")
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
	if *maxFP >= 0 && rep.BenignHit > *maxFP {
		fmt.Fprintf(os.Stderr, "strata-rules report: %d benign requests matched, at most %d allowed\n", rep.BenignHit, *maxFP)
		os.Exit(1)
	}
	if miss := rep.GateFailures(*maxFPBlock, *minRecall, report.GateAttackTypes); len(miss) > 0 {
		for _, m := range miss {
			fmt.Fprintln(os.Stderr, "strata-rules report:", m)
		}
		os.Exit(1)
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

// releaseCmd builds a signed signature package (bundle + manifest +
// changelog + NOTICE) from the rule repository.
func releaseCmd() {
	fs := flag.NewFlagSet("release", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository root")
	rules := fs.String("rules", "", "rules directory (default <repo>/rules)")
	version := fs.String("version", "", "package version label, e.g. 2026.w42")
	bundleVersion := fs.Uint64("bundle-version", 1, "numeric bundle version (monotonic)")
	key := fs.String("key", "", "ed25519 seed file to sign the bundle (strata-compile --key)")
	out := fs.String("out", "", "output directory for the package")
	baseline := fs.String("baseline", "", "previous manifest.json for the changelog diff")
	policies := fs.String("policies", "", "policies file compiled into the bundle (default: none)")
	_ = fs.Parse(os.Args[2:])
	if *out == "" {
		die(fmt.Errorf("--out is required"))
	}
	m, err := release.Build(release.Options{
		Repo:          *repo,
		RulesDir:      *rules,
		Version:       *version,
		BundleVersion: *bundleVersion,
		KeyFile:       *key,
		Out:           *out,
		Baseline:      *baseline,
		Policies:      *policies,
	})
	if err != nil {
		die(err)
	}
	fmt.Fprintf(os.Stderr, "strata-rules release: %s (%d rules) -> %s\n", m.Version, m.Rules, *out)
}

// verifyCmd checks a release package against a trusted public key (not the
// .pub inside the package, which an attacker could replace).
func verifyCmd() {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubFile := fs.String("pub", "", "trusted ed25519 public key (32 bytes)")
	_ = fs.Parse(os.Args[2:])
	if *pubFile == "" || fs.NArg() != 1 {
		die(fmt.Errorf("usage: strata-rules verify --pub KEY PACKAGE_DIR"))
	}
	pub, err := os.ReadFile(*pubFile)
	if err != nil {
		die(err)
	}
	m, err := release.Verify(fs.Arg(0), pub)
	if err != nil {
		die(err)
	}
	fmt.Fprintf(os.Stderr, "strata-rules verify: %s (%d rules) OK\n", m.Version, m.Rules)
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
// --group is under that pass rate, with --min-total when all the tests run
// together are.
func ftwCmd() {
	fs := flag.NewFlagSet("ftw", flag.ExitOnError)
	repo := fs.String("repo", ".", "repository root")
	groups := fs.String("group", "", "comma-separated CRS groups to run (930,942); default all")
	minRate := fs.Float64("min", 0, "fail when a group passes under this percentage")
	minTotal := fs.Float64("min-total", 0, "fail when all the tests together pass under this percentage")
	maxPL := fs.Int("pl", 1, "paranoia levels imported")
	testsDir := fs.String("tests", "", "test requests (default <repo>/corpus/crs-ftw)")
	rulesDir := fs.String("rules", "", "rules the tests are for (default <repo>/rules/crs)")
	inventory := fs.String("inventory", "", "rule paranoia levels (default <repo>/docs/crs-inventory.csv; none: every rule is level 1)")
	_ = fs.Parse(os.Args[2:])
	crs := *testsDir == ""
	if crs {
		*testsDir = filepath.Join(*repo, "corpus", "crs-ftw")
	}
	if *rulesDir == "" {
		*rulesDir = filepath.Join(*repo, "rules", "crs")
	}
	if *inventory == "" && crs {
		*inventory = filepath.Join(*repo, "docs", "crs-inventory.csv")
	}
	tools, err := runner.Find(*repo)
	if err != nil {
		die(err)
	}
	tests, err := ftw.Load(*testsDir)
	if err != nil {
		die(err)
	}
	if *groups != "" {
		want := strings.Split(*groups, ",")
		kept := tests[:0]
		for _, t := range tests {
			for _, g := range want {
				if g = strings.TrimSpace(g); t.Group == g || strings.HasPrefix(t.Group, "REQUEST-"+g+"-") {
					kept = append(kept, t)
					break
				}
			}
		}
		tests = kept
	}
	pl := map[int]int{}
	if *inventory != "" {
		if pl, err = ftw.ParanoiaLevels(*inventory); err != nil {
			die(err)
		}
	}
	results, err := ftw.Run(tools, *rulesDir, tests, pl, *maxPL)
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
	if t := ftw.Total(results); *minTotal > 0 && t.Rate() < *minTotal {
		fmt.Fprintf(os.Stderr, "strata-rules ftw: all groups pass %.1f%%, under %.0f%%\n", t.Rate(), *minTotal)
		low = true
	}
	if low {
		os.Exit(1)
	}
}

type policyList []string

func (p *policyList) String() string {
	return strings.Join(*p, ",")
}

func (p *policyList) Set(val string) error {
	parts := strings.Split(val, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			*p = append(*p, part)
		}
	}
	return nil
}

func fpReportCmd() {
	fs := flag.NewFlagSet("fp-report", flag.ExitOnError)
	defaultCH := os.Getenv("STRATA_CLICKHOUSE_URL")
	if defaultCH == "" {
		defaultCH = "http://127.0.0.1:18123"
	}
	clickhouse := fs.String("clickhouse", defaultCH, "ClickHouse HTTP URL")
	database := fs.String("database", "default", "ClickHouse database")
	defaultUser := os.Getenv("STRATA_CLICKHOUSE_USER")
	if defaultUser == "" {
		defaultUser = "default"
	}
	user := fs.String("user", defaultUser, "ClickHouse user (env STRATA_CLICKHOUSE_USER)")
	password := fs.String("password", os.Getenv("STRATA_CLICKHOUSE_PASSWORD"), "ClickHouse password")
	since := fs.Duration("since", 24*time.Hour, "time window to inspect (e.g. 24h)")
	timeout := fs.Duration("timeout", 60*time.Second, "HTTP request timeout")
	var policies policyList
	fs.Var(&policies, "policy", "policy ID to filter (repeatable or comma-separated)")
	excludeIPs := fs.String("exclude-ips", "", "path to file containing IPs or CIDRs to exclude")

	_ = fs.Parse(os.Args[2:])

	var excludeCIDRs []string
	if *excludeIPs != "" {
		var err error
		excludeCIDRs, err = fpreport.LoadCIDRs(*excludeIPs)
		if err != nil {
			die(err)
		}
	}

	opts := fpreport.Options{
		ClickHouseURL: *clickhouse,
		Database:      *database,
		User:          *user,
		Password:      *password,
		Since:         *since,
		Policies:      policies,
		ExcludeCIDRs:  excludeCIDRs,
		Timeout:       *timeout,
	}

	rows, err := fpreport.Query(context.Background(), opts)
	if err != nil {
		die(err)
	}
	fpreport.Markdown(os.Stdout, rows, opts)
}
