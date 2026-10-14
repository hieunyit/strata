// Command coraza-diff runs the same requests through Strata (libstrata via
// strata-eval, a bundle of the core pack) and through Coraza with the OWASP
// CRS release Strata imports, and lists where the two disagree, with a
// ticket draft per difference (W12-R-01; differences caused by the CRS
// importer are fixed in W12-S-01). PO decision 14/10/2026: a separate Go
// tool, the Coraza dependency stays here.
//
//	coraza-diff --crs build/crs/coreruleset-4.25.2 --bundle core.sbn --pubkey core.pub \
//	    [--policy name] [--corpus corpus] [--repo .] --md report.md [--json diff.json]
//
// Two comparisons:
//   - the verdict (block or not) of the benign corpus as it is and of every
//     attack payload in a query value of GET /v1/search (as strata-replay
//     gen builds replay samples);
//   - per rule, the go-ftw tests of the CRS release (corpus/crs-ftw): did
//     the rule the test is for match in each engine; the test's expectation
//     says which one follows CRS.
//
// Coraza runs CRS at paranoia level 1 with the default anomaly thresholds,
// request side only, with the setup Strata's import uses (allowed_methods
// as in strataDefaults of tools/strata-import-crs) and the body processors
// of coraza.conf-recommended. Differences the import explains (Strata's
// tuning in docs/crs-import-report.md, failures already in
// docs/crs-ftw-report.md, rules not imported) are listed without a ticket.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Request is a strata-eval request.
type Request struct {
	ID         string            `json:"id"`
	Method     string            `json:"method"`
	URI        string            `json:"uri"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	RemoteAddr string            `json:"remote_addr"`
	Kind       string            `json:"-"` // benign, the attack type or crs-ftw
	Rule       int               `json:"-"` // crs-ftw: the rule the test is for
	Expect     string            `json:"-"` // crs-ftw: match or no_match
}

// RuleDiff: a go-ftw test whose rule matched in one engine only.
type RuleDiff struct {
	Test   string `json:"test"`
	Rule   int    `json:"rule"`
	Expect string `json:"expect"`
	Strata bool   `json:"strata_match"`
	Coraza bool   `json:"coraza_match"`
	SRules []int  `json:"strata_rules"`
	CRules []int  `json:"coraza_rules"`
	SBlock bool   `json:"strata_block"`
	CBlock bool   `json:"coraza_block"`
	Method string `json:"method"`
	URI    string `json:"uri"`
}

// Verdict of one engine.
type Verdict struct {
	Block bool  `json:"block"`
	Rules []int `json:"rules"`
}

// Diff is one request the engines disagree on.
type Diff struct {
	ID     string  `json:"id"`
	Kind   string  `json:"kind"`
	Method string  `json:"method"`
	URI    string  `json:"uri"`
	Strata Verdict `json:"strata"`
	Coraza Verdict `json:"coraza"`
}

func main() {
	crs := flag.String("crs", "build/crs/coreruleset-4.25.2", "CRS release directory (crs-setup.conf.example, rules/)")
	bundle := flag.String("bundle", "", "Strata bundle (the core pack)")
	pubkey := flag.String("pubkey", "", "its public key")
	policy := flag.String("policy", "", "policy to evaluate the requests under (default: the bundle's first)")
	corpus := flag.String("corpus", "corpus", "corpus directory")
	repo := flag.String("repo", ".", "repository root (rules/crs: which CRS rules Strata imports)")
	md := flag.String("md", "", "Markdown report")
	js := flag.String("json", "", "every difference as JSON")
	eval := flag.String("strata-eval", "strata-eval", "strata-eval binary")
	flag.Parse()
	if *bundle == "" || *pubkey == "" {
		log.Fatal("coraza-diff: --bundle and --pubkey are required")
	}
	reqs, err := corpusRequests(*corpus)
	if err != nil {
		log.Fatal(err)
	}
	imported, err := importedRules(filepath.Join(*repo, "rules", "crs"))
	if err != nil {
		log.Fatal(err)
	}
	tuned, err := tunedRules(filepath.Join(*repo, "docs", "crs-import-report.md"))
	if err != nil {
		log.Fatal(err)
	}
	known, err := knownFailures(filepath.Join(*repo, "docs", "crs-ftw-report.md"))
	if err != nil {
		log.Fatal(err)
	}
	strata, err := runStrata(*eval, *bundle, *pubkey, *policy, reqs)
	if err != nil {
		log.Fatal(err)
	}
	waf, err := newCoraza(*crs)
	if err != nil {
		log.Fatal(err)
	}
	var diffs []Diff
	var ruleDiffs []RuleDiff
	agree := map[string]int{}
	ftw := 0
	for _, r := range reqs {
		c := runCoraza(waf, r)
		s := strata[r.ID]
		if r.Kind == "crs-ftw" {
			// per rule: did the rule the test is for match in each engine
			ftw++
			sm, cm := contains(s.Rules, r.Rule), contains(c.Rules, r.Rule)
			if sm != cm {
				ruleDiffs = append(ruleDiffs, RuleDiff{Test: r.ID, Rule: r.Rule, Expect: r.Expect, Strata: sm, Coraza: cm,
					SRules: s.Rules, CRules: c.Rules, SBlock: s.Block, CBlock: c.Block, Method: r.Method, URI: r.URI})
			}
			continue
		}
		if s.Block == c.Block {
			agree[r.Kind]++
			continue
		}
		diffs = append(diffs, Diff{ID: r.ID, Kind: r.Kind, Method: r.Method, URI: r.URI, Strata: s, Coraza: c})
	}
	if *js != "" {
		b, _ := json.MarshalIndent(map[string]any{"requests": diffs, "crs_ftw": ruleDiffs}, "", "  ")
		if err := os.WriteFile(*js, append(b, '\n'), 0o644); err != nil {
			log.Fatal(err)
		}
	}
	rep := report(reqs, agree, diffs, imported, tuned) + ruleReport(ftw, ruleDiffs, imported, tuned, known) +
		fmt.Sprintf("\n---\n\nGenerated by `make coraza-diff` (tools/coraza-diff): Coraza %s, CRS from `%s`, Strata bundle `%s`.\n",
			corazaVersion(), filepath.Base(*crs), filepath.Base(*bundle))
	if *md != "" {
		if err := os.WriteFile(*md, []byte(rep), 0o644); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Print(rep)
	}
	fmt.Fprintf(os.Stderr, "coraza-diff: %d requests, %d differences; %d go-ftw tests, %d rule differences\n",
		len(reqs)-ftw, len(diffs), ftw, len(ruleDiffs))
}

// corpusRequests: benign as is, attack payloads in ?q= (strata-replay gen).
func corpusRequests(dir string) ([]Request, error) {
	var out []Request
	read := func(path string, f func(map[string]any) error) error {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		sc := bufio.NewScanner(file)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var v map[string]any
			if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			if err := f(v); err != nil {
				return err
			}
		}
		return sc.Err()
	}
	err := read(filepath.Join(dir, "benign", "synthetic.jsonl"), func(v map[string]any) error {
		r := Request{ID: str(v["id"]), Method: str(v["method"]), URI: str(v["uri"]), Body: str(v["body"]),
			Headers: map[string]string{}, RemoteAddr: "192.0.2.10", Kind: "benign"}
		if r.Method == "" {
			r.Method = "GET"
		}
		if h, ok := v["headers"].(map[string]any); ok {
			for k, x := range h {
				r.Headers[k] = str(x)
			}
		}
		out = append(out, r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, kind := range []string{"sql-injection", "xss", "command-injection", "path-traversal"} {
		n := 0
		err := read(filepath.Join(dir, "attack", kind+".jsonl"), func(v map[string]any) error {
			n++
			out = append(out, Request{ID: fmt.Sprintf("%s-%04d", kind, n), Method: "GET",
				URI:        "/v1/search?q=" + strictEscape(str(v["payload"])),
				Headers:    map[string]string{"Host": "api.example.test", "User-Agent": "Mozilla/5.0"},
				RemoteAddr: "192.0.2.10", Kind: kind})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, "crs-ftw", "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, f := range files {
		err := read(f, func(v map[string]any) error {
			q, _ := v["request"].(map[string]any)
			r := Request{ID: str(v["test"]), Method: str(q["method"]), URI: str(q["uri"]), Body: str(q["body"]),
				Headers: map[string]string{}, RemoteAddr: str(q["remote_addr"]), Kind: "crs-ftw", Expect: str(v["expect"])}
			id, _ := v["rule"].(float64)
			r.Rule = int(id)
			if r.Method == "" {
				r.Method = "GET"
			}
			if r.RemoteAddr == "" {
				r.RemoteAddr = "192.0.2.10"
			}
			if h, ok := q["headers"].(map[string]any); ok {
				for k, x := range h {
					r.Headers[k] = str(x)
				}
			}
			out = append(out, r)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// strictEscape: every byte but [A-Za-z0-9-_.~] as %XX, as strata-replay gen.
func strictEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

var idRe = regexp.MustCompile(`(?m)^\s*-?\s*id:\s*(\d+)\s*$`)

var tuningRe = regexp.MustCompile(`(?m)^\| (\d+) \| (Strata tuning: .*?) \|$`)

// tunedRules: the CRS rules Strata's importer changes on purpose (tune in
// tools/strata-import-crs), from the import report. Coraza blocking what
// such a rule no longer matches is the tuning at work, not a defect.
func tunedRules(path string) (map[int]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[int]string{}
	for _, m := range tuningRe.FindAllSubmatch(b, -1) {
		id, _ := strconv.Atoi(string(m[1]))
		out[id] = string(m[2])
	}
	return out, nil
}

// importedRules: the CRS rule ids of Strata's import.
func importedRules(dir string) (map[int]bool, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	out := map[int]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, m := range idRe.FindAllSubmatch(b, -1) {
			id, _ := strconv.Atoi(string(m[1]))
			out[id] = true
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CRS rule in %s", dir)
	}
	return out, nil
}

func runStrata(bin, bundle, pubkey, policy string, reqs []Request) (map[string]Verdict, error) {
	var in bytes.Buffer
	for _, r := range reqs {
		b, _ := json.Marshal(r)
		in.Write(append(b, '\n'))
	}
	args := []string{"--bundle", bundle, "--pubkey", pubkey}
	if policy != "" {
		args = append(args, "--policy", policy)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin = &in
	var errb bytes.Buffer
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("strata-eval: %v: %s", err, bytes.TrimSpace(errb.Bytes()))
	}
	vs := map[string]Verdict{}
	for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		var v struct {
			ID     string `json:"id"`
			Action string `json:"action"`
			Rules  []int  `json:"rules"`
		}
		if err := json.Unmarshal(line, &v); err != nil {
			return nil, fmt.Errorf("strata-eval output: %w", err)
		}
		vs[v.ID] = Verdict{Block: v.Action == "block", Rules: v.Rules}
	}
	return vs, nil
}

func newCoraza(crs string) (coraza.WAF, error) {
	rules, err := filepath.Glob(filepath.Join(crs, "rules", "REQUEST-*.conf"))
	if err != nil || len(rules) == 0 {
		return nil, fmt.Errorf("no CRS request rules under %s (clone v4.25.2 there)", crs)
	}
	sort.Strings(rules)
	dir := []string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecRequestBodyLimit 13107200",
		"SecRequestBodyNoFilesLimit 131072",
		"SecResponseBodyAccess Off",
		// coraza.conf-recommended: parse XML and JSON bodies (otherwise the
		// whole JSON body becomes one urlencoded argument name)
		`SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"`,
		`SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"`,
		"Include " + filepath.Join(crs, "crs-setup.conf.example"),
		// the defaults Strata's importer changes (strataDefaults in
		// tools/strata-import-crs): the same setup on both sides, so what
		// differs is the engine or the import, not a configuration choice
		`SecAction "id:900200,phase:1,pass,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"`,
	}
	for _, r := range rules {
		dir = append(dir, "Include "+r)
	}
	return coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join(dir, "\n")))
}

// scoring and bookkeeping rules, not detections
func bookkeeping(id int) bool {
	return id < 900000 || id/1000 == 900 || id >= 1000000 || id/1000 == 901 || id/1000 == 905 || id/1000 == 949 || id/1000 == 980 ||
		id%1000 < 20 // the paranoia level skips (9xx011..9xx018)
}

// detection: a CRS rule that scores, as opposed to the flow rules (skips,
// body processor checks such as 920539) that carry no paranoia tag.
func detection(r types.RuleMetadata) bool {
	if r.Severity() > types.RuleSeverityNotice {
		return false
	}
	for _, t := range r.Tags() {
		if strings.HasPrefix(t, "paranoia-level/") {
			return true
		}
	}
	return false
}

func runCoraza(waf coraza.WAF, r Request) Verdict {
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection(r.RemoteAddr, 40000, "127.0.0.1", 80)
	tx.ProcessURI(r.URI, r.Method, "HTTP/1.1")
	for k, v := range r.Headers {
		tx.AddRequestHeader(k, v)
	}
	if r.Headers["Host"] != "" {
		tx.SetServerName(r.Headers["Host"])
	}
	it := tx.ProcessRequestHeaders()
	if it == nil && r.Body != "" {
		_, _, _ = tx.WriteRequestBody([]byte(r.Body))
	}
	if it == nil {
		it, _ = tx.ProcessRequestBody()
	}
	tx.ProcessLogging()
	v := Verdict{Block: it != nil && it.Action == "deny"}
	seen := map[int]bool{}
	for _, m := range tx.MatchedRules() {
		id := m.Rule().ID()
		if !bookkeeping(id) && !seen[id] && detection(m.Rule()) {
			seen[id] = true
			v.Rules = append(v.Rules, id)
		}
	}
	sort.Ints(v.Rules)
	return v
}

// group: requests that differ the same way share a ticket.
type group struct {
	key      string
	strataOn bool // Strata blocks, Coraza does not
	rules    []int
	diffs    []Diff
}

// explainedBy: Coraza blocks only through rules Strata tunes.
func (g *group) explainedBy(tuned map[int]string) bool {
	if g.strataOn || len(g.rules) == 0 {
		return false
	}
	for _, id := range g.rules {
		if tuned[id] == "" {
			return false
		}
	}
	return true
}

func corazaVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, m := range bi.Deps {
			if m.Path == "github.com/corazawaf/coraza/v3" {
				return m.Version
			}
		}
	}
	return "(unknown)"
}

func ids(v []int) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, ", ")
}

func report(reqs []Request, agree map[string]int, diffs []Diff, imported map[int]bool, tuned map[int]string) string {
	total := map[string]int{}
	n := 0
	for _, r := range reqs {
		if r.Kind != "crs-ftw" {
			total[r.Kind]++
			n++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Strata against Coraza + CRS 4.25.2\n\n%d requests (corpus/ benign and attack), %d differences in the verdict (block or not).\n\n", n, len(diffs))
	b.WriteString("| Requests | Total | Agree | Coraza blocks, Strata not | Strata blocks, Coraza not |\n| --- | --- | --- | --- | --- |\n")
	kinds := make([]string, 0, len(total))
	for k := range total {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		var co, st int
		for _, d := range diffs {
			if d.Kind != k {
				continue
			}
			if d.Coraza.Block {
				co++
			} else {
				st++
			}
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d |\n", k, total[k], agree[k], co, st)
	}
	groups := map[string]*group{}
	for _, d := range diffs {
		var g *group
		if d.Coraza.Block {
			// the CRS rules Coraza matched that Strata did not
			var miss []int
			for _, id := range d.Coraza.Rules {
				if !contains(d.Strata.Rules, id) {
					miss = append(miss, id)
				}
			}
			key := "c:" + ids(miss)
			if g = groups[key]; g == nil {
				g = &group{key: key, rules: miss}
				groups[key] = g
			}
		} else {
			key := "s:" + ids(d.Strata.Rules)
			if g = groups[key]; g == nil {
				g = &group{key: key, strataOn: true, rules: d.Strata.Rules}
				groups[key] = g
			}
		}
		g.diffs = append(g.diffs, d)
	}
	list := make([]*group, 0, len(groups))
	for _, g := range groups {
		list = append(list, g)
	}
	sort.Slice(list, func(i, j int) bool {
		if len(list[i].diffs) != len(list[j].diffs) {
			return len(list[i].diffs) > len(list[j].diffs)
		}
		return list[i].key < list[j].key
	})
	var tickets, explained []*group
	for _, g := range list {
		if g.explainedBy(tuned) {
			explained = append(explained, g)
		} else {
			tickets = append(tickets, g)
		}
	}
	if len(explained) > 0 {
		b.WriteString("\n## Explained by Strata's tuning\n\nCoraza blocks and Strata does not because Strata's importer changes these rules on purpose (docs/crs-import-report.md, W09-S-01). No ticket.\n\n| Rules | Requests | Tuning |\n| --- | --- | --- |\n")
		for _, g := range explained {
			why := make([]string, 0, len(g.rules))
			for _, id := range g.rules {
				why = append(why, fmt.Sprintf("%d: %s", id, strings.TrimPrefix(tuned[id], "Strata tuning: ")))
			}
			fmt.Fprintf(&b, "| %s | %d | %s |\n", ids(g.rules), len(g.diffs), strings.ReplaceAll(strings.Join(why, "; "), "|", "\\|"))
		}
	}
	b.WriteString("\n## Ticket drafts\n\nOne per way the engines differ, largest first. A CRS rule Strata does not import is a coverage gap; one it imports but that did not match points at the importer or the engine (W12-S-01).\n")
	if len(tickets) == 0 {
		b.WriteString("\nNone: every difference is explained above.\n")
	}
	for i, g := range tickets {
		fmt.Fprintf(&b, "\n### D-%02d · ", i+1)
		if g.strataOn {
			fmt.Fprintf(&b, "Strata blocks, Coraza does not: rules %s (%d requests)\n\n", ids(g.rules), len(g.diffs))
		} else {
			var notImported, importedMissed []int
			for _, id := range g.rules {
				if imported[id] {
					importedMissed = append(importedMissed, id)
				} else {
					notImported = append(notImported, id)
				}
			}
			fmt.Fprintf(&b, "Coraza blocks, Strata does not (%d requests)\n\n", len(g.diffs))
			if len(importedMissed) > 0 {
				fmt.Fprintf(&b, "- CRS rules Strata imports but that did not match: **%s** (importer or engine)\n", ids(importedMissed))
			}
			if len(notImported) > 0 {
				fmt.Fprintf(&b, "- CRS rules Strata does not import: %s\n", ids(notImported))
			}
			if len(g.rules) == 0 {
				b.WriteString("- same rules matched, different score or threshold\n")
			}
			b.WriteString("\n")
		}
		kinds := map[string]int{}
		for _, d := range g.diffs {
			kinds[d.Kind]++
		}
		ks := make([]string, 0, len(kinds))
		for k, n := range kinds {
			ks = append(ks, fmt.Sprintf("%s %d", k, n))
		}
		sort.Strings(ks)
		fmt.Fprintf(&b, "Requests: %s. Examples:\n\n", strings.Join(ks, ", "))
		for j, d := range g.diffs {
			if j == 3 {
				break
			}
			u, _ := url.PathUnescape(d.URI)
			if len(u) > 140 {
				u = u[:140] + "…"
			}
			fmt.Fprintf(&b, "- `%s` %s `%s` (Strata %v %s; Coraza %v %s)\n", d.ID, d.Method, strings.ReplaceAll(u, "`", "'"),
				blk(d.Strata.Block), ids(d.Strata.Rules), blk(d.Coraza.Block), ids(d.Coraza.Rules))
		}
	}
	return b.String()
}

var ftwFailRe = regexp.MustCompile(`(?m)^\| ([0-9]+-[0-9]+) \| (?:match|no_match) \|`)

// knownFailures: the go-ftw tests Strata already fails with each rule
// compiled alone (docs/crs-ftw-report.md, make test-crs-ftw).
func knownFailures(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, m := range ftwFailRe.FindAllSubmatch(b, -1) {
		out[string(m[1])] = true
	}
	return out, nil
}

// Why a go-ftw test differs, most to least explained.
const (
	whyCoraza   = "Coraza differs from the test"
	whyEarly    = "Strata blocked before reaching the rule"
	whyTuned    = "Strata's tuning"
	whyKnown    = "known (docs/crs-ftw-report.md)"
	whyMissing  = "rule not imported"
	whyStrata   = "Strata differs from the test"
	whyTicketed = whyStrata
)

func classify(d RuleDiff, imported map[int]bool, tuned map[int]string, known map[string]bool) string {
	want := d.Expect == "match"
	switch {
	case d.Strata == want:
		return whyCoraza
	case !imported[d.Rule]:
		return whyMissing
	case known[d.Test]:
		return whyKnown
	case want && d.SBlock:
		// CRS blocks at the end of phase 2 (949110, early blocking off);
		// Strata stops at the stage that reaches the threshold: blocked
		// all the same, the later rule is not evaluated
		return whyEarly
	case tuned[d.Rule] != "":
		return whyTuned
	}
	return whyStrata
}

// ruleReport: the go-ftw tests (corpus/crs-ftw), compared per rule. The
// test's expectation says which engine follows CRS.
func ruleReport(n int, diffs []RuleDiff, imported map[int]bool, tuned map[int]string, known map[string]bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n## go-ftw tests, per rule\n\n%d tests of CRS 4.25.2 (corpus/crs-ftw), the whole core pack loaded; for each, whether the rule the test is for matched in each engine. %d differ.\n\n", n, len(diffs))
	order := []string{whyCoraza, whyEarly, whyTuned, whyKnown, whyMissing, whyStrata}
	byWhy := map[string]map[int][]RuleDiff{}
	for _, d := range diffs {
		w := classify(d, imported, tuned, known)
		if byWhy[w] == nil {
			byWhy[w] = map[int][]RuleDiff{}
		}
		byWhy[w][d.Rule] = append(byWhy[w][d.Rule], d)
	}
	b.WriteString("| Why | Tests | Rules |\n| --- | ---: | --- |\n")
	for _, w := range order {
		rules, total := sortedRules(byWhy[w])
		if total == 0 {
			continue
		}
		list := make([]string, len(rules))
		for i, id := range rules {
			list[i] = fmt.Sprintf("%d (%d)", id, len(byWhy[w][id]))
		}
		fmt.Fprintf(&b, "| %s | %d | %s |\n", w, total, strings.Join(list, ", "))
	}
	b.WriteString("\n" + `"Coraza differs": Strata does what the test expects and Coraza does not; in the 4.25.2 run, all but one are XML attribute tests (CRS's GHSA tests of XML://@*, which Coraza 3.8.1 does not evaluate). "Blocked before reaching the rule": Strata blocks the request (Coraza too, in every such test of the 4.25.2 run); Strata stops at the stage whose score reaches the threshold (a header rule such as 920420), CRS evaluates the body rules too and blocks at 949110. "Known": the test fails in make test-crs-ftw too, already counted in the 95.9%.` + "\n")
	rules, _ := sortedRules(byWhy[whyTicketed])
	b.WriteString("\n## Ticket drafts (go-ftw)\n\nOne per rule where Strata, with the whole core pack, does not do what the CRS test expects and nothing above explains it.\n")
	if len(rules) == 0 {
		b.WriteString("\nNone.\n")
	}
	for i, id := range rules {
		ds := byWhy[whyTicketed][id]
		fmt.Fprintf(&b, "\n### F-%02d · rule %d: %d tests\n\n", i+1, id, len(ds))
		for j, d := range ds {
			if j == 4 {
				fmt.Fprintf(&b, "- … %d more\n", len(ds)-j)
				break
			}
			u := d.URI
			if len(u) > 120 {
				u = u[:120] + "…"
			}
			fmt.Fprintf(&b, "- `%s` expect %s: Strata %s (rules %s, %s), Coraza %s; %s `%s`\n", d.Test, d.Expect, mt(d.Strata),
				ids(d.SRules), blk(d.SBlock), mt(d.Coraza), d.Method, strings.ReplaceAll(u, "`", "'"))
		}
	}
	return b.String()
}

func sortedRules(m map[int][]RuleDiff) ([]int, int) {
	rules := make([]int, 0, len(m))
	total := 0
	for id, ds := range m {
		rules = append(rules, id)
		total += len(ds)
	}
	sort.Slice(rules, func(i, j int) bool {
		if len(m[rules[i]]) != len(m[rules[j]]) {
			return len(m[rules[i]]) > len(m[rules[j]])
		}
		return rules[i] < rules[j]
	})
	return rules, total
}

func mt(b bool) string {
	if b {
		return "match"
	}
	return "no match"
}

func blk(b bool) string {
	if b {
		return "block"
	}
	return "pass"
}

func contains(v []int, x int) bool {
	for _, y := range v {
		if y == x {
			return true
		}
	}
	return false
}
