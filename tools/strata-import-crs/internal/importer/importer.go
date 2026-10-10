// Package importer turns CRS rules into Strata's rule IR
// (docs/spec/ir.schema.json; W05-S-01, W06-S-01). What the IR cannot say
// is left out with the reason, rule by rule; the result is compiled with
// strata-compile, and a rule the compiler refuses (a regex Hyperscan
// cannot take) is left out with the compiler's message.
//
// Anomaly scoring: CRS blocks when the inbound score reaches 5 at
// paranoia level 1 (a CRITICAL rule adds 5, ERROR 4, WARNING 3, NOTICE 2);
// Strata blocks at 100. Scores are multiplied by 20, so one CRITICAL rule
// blocks, as in CRS, and two WARNING ones do too.
package importer

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/strata/strata/tools/strata-import-crs/internal/seclang"
)

// ScoreFactor maps CRS anomaly points onto Strata's block threshold of 100.
const ScoreFactor = 20

var severityPoints = map[string]int{"CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2}
var severityIR = map[string]string{"CRITICAL": "critical", "ERROR": "error", "WARNING": "warning", "NOTICE": "notice"}

// SecLang collections and variables -> IR targets.
var vars = map[string]string{
	"ARGS": "args", "ARGS_NAMES": "args_names", "ARGS_GET": "args_get", "ARGS_POST": "args_post",
	"ARGS_GET_NAMES": "args_names", "ARGS_POST_NAMES": "args_names",
	"REQUEST_HEADERS": "request_headers", "REQUEST_HEADERS_NAMES": "request_headers_names",
	"REQUEST_COOKIES": "request_cookies", "REQUEST_COOKIES_NAMES": "request_cookies_names",
	"REQUEST_URI": "uri", "REQUEST_URI_RAW": "uri_raw", "REQUEST_FILENAME": "path",
	"REQUEST_METHOD": "method", "REQUEST_PROTOCOL": "protocol", "REMOTE_ADDR": "remote_addr",
	"REQUEST_BODY": "request_body", "FILES": "files", "FILES_NAMES": "files_names",
}

// Targets dropped from a rule rather than refusing the rule: the engine
// has no XML body parser yet; the other targets of the rule still count.
var droppable = map[string]bool{"XML": true}

// SecLang transformations -> IR.
var transforms = map[string]string{
	"urlDecodeUni": "url_decode_uni", "htmlEntityDecode": "html_entity_decode", "jsDecode": "js_decode",
	"cssDecode": "css_decode", "lowercase": "lowercase", "removeNulls": "remove_nulls",
	"removeWhitespace": "remove_whitespace", "compressWhitespace": "compress_whitespace",
	"cmdLine": "cmd_line", "normalizePath": "normalize_path", "normalisePath": "normalize_path",
	"utf8toUnicode": "utf8_to_unicode", "base64Decode": "base64_decode",
	"urlDecode": "url_decode", "normalizePathWin": "normalize_path_win", "normalisePathWin": "normalize_path_win",
	"replaceComments": "replace_comments", "removeCommentsChar": "remove_comments_char",
}

// SecLang operators -> IR.
var operators = map[string]string{
	"rx": "rx", "pm": "pm", "pmFromFile": "pm", "pmf": "pm", "detectSQLi": "detect_sqli", "detectXSS": "detect_xss",
	"streq": "streq", "contains": "contains", "beginsWith": "begins_with", "endsWith": "ends_with",
	"eq": "eq", "ne": "ne", "gt": "gt", "ge": "ge", "lt": "lt", "le": "le",
}

// Group is one CRS file to import.
type Group struct {
	File       string // REQUEST-942-APPLICATION-ATTACK-SQLI.conf
	Out        string // 942-sqli.yaml
	Ruleset    string // crs-942-sqli
	AttackType string // IR attack_type
	Layer      string // protocol | managed
}

// Options of an import.
type Options struct {
	CRSDir     string // the release (rules/ under it)
	Version    string // 4.25.2
	MaxPL      int    // paranoia levels imported, default 1
	Compile    string // strata-compile binary; empty: no compile check
	PoliciesIR string // policies file for the compile check (temporary if empty)
}

// Skip is a rule not imported.
type Skip struct {
	Group  string
	Rule   int
	Reason string
}

// Note is a change made to an imported rule.
type Note struct {
	Rule int
	Text string
}

// Imported is the result for one group.
type Imported struct {
	Group Group
	Read  int // rules with an id in the file
	Rules []map[string]any
	Notes []Note
}

// Result of an import.
type Result struct {
	Groups  []*Imported
	Skipped []Skip
}

var macro = regexp.MustCompile(`%\{[^}]*\}`)

type target struct {
	v     string
	key   string
	count bool
}

// convertLink turns one chain link into an IR condition.
func convertLink(l seclang.Link, dataDir string, notes *[]string) (map[string]any, string) {
	var ts []*target
	excludes := map[string][]string{} // IR var -> names
	for _, raw := range l.Variables {
		neg := strings.HasPrefix(raw, "!")
		raw = strings.TrimPrefix(raw, "!")
		count := strings.HasPrefix(raw, "&")
		raw = strings.TrimPrefix(raw, "&")
		name, sel, _ := strings.Cut(raw, ":")
		if droppable[name] {
			*notes = append(*notes, "target "+raw+" left out (no XML body parser yet)")
			continue
		}
		v, ok := vars[name]
		if !ok {
			return nil, "variable " + name
		}
		if neg {
			if strings.HasPrefix(sel, "/") {
				*notes = append(*notes, fmt.Sprintf("exclusion !%s:%s left out (the IR excludes names, not patterns)", name, sel))
				continue
			}
			excludes[v] = append(excludes[v], sel)
			continue
		}
		if strings.HasPrefix(sel, "/") {
			return nil, "pattern selector " + name + ":" + sel
		}
		ts = append(ts, &target{v: v, key: sel, count: count})
	}
	if len(ts) == 0 {
		return nil, "no target the IR can read"
	}
	op, ok := operators[l.Operator]
	if !ok {
		return nil, "operator @" + l.Operator
	}
	arg := l.Argument
	if macro.MatchString(arg) {
		return nil, "macro in the operator argument (" + arg + ")"
	}
	opm := map[string]any{"type": op}
	switch l.Operator {
	case "rx":
		if _, err := regexp.Compile(arg); err != nil {
			return nil, "regex is not RE2: " + err.Error()
		}
		opm["value"] = arg
	case "pm":
		opm["value"] = strings.Fields(arg)
	case "pmFromFile", "pmf":
		words, err := dataFile(filepath.Join(dataDir, arg))
		if err != nil {
			return nil, "data file " + arg + ": " + err.Error()
		}
		opm["value"] = words
	case "detectSQLi", "detectXSS":
	case "eq", "ne", "gt", "ge", "lt", "le":
		n, err := strconv.Atoi(strings.TrimSpace(arg))
		if err != nil {
			return nil, "numeric operator on " + arg
		}
		opm["value"] = n
	default:
		if arg == "" {
			return nil, "@" + l.Operator + " without a value"
		}
		opm["value"] = arg
	}
	if l.Negated {
		opm["negate"] = true
	}
	var chain []string
	for _, t := range l.Transforms {
		if t == "none" {
			chain = nil
			continue
		}
		ir, ok := transforms[t]
		if !ok {
			return nil, "transformation " + t
		}
		chain = append(chain, ir)
	}
	targets := make([]map[string]any, 0, len(ts))
	for _, t := range ts {
		m := map[string]any{"var": t.v}
		if t.key != "" {
			m["key"] = t.key
		}
		if ex := excludes[t.v]; len(ex) > 0 && t.key == "" {
			m["exclude"] = ex
		}
		if t.count {
			m["count"] = true
		}
		targets = append(targets, m)
	}
	cond := map[string]any{"targets": targets, "operator": opm}
	if len(chain) > 0 {
		cond["transforms"] = chain
	}
	return cond, ""
}

// dataFile reads a CRS .data file: one phrase per line, # comments.
func dataFile(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty")
	}
	return out, sc.Err()
}

func hasAction(r seclang.Rule, name string) bool {
	for _, a := range r.Actions() {
		if a == name {
			return true
		}
	}
	return false
}

// convert turns one CRS rule into an IR rule, or gives the reason it
// cannot.
func convert(g Group, r seclang.Rule, opts Options, notes *[]string) (map[string]any, string) {
	if r.Directive != "SecRule" {
		return nil, "SecAction (sets variables)"
	}
	if pl := r.ParanoiaLevel(); pl > opts.MaxPL {
		return nil, fmt.Sprintf("paranoia level %d (PL2 and above come with W17)", pl)
	}
	if !hasAction(r, "block") && !hasAction(r, "deny") {
		return nil, "does not block or score (control flow)"
	}
	stage := map[string]string{"1": "request_headers", "request": "request_headers", "2": "request_body"}[r.Phase]
	if stage == "" {
		return nil, "phase " + r.Phase
	}
	pts, ok := severityPoints[r.Severity]
	if !ok {
		return nil, "severity " + r.Severity
	}
	var conds []any
	for _, l := range r.Chain {
		c, reason := convertLink(l, filepath.Join(opts.CRSDir, "rules"), notes)
		if reason != "" {
			return nil, reason
		}
		conds = append(conds, c)
	}
	name := r.Msg
	if name == "" {
		name = fmt.Sprintf("CRS rule %d", r.ID)
	}
	if len(name) > 200 {
		name = name[:200]
	}
	return map[string]any{
		"id": r.ID, "name": name, "layer": g.Layer, "stage": stage,
		"match":          map[string]any{"all": conds},
		"score":          pts * ScoreFactor,
		"severity":       severityIR[r.Severity],
		"paranoia_level": max(r.ParanoiaLevel(), 1),
		"metadata": map[string]any{
			"source": "crs", "upstream_id": strconv.Itoa(r.ID), "upstream_version": opts.Version,
			"license": "Apache-2.0", "author": "OWASP CRS project", "attack_type": g.AttackType,
		},
	}, ""
}

var compileErr = regexp.MustCompile(`rule (\d+): (.*)`)

// Import converts groups; with opts.Compile it also drops the rules the
// compiler refuses.
func Import(groups []Group, opts Options) (*Result, error) {
	if opts.MaxPL == 0 {
		opts.MaxPL = 1
	}
	res := &Result{}
	for _, g := range groups {
		src, err := os.ReadFile(filepath.Join(opts.CRSDir, "rules", g.File))
		if err != nil {
			return nil, err
		}
		f, err := seclang.Parse(g.File, string(src))
		if err != nil {
			return nil, err
		}
		if len(f.Errors) > 0 {
			return nil, fmt.Errorf("%s: %v", g.File, f.Errors)
		}
		im := &Imported{Group: g}
		for _, r := range f.Rules {
			if r.ID == 0 {
				continue
			}
			im.Read++
			var notes []string
			ir, reason := convert(g, r, opts, &notes)
			if reason != "" {
				res.Skipped = append(res.Skipped, Skip{Group: g.File, Rule: r.ID, Reason: reason})
				continue
			}
			for _, n := range notes {
				im.Notes = append(im.Notes, Note{Rule: r.ID, Text: n})
			}
			im.Rules = append(im.Rules, ir)
		}
		if opts.Compile != "" {
			if err := checkCompile(im, opts, res); err != nil {
				return nil, err
			}
		}
		res.Groups = append(res.Groups, im)
	}
	return res, nil
}

// checkCompile compiles the group and drops the rules the compiler
// refuses, one at a time, until it compiles.
func checkCompile(im *Imported, opts Options, res *Result) error {
	dir, err := os.MkdirTemp("", "strata-import-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	key := filepath.Join(dir, "key")
	_ = os.WriteFile(key, bytes.Repeat([]byte{7}, 32), 0o600)
	pol := filepath.Join(dir, "policies.json")
	_ = os.WriteFile(pol, []byte(`{"policies":[{"name":"import-check","mode":"shadow"}]}`), 0o644)
	for attempt := 0; attempt < 500 && len(im.Rules) > 0; attempt++ {
		doc, err := Marshal(im, opts.Version)
		if err != nil {
			return err
		}
		irFile := filepath.Join(dir, "rules.yaml")
		if err := os.WriteFile(irFile, doc, 0o644); err != nil {
			return err
		}
		var stderr bytes.Buffer
		cmd := exec.Command(opts.Compile, "--rules", irFile, "--policies", pol, "--key", key, "--version", "1",
			"--created-at", "1", "--out", filepath.Join(dir, "b.sbn"))
		cmd.Stderr = &stderr
		if cmd.Run() == nil {
			return nil
		}
		m := compileErr.FindStringSubmatch(stderr.String())
		if m == nil {
			return fmt.Errorf("%s: strata-compile: %s", im.Group.File, strings.TrimSpace(stderr.String()))
		}
		id, _ := strconv.Atoi(m[1])
		kept := im.Rules[:0]
		for _, r := range im.Rules {
			if r["id"] != id {
				kept = append(kept, r)
			}
		}
		if len(kept) == len(im.Rules) {
			return fmt.Errorf("%s: strata-compile refuses rule %d, which is not in the group: %s", im.Group.File, id, m[2])
		}
		im.Rules = kept
		res.Skipped = append(res.Skipped, Skip{Group: im.Group.File, Rule: id, Reason: "compiler: " + strings.TrimSpace(m[2])})
	}
	return nil
}

// Sorted skips by group then rule.
func (r *Result) Sorted() []Skip {
	s := append([]Skip(nil), r.Skipped...)
	sort.Slice(s, func(i, j int) bool {
		if s[i].Group != s[j].Group {
			return s[i].Group < s[j].Group
		}
		return s[i].Rule < s[j].Rule
	})
	return s
}
