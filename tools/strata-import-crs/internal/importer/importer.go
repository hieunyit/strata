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
	"MULTIPART_PART_HEADERS": "multipart_part_headers",
	"REQUEST_COOKIES":        "request_cookies", "REQUEST_COOKIES_NAMES": "request_cookies_names",
	"REQUEST_URI": "uri", "REQUEST_URI_RAW": "uri_raw", "REQUEST_FILENAME": "path",
	"REQUEST_METHOD": "method", "REQUEST_PROTOCOL": "protocol", "REMOTE_ADDR": "remote_addr",
	"REQUEST_BODY": "request_body", "FILES": "files", "FILES_NAMES": "files_names",
	"REQUEST_LINE": "request_line", "QUERY_STRING": "query_string", "MATCHED_VARS": "matched_vars",
	"REQBODY_PROCESSOR": "body_processor",
}

// Targets with exactly one value: a condition on them can be negated
// exactly, so a control rule "skip the next rules when X" becomes "not X"
// on those rules.
var singleValued = map[string]bool{"body_processor": true, "method": true, "protocol": true}

// XPath selectors of XML the engine reads: the document text and every
// attribute value; another selector is dropped from the rule (noted),
// the rule's other targets still count.
var xmlSelectors = map[string]string{"/*": "xml", "//@*": "xml_attributes"}

// SecLang transformations -> IR.
var transforms = map[string]string{
	"urlDecodeUni": "url_decode_uni", "htmlEntityDecode": "html_entity_decode", "jsDecode": "js_decode",
	"cssDecode": "css_decode", "lowercase": "lowercase", "removeNulls": "remove_nulls",
	"removeWhitespace": "remove_whitespace", "compressWhitespace": "compress_whitespace",
	"cmdLine": "cmd_line", "normalizePath": "normalize_path", "normalisePath": "normalize_path",
	"utf8toUnicode": "utf8_to_unicode", "base64Decode": "base64_decode",
	"urlDecode": "url_decode", "normalizePathWin": "normalize_path_win", "normalisePathWin": "normalize_path_win",
	"replaceComments": "replace_comments", "removeCommentsChar": "remove_comments_char",
	"length": "length",
}

// SecLang operators -> IR.
var operators = map[string]string{
	"rx": "rx", "pm": "pm", "pmFromFile": "pm", "pmf": "pm", "detectSQLi": "detect_sqli", "detectXSS": "detect_xss",
	"streq": "streq", "contains": "contains", "beginsWith": "begins_with", "endsWith": "ends_with",
	"eq": "eq", "ne": "ne", "gt": "gt", "ge": "ge", "lt": "lt", "le": "le",
	"validateByteRange": "validate_byte_range", "validateUrlEncoding": "validate_url_encoding",
	"validateUtf8Encoding": "validate_utf8_encoding", "ipMatch": "ip_match",
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
	// Defaults: the tx.* lists REQUEST-901-INITIALIZATION sets when the
	// operator does not (allowed methods, content types...), read by Import.
	Defaults map[string]string
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
func convertLink(l seclang.Link, dataDir string, defs map[string]string, notes *[]string) (map[string]any, string) {
	if l.Operator == "within" {
		return withinLink(l, defs)
	}
	var ts []*target
	excludes := map[string][]string{} // IR var -> names
	for _, raw := range l.Variables {
		neg := strings.HasPrefix(raw, "!")
		raw = strings.TrimPrefix(raw, "!")
		count := strings.HasPrefix(raw, "&")
		raw = strings.TrimPrefix(raw, "&")
		name, sel, _ := strings.Cut(raw, ":")
		if name == "XML" {
			v, ok := xmlSelectors[sel]
			if !ok || neg || count {
				*notes = append(*notes, "target "+raw+" left out (XPath selector the engine does not read)")
				continue
			}
			ts = append(ts, &target{v: v})
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
	case "validateUrlEncoding", "validateUtf8Encoding":
	case "validateByteRange":
		arg = strings.TrimSpace(arg)
		if arg == "" {
			return nil, "@validateByteRange without a value"
		}
		opm["value"] = arg
	case "ipMatch":
		parts := strings.Split(arg, ",")
		var ips []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				ips = append(ips, p)
			}
		}
		if len(ips) == 0 {
			return nil, "@ipMatch without a value"
		}
		opm["value"] = ips
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
		for _, a := range l.Actions {
			if a == "multiMatch" {
				cond["multi_match"] = true
			}
		}
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

// skipGate is the condition under which the rules a skip:N control rule
// skips still run: its single condition, negated. nil when that cannot be
// said exactly (a chain, a target with several values).
func skipGate(r seclang.Rule, dataDir string) map[string]any {
	if r.Directive != "SecRule" || len(r.Chain) != 1 {
		return nil
	}
	var notes []string
	c, reason := convertLink(r.Chain[0], dataDir, nil, &notes)
	if reason != "" || len(notes) > 0 {
		return nil
	}
	for _, t := range c["targets"].([]map[string]any) {
		if !singleValued[t["var"].(string)] || t["count"] != nil || t["key"] != nil {
			return nil
		}
	}
	op := c["operator"].(map[string]any)
	if op["negate"] == true {
		delete(op, "negate")
	} else {
		op["negate"] = true
	}
	return c
}

// copyCond copies a condition so each gated rule has its own.
func copyCond(c map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range c {
		if m, ok := v.(map[string]any); ok {
			v = copyCond(m)
		}
		out[k] = v
	}
	return out
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
	if cs, ok, reason := configList(r, opts.Defaults); ok {
		if reason != "" {
			return nil, reason
		}
		conds = cs
		*notes = append(*notes, "list of crs-setup checked with its REQUEST-901 default")
	} else {
		for _, l := range r.Chain {
			c, reason := convertLink(l, filepath.Join(opts.CRSDir, "rules"), opts.Defaults, notes)
			if reason != "" {
				return nil, reason
			}
			conds = append(conds, c)
		}
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
		"action_mode":    "score", // CRS is anomaly scoring: no rule blocks alone
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
	if opts.Defaults == nil {
		d, err := ReadDefaults(filepath.Join(opts.CRSDir, "rules", "REQUEST-901-INITIALIZATION.conf"))
		if err != nil {
			return nil, err
		}
		opts.Defaults = d
	}
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
		// a control rule with skip:N gates the N rules after it: they get
		// the negation of its condition, or are left out when that cannot
		// be said exactly
		var gate map[string]any
		gateFrom, gateLeft := 0, 0
		for _, r := range f.Rules {
			if r.ID == 0 {
				continue
			}
			im.Read++
			gated, gatedBy := gate, gateFrom
			if gateLeft > 0 {
				gateLeft--
			} else {
				gatedBy = 0
			}
			if r.Skip > 0 && !hasAction(r, "block") && !hasAction(r, "deny") {
				gate, gateFrom, gateLeft = skipGate(r, filepath.Join(opts.CRSDir, "rules")), r.ID, r.Skip
			}
			var notes []string
			ir, reason := convert(g, r, opts, &notes)
			if reason == "" && gatedBy != 0 && gated == nil {
				reason = fmt.Sprintf("skipped by control rule %d under a condition the IR cannot negate", gatedBy)
			}
			if reason != "" {
				res.Skipped = append(res.Skipped, Skip{Group: g.File, Rule: r.ID, Reason: reason})
				continue
			}
			if gatedBy != 0 {
				m := ir["match"].(map[string]any)
				m["all"] = append(m["all"].([]any), copyCond(gated))
				notes = append(notes, fmt.Sprintf("condition added from control rule %d: it skips this rule when it matches", gatedBy))
			}
			tune(r.ID, ir, &notes)
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

// sqlSignal: something SQL-like besides what libinjection fingerprints,
// for 942100 (see tune), **before** the first SQL comment ("--" or "#"):
// an injection puts its payload ahead of the comment that cuts the rest of
// the query ("admin'--", "1 OR 1=1 --", "'; DROP TABLE t; #"), while prose
// that libinjection reads as a comment ("50% off -- today only. drop me a
// line") has its words after it (W11-S-01: the 12 benign false positives
// left in the v0 corpus). An SQL keyword alone is not enough: it needs
// another keyword or a number with it ("1 or 1", "x or true"), since a
// word of prose such as "john+or@var.es" (GoTestWAF's false-positive set,
// 15/10/2026) is flagged by libinjection with one keyword and nothing
// else. Linear: no lookaround; the prefix is any text without "--" or
// "#", and a single "-" may come right before the signal.
const sqlSignal = `(?i)^(?:[^#-]|-[^#-])*-?(?:[\x27"\x60()=;]|\b(?:select|union|insert|update|delete|drop|from|where|and|or|not|xor|like|sleep|benchmark|waitfor|exec|execute|cast|convert|char|concat|having|order|group|limit|null|true|false|information_schema)\b(?:[^#-]|-[^#-])*-?\b(?:(?:select|union|insert|update|delete|drop|from|where|and|or|not|xor|like|sleep|benchmark|waitfor|exec|execute|cast|convert|char|concat|having|order|group|limit|null|true|false|information_schema)|[0-9]+)\b|\b[0-9]+\b(?:[^#-]|-[^#-])*-?\b(?:select|union|insert|update|delete|drop|from|where|and|or|not|xor|like|sleep|benchmark|waitfor|exec|execute|cast|convert|char|concat|having|order|group|limit|null|true|false|information_schema)\b)`

// shellSignal, for 932250 (see tune): the value is one word (the command
// alone: "id", "whoami"), or holds shell syntax or a path: an option, a
// slash, a pipe, a redirection, a substitution, a quote, a glob, or a host
// or file name ("wget evil.example"). "ls foo bar" (CRS test 932250-9) is
// prose to this test, as "ls 300 lexus" is: the one go-ftw test the tuning
// gives up (docs/decisions/base64-args.md §3).
const shellSignal = `^[\s\x0b]*[^\s\x0b]+[\s\x0b]*$|[-/\x5c~|;&$\x60<>*?'"(){}\[\]=]|[0-9A-Za-z]\.[0-9A-Za-z]`

// jsSignal, for 941210 (see tune): a call or an assignment, or an
// obfuscated word (a tab or newline between two of its letters, an entity).
const jsSignal = `(?i)[(\x60=]|[a-z][\t\n\r]+[a-z:]|&(?:tab|newline|colon);|&#`

// jsCallSignal, for 941390 (see tune): the function name is called as
// code: right against "(" or "{"; before "{" after spaces ("import { a, b }
// from", CRS test 941390-11); or before "(" after spaces with an argument
// that starts with something other than a letter or with a name followed by
// ".", "(" or "[" ("alert (document.cookie)").
const jsCallSignal = `(?i)\b(?:eval|set(?:timeout|interval)|new[\s\x0b]+function|a(?:lert|tob)|btoa|(?:promp|impor)t|con(?:firm|sole\.(?:log|dir))|fetch)(?:[\(\{]|[\s\x0b]+\{|[\s\x0b]+\([\s\x0b]*(?:[^\sa-z_$]|[a-z_$][0-9a-z_$]*[\s\x0b]*[.\(\[]))`

// 942190's "union, any words, select" and what Strata allows instead.
const (
	unionAnyWords = `union(?:[\s\x0b]select[\s\x0b]@|[\s\x0b\(0-9A-Z_a-z]*?select)`
	unionTight    = `union(?:[\s\x0b]select[\s\x0b]@|[\(0-9A-Z_a-z]*?[\s\x0b\(]*?(?:(?:all|distinct(?:row)?)[\s\x0b\(]*?)?select)`
)

// tune applies Strata's tuning of CRS PL1 (W09-S-01, rules/reviews): rules
// that, as CRS writes them, block common prose on their own (8.35% of the
// benign corpus, Gate A asks under 1%; 15/10/2026: GoTestWAF's
// false-positive set, docs/decisions/base64-args.md). Each change keeps
// what the rule is for; the go-ftw tests of the rules still pass.
//   - 930120 (OS file access) lists "program files", which matches text
//     such as "C:/Program Files is slow". Strata lists "program files/":
//     a path into the directory still matches (normalize_path_win makes
//     "C:\Program Files\x" "c:/program files/x").
//   - 942100 (libinjection) flags "50% off -- today only" (fingerprint
//     1c, as the C library does). Strata adds a condition on the value
//     libinjection flagged: it must also hold, before its first SQL
//     comment, a quote, a parenthesis, "=", ";", or an SQL keyword with
//     another keyword or a number (sqlSignal).
//   - 932250 (Unix command at the start of a value) matches prose that
//     starts with a command name: "ls 300 lexus", "zsh is the best!".
//     Strata adds a condition: the value is the command alone, or holds a
//     character of shell syntax or of a path (shellSignal).
//   - 941210 ("javascript:" with obfuscations) matches "JavaScript: Basics
//     of JavaScript". Strata adds a condition, after the rule's own
//     transforms: the value holds "(", "`" or "=", which a script needs
//     to call or assign anything, or the word is obfuscated (a tab or a
//     newline inside it, an entity left: "ja&tab;vascript:"), which prose
//     never is (jsSignal).
//   - 941390 (JavaScript method) matches prose that puts a word in
//     brackets after alert, confirm, prompt or fetch: "Set an alert
//     (daily)", "please confirm (yes or no)" (prod-sim, 15/10/2026).
//     Strata adds a condition, after the rule's transforms: the name is
//     right against its bracket, or the bracket opens on something other
//     than a word, or on a name followed by ".", "(" or "[" (jsCallSignal).
//     CRS's own test 941390-10, a known false positive of prose ("willing
//     to import (and perhaps wait"), no longer matches: the one go-ftw test
//     this tuning gives up.
//   - 942190 (MSSQL, "union ... select") allows any words between union
//     and select: "union was a great select". Strata allows one run without
//     spaces right after union (what is left of a comment once
//     remove_comments_char took its marks: "union/*x*/select",
//     "union#x\nselect"), then spaces, "(" and ALL, DISTINCT or DISTINCTROW.
func tune(id int, ir map[string]any, notes *[]string) {
	m, _ := ir["match"].(map[string]any)
	all, _ := m["all"].([]any)
	switch id {
	case 930120:
		for _, c := range all {
			cm, _ := c.(map[string]any)
			op, _ := cm["operator"].(map[string]any)
			list, _ := op["value"].([]string)
			for i, v := range list {
				if v == "program files" {
					list[i] = "program files/"
					*notes = append(*notes, `Strata tuning: "program files" listed as "program files/", so that prose naming the directory does not match`)
				}
			}
		}
	case 942100:
		m["all"] = append(all, map[string]any{
			"operator": map[string]any{"type": "rx", "value": sqlSignal},
			"targets":  []any{map[string]any{"var": "matched_vars"}},
		})
		*notes = append(*notes, "Strata tuning: the value libinjection flags must also hold, before its first SQL comment (-- or #), a quote, a parenthesis, =, ;, or an SQL keyword with another keyword or a number (prose such as \"50% off -- today only. drop me a line\" or \"john+or@var.es\" is flagged by libinjection alone)")
	case 932250:
		m["all"] = append(all, map[string]any{
			"operator": map[string]any{"type": "rx", "value": shellSignal},
			"targets":  []any{map[string]any{"var": "matched_vars"}},
		})
		*notes = append(*notes, "Strata tuning: the value must also be the command alone or hold shell or path syntax (prose such as \"ls 300 lexus\" starts with a command name)")
	case 941210, 941390:
		signal, why := jsSignal, "Strata tuning: the value must also hold (, ` or = after the rule's transforms (prose such as \"JavaScript: Basics of JavaScript\" names the word)"
		if id == 941390 {
			signal, why = jsCallSignal, "Strata tuning: the function must also be called as code (prose such as \"Set an alert (daily)\" puts a word in brackets after it)"
		}
		first, _ := all[0].(map[string]any)
		c := map[string]any{
			"operator": map[string]any{"type": "rx", "value": signal},
			"targets":  []any{map[string]any{"var": "matched_vars"}},
		}
		if tr, ok := first["transforms"]; ok {
			c["transforms"] = tr
		}
		m["all"] = append(all, c)
		*notes = append(*notes, why)
	case 942190:
		for _, c := range all {
			cm, _ := c.(map[string]any)
			op, _ := cm["operator"].(map[string]any)
			v, _ := op["value"].(string)
			if strings.Contains(v, unionAnyWords) {
				op["value"] = strings.Replace(v, unionAnyWords, unionTight, 1)
				*notes = append(*notes, "Strata tuning: between union and select only spaces, (, ALL or DISTINCT, or one run without spaces (prose such as \"union was a great select\" has words between them)")
			}
		}
	}
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

// strataDefaults replace REQUEST-901 defaults where they do not suit what
// Strata protects. CRS's allowed_methods (GET HEAD POST OPTIONS) blocks every
// REST API (PUT, PATCH, DELETE); CRS's own crs-setup asks to widen it for
// them. Recorded in docs/crs-import-report.md.
var strataDefaults = map[string]string{
	"allowed_methods": "GET HEAD POST OPTIONS PUT PATCH DELETE",
}

var defaultRe = regexp.MustCompile(`setvar:'tx\.([a-z0-9_]+)=([^']*)'`)

// ReadDefaults reads the tx.* values REQUEST-901-INITIALIZATION.conf sets
// when crs-setup does not: the first assignment of each (later ones add to
// it under conditions, e.g. extra content types for some hosts).
func ReadDefaults(path string) (map[string]string, error) {
	out := map[string]string{}
	src, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return out, nil // a partial tree (tests): rules needing a list are left out
	}
	if err != nil {
		return nil, err
	}
	for _, m := range defaultRe.FindAllStringSubmatch(string(src), -1) {
		if _, seen := out[m[1]]; !seen && !strings.Contains(m[2], "%{") {
			out[m[1]] = m[2]
		}
	}
	for k, v := range strataDefaults {
		out[k] = v
	}
	return out, nil
}

// listOf expands an @within argument (literal or %{tx.name}) into its
// items, delimiters (| or /, a leading .) dropped.
func listOf(arg string, defs map[string]string) ([]string, string) {
	arg = strings.TrimSpace(arg)
	if m := regexp.MustCompile(`^%\{tx\.([a-z0-9_]+)\}$`).FindStringSubmatch(strings.ToLower(arg)); m != nil {
		v, ok := defs[m[1]]
		if !ok {
			return nil, "@within %{tx." + m[1] + "} without a REQUEST-901 default"
		}
		arg = v
	} else if macro.MatchString(arg) {
		return nil, "macro in the operator argument (" + arg + ")"
	}
	var items []string
	for _, f := range strings.Fields(arg) {
		f = strings.Trim(f, "|/")
		f = strings.TrimPrefix(f, ".")
		if f != "" {
			items = append(items, f)
		}
	}
	if len(items) == 0 {
		return nil, "@within with an empty list"
	}
	return items, ""
}

func alternation(items []string) string {
	q := make([]string, len(items))
	for i, it := range items {
		q[i] = regexp.QuoteMeta(it)
	}
	return "(?:" + strings.Join(q, "|") + ")"
}

// withinLink: @within on a request variable (REQUEST_METHOD,
// REQUEST_PROTOCOL...) is "the value is one of the items": an anchored
// alternation. (ModSecurity looks for the value inside the list string;
// with CRS's delimited lists that is the same.)
func withinLink(l seclang.Link, defs map[string]string) (map[string]any, string) {
	if len(l.Variables) != 1 || strings.HasPrefix(l.Variables[0], "TX") {
		return nil, "@within on " + strings.Join(l.Variables, "|")
	}
	name, sel, _ := strings.Cut(strings.TrimPrefix(l.Variables[0], "!"), ":")
	v, ok := vars[name]
	if !ok || strings.HasPrefix(l.Variables[0], "&") {
		return nil, "variable " + name
	}
	items, reason := listOf(l.Argument, defs)
	if reason != "" {
		return nil, reason
	}
	t := map[string]any{"var": v}
	if sel != "" {
		t["key"] = sel
	}
	op := map[string]any{"type": "rx", "value": "^" + alternation(items) + "$"}
	if l.Negated {
		op["negate"] = true
	}
	return map[string]any{"targets": []map[string]any{t}, "operator": op}, ""
}

// configList translates the CRS rules that capture a part of the request
// into a TX variable and check it @within a crs-setup list: content type
// (920420), its charset (920480), the file extension (920440) and header
// names (920450). The capture and the list check become conditions on the
// request value itself. ok is false for any other rule.
func configList(r seclang.Rule, defs map[string]string) ([]any, bool, string) {
	if cs, ok, reason := multipartForms(r, defs); ok {
		return cs, ok, reason
	}
	if len(r.Chain) != 2 || r.Chain[1].Operator != "within" || len(r.Chain[1].Variables) != 1 {
		return nil, false, ""
	}
	tv := strings.ToLower(r.Chain[1].Variables[0])
	items, reason := listOf(r.Chain[1].Argument, defs)
	alt := ""
	if reason == "" {
		alt = alternation(lower(items))
	}
	neg := r.Chain[1].Negated
	rx := func(target map[string]any, value string, negate bool) map[string]any {
		op := map[string]any{"type": "rx", "value": value}
		if negate {
			op["negate"] = true
		}
		return map[string]any{"targets": []map[string]any{target}, "transforms": []string{"lowercase"}, "operator": op}
	}
	ct := map[string]any{"var": "request_headers", "key": "Content-Type"}
	switch {
	case tv == "tx:content_type" && neg:
		if reason != "" {
			return nil, true, reason
		}
		return []any{rx(ct, `^[^;\s]+`, false), rx(ct, `^`+alt+`(?:[;\s]|$)`, true)}, true, ""
	case tv == "tx:content_type_charset" && neg:
		if reason != "" {
			return nil, true, reason
		}
		has := `charset\s*=\s*["']?[^;"'\s]+`
		return []any{rx(ct, has, false), rx(ct, `charset\s*=\s*["']?`+alt+`(?:[;"'\s]|$)`, true)}, true, ""
	case tv == "tx:extension" && !neg:
		if reason != "" {
			return nil, true, reason
		}
		return []any{rx(map[string]any{"var": "path"}, `\.`+alt+`$`, false)}, true, ""
	case strings.HasPrefix(tv, "tx:/^header_name_") && !neg:
		if reason != "" {
			return nil, true, reason
		}
		return []any{rx(map[string]any{"var": "request_headers_names"}, `^`+alt+`$`, false)}, true, ""
	}
	return nil, false, ""
}

func lower(s []string) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = strings.ToLower(x)
	}
	return out
}

// multipartForms translates the two CRS 922 rules that check values other
// rules captured into TX: 922110 (a part's Content-Type, captured by the
// pass rule 922150) and 922100 (the _charset_ field of a multipart body).
func multipartForms(r seclang.Rule, defs map[string]string) ([]any, bool, string) {
	ch := r.Chain
	switch {
	case len(ch) == 1 && strings.EqualFold(ch[0].Variables[0], "TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/") && ch[0].Operator == "rx" && ch[0].Negated:
		// the line of each part's Content-Type, then that value (matched_vars)
		// against the allowed form; per value, so only Content-Type lines
		pat := strings.TrimPrefix(ch[0].Argument, "^")
		full := `^content-type\s*:\s*` + pat
		if _, err := regexp.Compile(full); err != nil {
			return nil, true, "regex is not RE2: " + err.Error()
		}
		return []any{
			map[string]any{"targets": []map[string]any{{"var": "multipart_part_headers"}}, "transforms": []string{"lowercase"},
				"operator": map[string]any{"type": "rx", "value": `^content-type\s*:\s*(.*)$`}},
			map[string]any{"targets": []map[string]any{{"var": "matched_vars"}},
				"operator": map[string]any{"type": "rx", "value": full, "negate": true}},
		}, true, ""
	case len(ch) == 3 && strings.EqualFold(ch[0].Variables[0], "&MULTIPART_PART_HEADERS:_charset_") &&
		strings.EqualFold(ch[1].Variables[0], "ARGS:_charset_") && ch[2].Operator == "within":
		items, reason := listOf(ch[2].Argument, defs)
		if reason != "" {
			return nil, true, reason
		}
		return []any{
			map[string]any{"targets": []map[string]any{{"var": "multipart_part_headers", "key": "_charset_", "count": true}},
				"operator": map[string]any{"type": "gt", "value": 0}},
			map[string]any{"targets": []map[string]any{{"var": "args", "key": "_charset_"}}, "transforms": []string{"lowercase"},
				"operator": map[string]any{"type": "rx", "value": "^" + alternation(lower(items)) + "$", "negate": true}},
		}, true, ""
	}
	return nil, false, ""
}
