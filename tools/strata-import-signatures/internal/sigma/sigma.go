// Package sigma converts Sigma rules of rules/web (webserver and proxy
// logs) to the IR: the detection (named selections, a condition over them)
// becomes one flat all or any match when it can; the rest is reported.
//
// Sigma matches field values case-insensitively, with * and ? wildcards and
// the modifiers contains, startswith, endswith, all, re, cidr. The
// webserver taxonomy's fields map to request variables; keywords (values
// without a field: anywhere in the log line) are looked for in the raw
// request target, which is what an access log line holds of the attacker's
// input.
package sigma

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/strata/strata/tools/strata-import-signatures/internal/irout"
)

// Rule ids of Sigma rules (rules/README.md: 400000-449999 imported Sigma;
// 400100 is a sample rule).
const (
	MinID = 400200
	MaxID = 449999
)

// Source is the Sigma checkout being imported.
type Source struct {
	Dir     string // repository root
	Version string // upstream_version, e.g. 2026-10-06 (8a48134)
}

// Result of an import.
type Result struct {
	Read    int
	Rules   []irout.Rule
	Tests   []irout.Test
	Skipped []irout.Skipped
	Notes   []irout.Skipped // imported, with a change worth knowing
}

type doc struct {
	Title       string         `yaml:"title"`
	ID          string         `yaml:"id"`
	Status      string         `yaml:"status"`
	Author      string         `yaml:"author"`
	Date        string         `yaml:"date"`
	Modified    string         `yaml:"modified"`
	Tags        []string       `yaml:"tags"`
	Level       string         `yaml:"level"`
	Logsource   map[string]any `yaml:"logsource"`
	Detection   map[string]any `yaml:"detection"`
	Description string         `yaml:"description"`
}

// Import converts every rule under <dir>/rules/web.
func Import(src Source, ids *irout.IDs) (*Result, error) {
	var files []string
	err := filepath.WalkDir(filepath.Join(src.Dir, "rules", "web"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".yml") {
			files = append(files, p)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	res := &Result{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var d doc
		if err := yaml.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		res.Read++
		rel, _ := filepath.Rel(src.Dir, f)
		r, tests, note, err := convert(d, src, ids)
		if err != nil {
			res.Skipped = append(res.Skipped, irout.Skipped{Upstream: d.ID + " (" + rel + ")", Name: d.Title, Reason: err.Error()})
			continue
		}
		res.Rules = append(res.Rules, r)
		res.Tests = append(res.Tests, tests...)
		if note != "" {
			res.Notes = append(res.Notes, irout.Skipped{Upstream: fmt.Sprint(r["id"]), Name: d.Title, Reason: note})
		}
	}
	return res, nil
}

// fc is one field condition: the field matches one of the values (all of
// them with the all modifier: split into one fc per value beforehand).
type fc struct {
	field  string // "" for keywords
	mods   []string
	values []string
}

func (f fc) key() string { return f.field + "|" + strings.Join(f.mods, "|") }

type lit struct {
	f   fc
	neg bool
}

// dnf: OR of ANDs of literals.
type dnf [][]lit

const maxDNF = 64

func and(a, b dnf) (dnf, error) {
	var out dnf
	for _, x := range a {
		for _, y := range b {
			out = append(out, append(append([]lit{}, x...), y...))
			if len(out) > maxDNF {
				return nil, errors.New("condition too large")
			}
		}
	}
	return out, nil
}

func not(a dnf) (dnf, error) {
	out := dnf{{}}
	for _, conj := range a {
		var alt dnf
		for _, l := range conj {
			alt = append(alt, []lit{{f: l.f, neg: !l.neg}})
		}
		var err error
		if out, err = and(out, alt); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// selection turns one named detection item into a dnf.
func selection(v any) (dnf, error) {
	switch s := v.(type) {
	case map[string]any:
		return fieldMap(s)
	case []any:
		if len(s) == 0 {
			return nil, errors.New("empty selection")
		}
		if _, ok := s[0].(map[string]any); ok {
			var out dnf
			for _, m := range s {
				mm, ok := m.(map[string]any)
				if !ok {
					return nil, errors.New("mixed selection list")
				}
				d, err := fieldMap(mm)
				if err != nil {
					return nil, err
				}
				out = append(out, d...)
			}
			return out, nil
		}
		vals, err := values(s)
		if err != nil {
			return nil, err
		}
		return dnf{{{f: fc{values: vals}}}}, nil
	case string, int:
		vals, err := values([]any{s})
		if err != nil {
			return nil, err
		}
		return dnf{{{f: fc{values: vals}}}}, nil
	}
	return nil, fmt.Errorf("selection of type %T", v)
}

func fieldMap(m map[string]any) (dnf, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var conj []lit
	for _, k := range keys {
		parts := strings.Split(k, "|")
		var list []any
		switch v := m[k].(type) {
		case []any:
			list = v
		case nil:
			// null: the field is absent
			conj = append(conj, lit{f: fc{field: parts[0], values: []string{nullValue}}})
			continue
		default:
			list = []any{v}
		}
		vals, err := values(list)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", parts[0], err)
		}
		mods, all := []string{}, false
		for _, mod := range parts[1:] {
			if mod == "all" {
				all = true
				continue
			}
			mods = append(mods, mod)
		}
		if all {
			for _, v := range vals {
				conj = append(conj, lit{f: fc{field: parts[0], mods: mods, values: []string{v}}})
			}
		} else {
			conj = append(conj, lit{f: fc{field: parts[0], mods: mods, values: vals}})
		}
	}
	return dnf{conj}, nil
}

func values(list []any) ([]string, error) {
	out := make([]string, 0, len(list))
	for _, v := range list {
		switch x := v.(type) {
		case string:
			if x == "" {
				return nil, errors.New("empty value")
			}
			out = append(out, x)
		case int:
			out = append(out, strconv.Itoa(x))
		default:
			return nil, fmt.Errorf("value of type %T", v)
		}
	}
	return out, nil
}

// condition parses the condition over the named selections.
type parser struct {
	toks []string
	pos  int
	sels map[string]dnf
}

var tokRe = regexp.MustCompile(`\(|\)|[^\s()]+`)

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *parser) next() string { t := p.peek(); p.pos++; return t }

func (p *parser) expr() (dnf, error) {
	d, err := p.term()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.next()
		e, err := p.term()
		if err != nil {
			return nil, err
		}
		d = append(d, e...)
	}
	return d, nil
}

func (p *parser) term() (dnf, error) {
	d, err := p.factor()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.next()
		e, err := p.factor()
		if err != nil {
			return nil, err
		}
		if d, err = and(d, e); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (p *parser) factor() (dnf, error) {
	t := p.next()
	switch {
	case strings.EqualFold(t, "not"):
		d, err := p.factor()
		if err != nil {
			return nil, err
		}
		return not(d)
	case t == "(":
		d, err := p.expr()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, errors.New("unbalanced parentheses")
		}
		return d, nil
	case t == "1" || strings.EqualFold(t, "all"):
		if !strings.EqualFold(p.next(), "of") {
			return nil, errors.New("expected 'of'")
		}
		pat := p.next()
		var names []string
		for n := range p.sels {
			if ok, _ := filepath.Match(pat, n); ok || pat == "them" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("%s matches no selection", pat)
		}
		sort.Strings(names)
		out := p.sels[names[0]]
		for _, n := range names[1:] {
			if t == "1" {
				out = append(append(dnf{}, out...), p.sels[n]...)
			} else {
				var err error
				if out, err = and(out, p.sels[n]); err != nil {
					return nil, err
				}
			}
		}
		return out, nil
	case t == "" || t == ")":
		return nil, errors.New("condition ends early")
	}
	d, ok := p.sels[t]
	if !ok {
		return nil, fmt.Errorf("unknown selection %q", t)
	}
	return d, nil
}

// merge folds conjunctions that differ in one positive literal of the same
// field and modifiers into one, with the values of both (A∧x ∨ A∧y = A∧(x∨y)).
func merge(d dnf) dnf {
	for {
		merged := false
	outer:
		for i := 0; i < len(d); i++ {
			for j := i + 1; j < len(d); j++ {
				if k, ok := oneApart(d[i], d[j]); ok {
					n := append([]lit{}, d[i]...)
					n[k].f.values = union(d[i][k].f.values, other(d[j], d[i], k).f.values)
					d = append(append(append(dnf{}, d[:i]...), n), append(d[i+1:j], d[j+1:]...)...)
					merged = true
					break outer
				}
			}
		}
		if !merged {
			return d
		}
	}
}

func litKey(l lit) string {
	return fmt.Sprintf("%t|%s|%s", l.neg, l.f.key(), strings.Join(l.f.values, "\x00"))
}

// oneApart: a and b have the same literals but one (index k in a), and
// those two are positive with the same field and modifiers.
func oneApart(a, b []lit) (int, bool) {
	if len(a) != len(b) {
		return 0, false
	}
	inB := map[string]int{}
	for _, l := range b {
		inB[litKey(l)]++
	}
	diff := -1
	for i, l := range a {
		if inB[litKey(l)] > 0 {
			inB[litKey(l)]--
			continue
		}
		if diff >= 0 {
			return 0, false
		}
		diff = i
	}
	if diff < 0 {
		return 0, false
	}
	o := other(b, a, diff)
	return diff, !a[diff].neg && !o.neg && o.f.key() == a[diff].f.key()
}

// other is the literal of b that a (minus a[k]) does not have.
func other(b, a []lit, k int) lit {
	inA := map[string]int{}
	for i, l := range a {
		if i != k {
			inA[litKey(l)]++
		}
	}
	for _, l := range b {
		if inA[litKey(l)] > 0 {
			inA[litKey(l)]--
			continue
		}
		return l
	}
	return lit{}
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range append(append([]string{}, a...), b...) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// field mapping: target and kind of value.
type fieldDef struct {
	target irout.Target
	uri    bool // raw request target or query: checked raw and URL-decoded
	ip     bool
	ext    bool // c-uri-extension: the path ends with "." + value
}

var fields = map[string]fieldDef{
	"":                {target: irout.Target{Var: "uri_raw"}, uri: true}, // keywords
	"cs-uri":          {target: irout.Target{Var: "uri_raw"}, uri: true},
	"c-uri":           {target: irout.Target{Var: "uri_raw"}, uri: true},
	"cs-uri-query":    {target: irout.Target{Var: "uri_raw"}, uri: true}, // used for the whole URI by many rules
	"c-uri-query":     {target: irout.Target{Var: "uri_raw"}, uri: true},
	"cs-uri-stem":     {target: irout.Target{Var: "path"}},
	"c-uri-stem":      {target: irout.Target{Var: "path"}},
	"c-uri-extension": {target: irout.Target{Var: "path"}, ext: true},
	"cs-method":       {target: irout.Target{Var: "method"}},
	"cs-version":      {target: irout.Target{Var: "protocol"}},
	"c-useragent":     {target: irout.Target{Var: "request_headers", Key: "User-Agent"}},
	"cs-user-agent":   {target: irout.Target{Var: "request_headers", Key: "User-Agent"}},
	"cs-referer":      {target: irout.Target{Var: "request_headers", Key: "Referer"}},
	"cs-cookie":       {target: irout.Target{Var: "request_headers", Key: "Cookie"}},
	"cs-host":         {target: irout.Target{Var: "request_headers", Key: "Host"}},
	"c-ip":            {target: irout.Target{Var: "remote_addr"}, ip: true},
	"src_ip":          {target: irout.Target{Var: "remote_addr"}, ip: true},
}

// response fields: a request rule cannot see them.
var responseFields = map[string]bool{"sc-status": true, "sc-bytes": true, "sc-content-type": true, "sc-win32-status": true, "sc-substatus": true}

// nullValue stands for a null in the detection: the field is absent.
const nullValue = "\x00null"

func cond(l lit) (irout.Cond, error) {
	def, ok := fields[l.f.field]
	if !ok {
		return irout.Cond{}, fmt.Errorf("field %s not mapped to a request variable", l.f.field)
	}
	if len(l.f.values) == 1 && l.f.values[0] == nullValue {
		if def.target.Key == "" {
			return irout.Cond{}, fmt.Errorf("null on %s", l.f.field)
		}
		t := def.target
		t.Count = true
		op := "eq"
		if l.neg {
			op = "ne" // not absent: present
		}
		return irout.Cond{Targets: []irout.Target{t}, Op: op, Value: 0}, nil
	}
	c := irout.Cond{Targets: []irout.Target{def.target}, Negate: l.neg}
	kind, re, ci := "equals", false, false
	for _, m := range l.f.mods {
		switch m {
		case "contains", "startswith", "endswith":
			kind = m
		case "re":
			re = true
		case "i":
			ci = true
		case "cidr":
			if !def.ip {
				return c, fmt.Errorf("cidr on %s", l.f.field)
			}
			var nets []string
			for _, v := range l.f.values {
				if _, err := netip.ParsePrefix(v); err != nil {
					return c, fmt.Errorf("bad cidr %q", v)
				}
				nets = append(nets, v)
			}
			c.Op, c.Value = "ip_match", nets
			return c, nil
		default:
			return c, fmt.Errorf("modifier %s not supported", m)
		}
	}
	if l.f.field == "" {
		kind = "contains" // keywords: anywhere
	}
	if def.ext {
		kind = "endswith"
	}
	if def.ip {
		return c, fmt.Errorf("%s compared as text", l.f.field)
	}
	if re {
		if len(l.f.values) != 1 {
			return c, errors.New("several regexes")
		}
		p := l.f.values[0]
		if ci {
			p = "(?i)" + p
		}
		if !irout.RE2(p) {
			return c, fmt.Errorf("regex %q is not RE2", l.f.values[0])
		}
		c.Op, c.Value = "rx", p
		if def.uri {
			c.Transforms, c.MultiMatch = []string{"url_decode"}, true
		}
		return c, nil
	}
	c.Transforms = []string{"lowercase"}
	if def.uri {
		// raw, lowercased, then decoded: encoded and decoded patterns alike
		c.Transforms, c.MultiMatch = []string{"lowercase", "url_decode"}, true
	}
	vals := make([]string, len(l.f.values))
	wild := false
	for i, v := range l.f.values {
		if def.ext {
			v = "." + strings.TrimPrefix(v, ".")
		}
		vals[i] = strings.ToLower(v)
		if hasWildcard(v) {
			wild = true
		}
	}
	for _, v := range vals {
		if !irout.Printable(unescape(v)) {
			return c, fmt.Errorf("value %q is not printable ASCII", v)
		}
	}
	switch {
	case !wild && kind == "contains":
		lits := make([]string, len(vals))
		for i, v := range vals {
			lits[i] = unescape(v)
		}
		c.Op, c.Value = "pm", lits
	case !wild && len(vals) == 1 && kind != "contains":
		c.Op = map[string]string{"equals": "streq", "startswith": "begins_with", "endswith": "ends_with"}[kind]
		c.Value = unescape(vals[0])
	default:
		alts := make([]string, len(vals))
		for i, v := range vals {
			alts[i] = wildcardRegex(v)
		}
		p := "(?:" + strings.Join(alts, "|") + ")"
		switch kind {
		case "equals":
			p = "^" + p + "$"
		case "startswith":
			p = "^" + p
		case "endswith":
			p += "$"
		}
		c.Op, c.Value = "rx", p
	}
	return c, nil
}

func hasWildcard(v string) bool {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			i++
		case '*', '?':
			return true
		}
	}
	return false
}

// unescape drops Sigma's escapes (\* \? \\) from a value without wildcards.
func unescape(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) && strings.IndexByte(`*?\`, v[i+1]) >= 0 {
			i++
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

func wildcardRegex(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '\\' && i+1 < len(v) && strings.IndexByte(`*?\`, v[i+1]) >= 0:
			b.WriteString(irout.Literal(string(v[i+1])))
			i++
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		default:
			b.WriteString(irout.Literal(string(c)))
		}
	}
	return b.String()
}

var levels = map[string]struct {
	score    int
	severity string
}{
	"critical": {100, "critical"}, "high": {60, "error"}, "medium": {40, "warning"}, "low": {20, "notice"},
}

func convert(d doc, src Source, ids *irout.IDs) (irout.Rule, []irout.Test, string, error) {
	if d.ID == "" || d.Title == "" {
		return nil, nil, "", errors.New("no id or title")
	}
	if d.Status == "deprecated" || d.Status == "unsupported" {
		return nil, nil, "", fmt.Errorf("status %s", d.Status)
	}
	lv, ok := levels[d.Level]
	if !ok {
		return nil, nil, "", fmt.Errorf("level %q (informational rules are not imported)", d.Level)
	}
	cat, _ := d.Logsource["category"].(string)
	if cat != "webserver" && cat != "proxy" {
		return nil, nil, "", fmt.Errorf("server error log, not requests: logsource %v", d.Logsource)
	}
	condStr, _ := d.Detection["condition"].(string)
	if condStr == "" {
		return nil, nil, "", errors.New("no condition (or a list of conditions)")
	}
	sels := map[string]dnf{}
	for name, v := range d.Detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		s, err := selection(v)
		if err != nil {
			return nil, nil, "", fmt.Errorf("selection %s: %w", name, err)
		}
		sels[name] = s
	}
	if strings.Contains(condStr, "|") {
		return nil, nil, "", errors.New("aggregation in the condition")
	}
	p := &parser{toks: tokRe.FindAllString(condStr, -1), sels: sels}
	f, err := p.expr()
	if err != nil {
		return nil, nil, "", fmt.Errorf("condition %q: %w", condStr, err)
	}
	if p.pos != len(p.toks) {
		return nil, nil, "", fmt.Errorf("condition %q: trailing tokens", condStr)
	}
	// Filters on the response (e.g. not sc-status: 404) are left out: the
	// rule runs before there is a response.
	var notes []string
	for i, conj := range f {
		var kept []lit
		for _, l := range conj {
			if responseFields[l.f.field] {
				if !l.neg {
					return nil, nil, "", fmt.Errorf("needs the response (%s)", l.f.field)
				}
				notes = append(notes, "filter on "+l.f.field+" left out")
				continue
			}
			kept = append(kept, l)
		}
		f[i] = kept
	}
	f = merge(f)
	if cat == "proxy" {
		for _, conj := range f {
			for _, l := range conj {
				if l.f.field != "c-useragent" {
					return nil, nil, "", fmt.Errorf("proxy (outbound) traffic: field %s", fieldName(l.f.field))
				}
			}
		}
	}
	var conds []irout.Cond
	andMatch := true
	switch {
	case len(f) == 1:
		for _, l := range f[0] {
			c, err := cond(l)
			if err != nil {
				return nil, nil, "", err
			}
			conds = append(conds, c)
		}
	default:
		andMatch = false
		for _, conj := range f {
			if len(conj) != 1 {
				return nil, nil, "", fmt.Errorf("condition %q needs nested any/all", condStr)
			}
			c, err := cond(conj[0])
			if err != nil {
				return nil, nil, "", err
			}
			conds = append(conds, c)
		}
	}
	if len(conds) == 0 || len(conds) > irout.MaxConds {
		return nil, nil, "", fmt.Errorf("%d conditions", len(conds))
	}
	positive := false
	for _, c := range conds {
		positive = positive || !c.Negate
	}
	if !positive {
		return nil, nil, "", errors.New("only negated conditions")
	}
	id, err := ids.Get(d.ID)
	if err != nil {
		return nil, nil, "", err
	}
	meta := map[string]any{"source": "sigma", "upstream_id": d.ID, "upstream_version": src.Version,
		"license": "DRL-1.1", "author": author(d.Author), "attack_type": attackType(d)}
	if tags := attackTags(d.Tags); len(tags) > 0 {
		meta["tags"] = tags
	}
	if rev := date(d.Modified, d.Date); rev != "" {
		meta["revision"] = rev
	}
	r := irout.Rule{"id": id, "name": strings.TrimSpace(d.Title), "layer": "managed", "stage": "request_headers",
		"match": irout.Match(conds, andMatch), "score": lv.score, "severity": lv.severity, "metadata": meta}
	tests := []irout.Test{irout.NoMatch(id)}
	if req, ok := sample(f[0]); ok && andMatch {
		tests = append(tests, irout.Test{Rule: id, Name: fmt.Sprintf("%d-generated", id), Expect: "match", Generated: true, Request: req})
	} else if !andMatch {
		// any: one request per alternative that can be made
		for i, conj := range f {
			if req, ok := sample(conj); ok {
				tests = append(tests, irout.Test{Rule: id, Name: fmt.Sprintf("%d-generated-%d", id, i+1), Expect: "match", Generated: true, Request: req})
			}
		}
	}
	return r, tests, strings.Join(uniq(notes), "; "), nil
}

func fieldName(f string) string {
	if f == "" {
		return "keywords"
	}
	return f
}

func uniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func author(a string) string {
	a = strings.Join(strings.Fields(a), " ")
	if a == "" {
		return "Sigma contributors"
	}
	return a
}

var dateRe = regexp.MustCompile(`^(\d{4})[-/](\d{2})[-/](\d{2})$`)

func date(ds ...string) string {
	for _, d := range ds {
		if m := dateRe.FindStringSubmatch(strings.TrimSpace(d)); m != nil {
			return m[1] + "-" + m[2] + "-" + m[3]
		}
	}
	return ""
}

func attackTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if strings.HasPrefix(t, "attack.") || strings.HasPrefix(t, "cve.") {
			out = append(out, t)
		}
	}
	return uniq(out)
}

func attackType(d doc) string {
	s := strings.ToLower(d.Title + " " + d.Description)
	for _, c := range []struct{ word, typ string }{
		{"sql", "sql-injection"}, {"xss", "xss"}, {"cross-site", "xss"}, {"traversal", "path-traversal"},
		{"template injection", "template-injection"}, {"ssti", "template-injection"}, {"jndi", "rce"},
		{"webshell", "rce"}, {"web shell", "rce"}, {"command", "command-injection"}, {"user agent", "scanner"},
		{"user-agent", "scanner"}, {"scan", "scanner"}, {"enumeration", "scanner"},
	} {
		if strings.Contains(s, c.word) {
			return c.typ
		}
	}
	return "other"
}

// sample builds a request every positive literal of conj matches, or false
// when one cannot be made from the values (regexes, conflicts).
func sample(conj []lit) (map[string]any, bool) {
	type parts struct {
		prefix, suffix, exact string
		mid                   []string
		set                   bool
	}
	byTarget := map[string]*parts{}
	order := []string{}
	absent := map[string]bool{} // headers the rule wants absent
	for _, l := range conj {
		if l.neg {
			continue
		}
		def := fields[l.f.field]
		kind := "equals"
		for _, m := range l.f.mods {
			switch m {
			case "contains", "startswith", "endswith":
				kind = m
			case "re", "cidr", "i":
				return nil, false
			}
		}
		if l.f.field == "" {
			kind = "contains"
		}
		v := l.f.values[0]
		if v == nullValue {
			absent[def.target.Key] = true
			continue
		}
		if def.ext {
			v, kind = "."+strings.TrimPrefix(v, "."), "endswith"
		}
		v = strings.NewReplacer(`\*`, "*", `\?`, "?", `\\`, `\`).Replace(strings.NewReplacer("*", "x", "?", "a").Replace(v))
		k := def.target.Var + "|" + def.target.Key
		p := byTarget[k]
		if p == nil {
			p = &parts{}
			byTarget[k] = p
			order = append(order, k)
		}
		switch kind {
		case "equals":
			if p.set && p.exact != v {
				return nil, false
			}
			p.exact, p.set = v, true
		case "startswith":
			if p.prefix != "" {
				return nil, false
			}
			p.prefix = v
		case "endswith":
			if p.suffix != "" {
				return nil, false
			}
			p.suffix = v
		default:
			p.mid = append(p.mid, v)
		}
	}
	req := map[string]any{"method": "GET", "uri": "/"}
	headers := map[string]any{"Host": "api.example.test", "User-Agent": irout.BenignUA}
	path, query := "/", ""
	for _, k := range order {
		p := byTarget[k]
		val := p.exact
		if !p.set {
			val = p.prefix + strings.Join(p.mid, "/") + p.suffix
		} else if p.prefix != "" || p.suffix != "" || len(p.mid) > 0 {
			return nil, false
		}
		v, key, _ := strings.Cut(k, "|")
		switch v {
		case "method":
			req["method"] = strings.ToUpper(val)
		case "protocol":
			req["protocol"] = strings.ToUpper(val)
		case "request_headers":
			headers[key] = val
		case "path":
			if !strings.HasPrefix(val, "/") {
				val = "/x" + val
			}
			path = val
		case "query_string":
			query = val
		case "uri_raw":
			if !strings.HasPrefix(val, "/") {
				val = "/?q=" + val
			}
			req["uri"] = encodeTarget(val)
		}
	}
	if _, set := req["uri"].(string); req["uri"] == "/" || !set {
		u := path
		if query != "" {
			u += "?" + query
		}
		req["uri"] = encodeTarget(u)
	}
	for k := range absent {
		delete(headers, k)
	}
	req["headers"] = headers
	return req, true
}

// encodeTarget percent-encodes what may not appear in a request target.
func encodeTarget(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte("\"<>\\^`{|}#", c) >= 0 {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
