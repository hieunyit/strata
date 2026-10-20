package importer

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/strata/strata/tools/strata-import-crs/internal/seclang"
)

// W17-S-01: the CRS rule exclusion plugins (WordPress, Drupal...) as IR
// exclusion rules: a rule's conditions as they are, its ctl actions as
// `exclude` entries. Tags are expanded here, from the tags of the CRS
// release's rules, into ID ranges, so the engine never sees tags.

var tagSlash = regexp.MustCompile(`ctl:ruleRemove(?:Target)?ByTag=[^;,"\s]*`)

// an ID range lo-hi of ruleRemoveTargetById, packed while parsing into one
// number: 9, lo and hi on 7 digits each (real IDs have at most 7)
var (
	idRangeTarget = regexp.MustCompile(`(ctl:ruleRemoveTargetById=)([0-9]{1,7})-([0-9]{1,7});`)
	packedRange   = regexp.MustCompile(`^(ruleRemoveTargetById=)9([0-9]{7})([0-9]{7});(.*)$`)
)

const slashMark = "__SLASH__"

// Plugin is one rule exclusion plugin release.
type Plugin struct {
	Name    string // wordpress
	Version string // v1.2.0
	Dir     string // the release (plugins/ under it)
}

// PluginResult is the import of one plugin.
type PluginResult struct {
	Imported *Imported
	Skipped  []Skip
	// Dropped: removals left out of imported rules (rule, text)
	Dropped []Note
	// Extra: exclusion rules split off a rule that both extends a CRS list
	// option and has ctl actions (ID + widenIDOffset)
	Extra []map[string]any
	// the plugin's go-ftw tests: read, not converted, and expectations
	// written (one per rule id a test asserts)
	TestsRead, TestsSkipped, Tests int
}

// CRSTags reads tag -> CRS rule IDs (sorted) from every rule of the
// release, and the sorted IDs of all of them.
func CRSTags(crsDir string) (map[string][]int, []int, error) {
	files, err := filepath.Glob(filepath.Join(crsDir, "rules", "*.conf"))
	if err != nil {
		return nil, nil, err
	}
	tags := map[string][]int{}
	var all []int
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, err
		}
		pf, err := seclang.Parse(filepath.Base(f), string(src))
		if err != nil {
			return nil, nil, err
		}
		for _, r := range pf.Rules {
			if r.ID == 0 {
				continue
			}
			all = append(all, r.ID)
			for _, t := range r.Tags {
				tags[t] = append(tags[t], r.ID)
			}
		}
	}
	sort.Ints(all)
	for t := range tags {
		sort.Ints(tags[t])
	}
	return tags, all, nil
}

// ranges turns the members of a sorted universe into [lo, hi] runs with no
// other member of the universe inside.
func ranges(universe, members []int) [][2]int {
	in := map[int]bool{}
	for _, m := range members {
		in[m] = true
	}
	var out [][2]int
	for i := 0; i < len(universe); i++ {
		if !in[universe[i]] {
			continue
		}
		j := i
		for j+1 < len(universe) && in[universe[j+1]] {
			j++
		}
		out = append(out, [2]int{universe[i], universe[j]})
		i = j
	}
	return out
}

// pluginTarget maps a ctl target (ARGS:pwd, REQUEST_BODY, XML:/*) to an IR
// target; ok is false for one Strata has no variable for (TX...).
func pluginTarget(t string) (map[string]any, bool) {
	name, key, keyed := strings.Cut(t, ":")
	switch name {
	case "XML":
		return map[string]any{"var": "xml"}, true
	case "REQUEST_COOKIES_NAMES", "REQUEST_HEADERS_NAMES":
		return map[string]any{"var": vars[name]}, !keyed
	case "RESPONSE_BODY":
		return map[string]any{"var": "response_body"}, !keyed
	}
	v, ok := vars[name]
	if !ok || name == "MATCHED_VARS" || name == "REQBODY_PROCESSOR" {
		return nil, false
	}
	m := map[string]any{"var": v}
	if keyed {
		if key == "" || strings.HasPrefix(key, "/") || len(key) > 256 {
			return nil, false
		}
		m["key"] = key
	}
	return m, true
}

// ImportPlugin converts the rules of a plugin's *-before.conf files.
// tags/universe come from CRSTags. Rules with nothing to remove, or a
// condition the IR cannot say, are left out with the reason.
func ImportPlugin(p Plugin, tags map[string][]int, universe []int, crsDir string, defaults map[string]string) (*PluginResult, error) {
	files, err := filepath.Glob(filepath.Join(p.Dir, "plugins", "*.conf"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	res := &PluginResult{Imported: &Imported{Group: Group{File: p.Name, Out: p.Name + ".yaml", Ruleset: "crs-plugin-" + p.Name, Layer: "pre"}}}
	config, err := pluginConfig(files)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		base := filepath.Base(f)
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(base, "-config.conf") {
			continue // setvar defaults of the plugin: the policy's crs_plugins replaces them
		}
		if strings.HasSuffix(base, "-after.conf") {
			for _, line := range strings.Split(string(src), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "SecRuleUpdateTargetById") {
					res.Skipped = append(res.Skipped, Skip{Group: base, Reason: "SecRuleUpdateTargetById (after the CRS, a pattern key): " + strings.TrimSpace(line)})
				}
			}
			continue
		}
		// the SecLang grammar takes no "/" in a ctl tag value
		// (ruleRemoveByTag=OWASP_CRS/DATA-LEAKAGES-PHP) and no ID range in
		// ruleRemoveTargetById (930100-930110;REQUEST_BODY): hidden while
		// parsing
		text := tagSlash.ReplaceAllStringFunc(string(src), func(m string) string {
			return strings.ReplaceAll(m, "/", slashMark)
		})
		text = idRangeTarget.ReplaceAllStringFunc(text, func(m string) string {
			g := idRangeTarget.FindStringSubmatch(m)
			lo, _ := strconv.Atoi(g[2])
			hi, _ := strconv.Atoi(g[3])
			return fmt.Sprintf("%s9%07d%07d;", g[1], lo, hi)
		})
		pf, err := seclang.Parse(base, text)
		if err != nil {
			return nil, err
		}
		if len(pf.Errors) > 0 {
			return nil, fmt.Errorf("%s: %v", base, pf.Errors)
		}
		markers := secMarkers(text)
		var gates []gate
		var off []optionOff
		for _, r := range pf.Rules {
			if r.ID == 0 {
				continue
			}
			res.Imported.Read++
			// the gates whose marker is behind this rule are over
			live := gates[:0]
			for _, g := range gates {
				if g.until > r.Line {
					live = append(live, g)
				}
			}
			gates = live
			var mine []gate
			for _, g := range gates {
				if g.phase == r.Phase {
					mine = append(mine, g)
				}
			}
			skipped := ""
			for _, g := range mine {
				if g.cond == nil {
					skipped = g.reason
				}
			}
			// a plugin option turning plugin rules off (ctl:ruleRemoveById of
			// its own IDs), decided with the plugin's defaults
			if ids, reason, ok := optionGate(r, config); ok {
				off = append(off, ids...)
				res.Skipped = append(res.Skipped, Skip{Group: base, Rule: r.ID, Reason: reason})
				continue
			}
			if why := offBy(off, r.ID); why != "" {
				res.Skipped = append(res.Skipped, Skip{Group: base, Rule: r.ID, Reason: why})
				continue
			}
			if r.SkipAfter != "" {
				reason := "skipAfter gate: folded into the rules it gates"
				if skipped != "" {
					reason = skipped
				} else if g, err := newGate(r, markers, config, filepath.Join(crsDir, "rules")); err != nil {
					return nil, fmt.Errorf("%s: rule %d: %w", base, r.ID, err)
				} else if g != nil {
					gates = append(gates, *g)
				}
				res.Skipped = append(res.Skipped, Skip{Group: base, Rule: r.ID, Reason: reason})
				continue
			}
			if skipped != "" {
				res.Skipped = append(res.Skipped, Skip{Group: base, Rule: r.ID, Reason: skipped})
				continue
			}
			ir, reason := convertPluginRule(p, r, tags, universe, crsDir, defaults, res)
			if reason != "" {
				res.Extra = nil
				res.Skipped = append(res.Skipped, Skip{Group: base, Rule: r.ID, Reason: reason})
				continue
			}
			for _, g := range mine {
				m := ir["match"].(map[string]any)
				m["all"] = append(m["all"].([]any), copyCond(g.cond))
				res.Imported.Notes = append(res.Imported.Notes, Note{Rule: r.ID, Text: fmt.Sprintf("condition added from gate %d: it skips this rule when it matches", g.from)})
			}
			res.Imported.Rules = append(res.Imported.Rules, ir)
			res.Imported.Rules = append(res.Imported.Rules, res.Extra...)
			res.Extra = nil
		}
	}
	seen := map[int]bool{}
	for _, r := range res.Imported.Rules {
		id := r["id"].(int)
		if seen[id] {
			return nil, fmt.Errorf("%s: rule id %d twice", p.Name, id)
		}
		seen[id] = true
	}
	return res, nil
}

func convertPluginRule(p Plugin, r seclang.Rule, tags map[string][]int, universe []int, crsDir string, defaults map[string]string, res *PluginResult) (map[string]any, string) {
	var ctls []string
	for _, l := range r.Chain {
		for _, c := range l.Ctls {
			c = strings.ReplaceAll(c, slashMark, "/")
			if m := packedRange.FindStringSubmatch(c); m != nil {
				lo, _ := strconv.Atoi(m[2])
				hi, _ := strconv.Atoi(m[3])
				c = fmt.Sprintf("%s%d-%d;%s", m[1], lo, hi, m[4])
			}
			ctls = append(ctls, c)
		}
	}
	// a list option of the CRS extended under the rule's conditions:
	// the same as taking away, when the request has one of the values
	// added, the one CRS rule that checks the list
	var widen []map[string]any
	var setvars int
	for _, l := range r.Chain {
		for _, sv := range l.Setvars {
			setvars++
			m := listOption.FindStringSubmatch(sv)
			if m == nil {
				continue
			}
			c, ok := widenCondition(strings.ToLower(m[1]), m[3])
			if !ok {
				return nil, "setvar " + sv
			}
			widen = append(widen, c)
		}
	}
	switch {
	case len(widen) > 0 && len(ctls) > 0:
		// two exclusion rules: the ctl actions under the rule's conditions,
		// the list option under them and the added values (ID + 100000)
		w := r
		w.ID = r.ID + widenIDOffset
		w.Chain = append([]seclang.Link(nil), r.Chain...)
		for i := range w.Chain {
			w.Chain[i].Ctls = nil
		}
		wr, reason := convertPluginRule(p, w, tags, universe, crsDir, defaults, res)
		if reason != "" {
			res.Dropped = append(res.Dropped, Note{Rule: r.ID, Text: "the CRS list option it extends: " + reason})
		} else {
			res.Extra = append(res.Extra, wr)
			res.Imported.Notes = append(res.Imported.Notes, Note{Rule: r.ID, Text: fmt.Sprintf("its CRS list option extension is rule %d", w.ID)})
		}
		widen = nil
	case len(widen) > 1:
		return nil, "more than one CRS list option extended"
	case len(widen) == 0 && len(ctls) == 0 && setvars > 0:
		return nil, "setvar of CRS options (Strata keeps the CRS defaults)"
	case len(widen) == 0 && len(ctls) == 0:
		return nil, "no ctl action"
	}
	first := r.Chain[0]
	if len(first.Variables) == 1 && strings.HasPrefix(strings.ToLower(strings.TrimPrefix(first.Variables[0], "&")), "tx:") &&
		strings.HasSuffix(strings.ToLower(first.Variables[0]), "_enabled") {
		return nil, "plugin switch: a policy runs the plugin with crs_plugins"
	}
	stage := map[string]string{"1": "request_headers", "request": "request_headers", "2": "request_body"}[r.Phase]
	if stage == "" {
		return nil, "phase " + r.Phase
	}
	var conds []any
	var notes []string
	for _, l := range r.Chain {
		if l.Operator == "unconditionalMatch" && !l.Negated {
			// always true: the method is always there and rx ^ matches it
			conds = append(conds, map[string]any{
				"targets":  []map[string]any{{"var": "method"}},
				"operator": map[string]any{"type": "rx", "value": "^"},
			})
			continue
		}
		c, reason := convertLink(l, filepath.Join(crsDir, "rules"), defaults, &notes)
		if reason != "" {
			return nil, reason
		}
		conds = append(conds, c)
	}
	// removals, grouped by target, in the order the plugin names them
	byTarget := map[string]map[string]any{}
	var order []string
	add := func(target map[string]any, lo, hi int) {
		k := fmt.Sprint(target)
		e, ok := byTarget[k]
		if !ok {
			e = map[string]any{}
			if target != nil {
				e["target"] = target
			}
			byTarget[k] = e
			order = append(order, k)
		}
		if lo == hi {
			ids, _ := e["rules"].([]int)
			e["rules"] = append(ids, lo)
		} else {
			rs, _ := e["rule_ranges"].([][2]int)
			e["rule_ranges"] = append(rs, [2]int{lo, hi})
		}
	}
	drop := func(text string) {
		res.Dropped = append(res.Dropped, Note{Rule: r.ID, Text: text})
	}
	for _, c := range ctls {
		op, arg, _ := strings.Cut(c, "=")
		switch op {
		case "ruleRemoveById":
			for _, part := range strings.Split(arg, ",") {
				lo, hi, ok := idRange(part)
				if !ok {
					drop("ctl:" + c + ": not an ID or range")
					continue
				}
				if lo >= 1_000_000 {
					drop("ctl:" + c + ": the plugin's own rules")
					continue
				}
				add(nil, lo, hi)
			}
		case "ruleRemoveByTag":
			ids := tags[arg]
			if len(ids) == 0 {
				drop("ctl:" + c + ": no CRS rule has the tag")
				continue
			}
			for _, rg := range ranges(universe, ids) {
				add(nil, rg[0], rg[1])
			}
		case "ruleRemoveTargetById", "ruleRemoveTargetByTag":
			which, tgt, ok := strings.Cut(arg, ";")
			t, tok := pluginTarget(tgt)
			if !ok || !tok {
				drop("ctl:" + c + ": no Strata target for " + tgt)
				continue
			}
			if op == "ruleRemoveTargetById" {
				lo, hi, ok := idRange(which)
				if !ok {
					drop("ctl:" + c + ": not an ID or range")
					continue
				}
				add(t, lo, hi)
				continue
			}
			ids := tags[which]
			if len(ids) == 0 {
				drop("ctl:" + c + ": no CRS rule has the tag")
				continue
			}
			for _, rg := range ranges(universe, ids) {
				add(t, rg[0], rg[1])
			}
		default:
			return nil, "ctl:" + op + " (only rule and target removals are imported)"
		}
	}
	if len(widen) == 1 {
		conds = append(conds, widen[0]["condition"])
		add(nil, widen[0]["rule"].(int), widen[0]["rule"].(int))
	}
	if len(order) == 0 {
		return nil, "nothing left to remove"
	}
	var exclude []any
	for _, k := range order {
		exclude = append(exclude, byTarget[k])
	}
	for _, n := range notes {
		res.Imported.Notes = append(res.Imported.Notes, Note{Rule: r.ID, Text: n})
	}
	return map[string]any{
		"id": r.ID, "name": fmt.Sprintf("%s plugin exclusion %d", p.Name, r.ID), "layer": "pre", "stage": stage,
		"match": map[string]any{"all": conds}, "score": 0, "severity": "notice",
		"exclude": exclude,
		"metadata": map[string]any{
			"source": "crs-plugin", "plugin": p.Name, "license": "Apache-2.0",
			"upstream_id": strconv.Itoa(r.ID), "upstream_version": p.Version,
			"author": "OWASP CRS project",
		},
	}, ""
}

// idRange reads "920100" or "920100-920199".
func idRange(s string) (int, int, bool) {
	a, b, isRange := strings.Cut(strings.TrimSpace(s), "-")
	lo, err := strconv.Atoi(a)
	if err != nil || lo <= 0 {
		return 0, 0, false
	}
	if !isRange {
		return lo, lo, true
	}
	hi, err := strconv.Atoi(b)
	if err != nil || hi < lo {
		return 0, 0, false
	}
	return lo, hi, true
}

// ReadPluginLock reads crs-plugins.lock ("name version sha256" lines);
// each plugin is at <dir>/<name>-<version>.
func ReadPluginLock(lock, dir string) ([]Plugin, error) {
	src, err := os.ReadFile(lock)
	if err != nil {
		return nil, err
	}
	var out []Plugin
	for _, line := range strings.Split(string(src), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("%s: bad line %q", lock, line)
		}
		out = append(out, Plugin{Name: f[0], Version: f[1], Dir: filepath.Join(dir, f[0]+"-"+f[1])})
	}
	return out, nil
}

// CompilePlugin compiles a plugin's IR with a policy that runs it.
func CompilePlugin(compiler, irFile, name string) error {
	dir, err := os.MkdirTemp("", "strata-plugin-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	key := filepath.Join(dir, "key")
	_ = os.WriteFile(key, bytes.Repeat([]byte{7}, 32), 0o600)
	pol := filepath.Join(dir, "policies.json")
	_ = os.WriteFile(pol, []byte(`{"policies":[{"name":"import-check","mode":"shadow","crs_plugins":["`+name+`"]}]}`), 0o644)
	var stderr bytes.Buffer
	cmd := exec.Command(compiler, "--rules", irFile, "--policies", pol, "--key", key, "--version", "1",
		"--created-at", "1", "--out", filepath.Join(dir, "b.sbn"))
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: strata-compile: %s", name, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// PluginReport writes the import report of the plugins.
func PluginReport(w io.Writer, plugins []Plugin, results []*PluginResult) {
	fmt.Fprintf(w, "# CRS plugin import report\n\nGenerated by `make crs-plugins-import` (`strata-import-crs plugins`, W17-S-01): the CRS rule exclusion plugins pinned in `tools/strata-import-crs/crs-plugins.lock`, as exclusion rules in `rules/crs-plugins/` (one file per plugin). A policy runs a plugin when it lists it in `crs_plugins`. Tags (`OWASP_CRS`, `attack-sqli`...) are expanded into ranges of the CRS rule IDs that carry them.\n\n")
	fmt.Fprintf(w, "| Plugin | Version | Rules | Imported | Rate | go-ftw tests (converted) |\n| --- | --- | ---: | ---: | ---: | ---: |\n")
	for i, r := range results {
		im := r.Imported
		fmt.Fprintf(w, "| %s | %s | %d | %d | %.0f%% | %d (%d) |\n", plugins[i].Name, plugins[i].Version, im.Read, len(im.Rules), 100*float64(len(im.Rules))/float64(max(im.Read, 1)), r.TestsRead, r.TestsRead-r.TestsSkipped)
	}
	fmt.Fprintf(w, "\nThe converted tests are in `corpus/crs-plugins-ftw/`; `make test-crs-plugins` runs them (`docs/crs-plugins-ftw-report.md`).\n")
	fmt.Fprintf(w, "\n## Rules left out\n\n| Plugin | File | Rule | Reason |\n| --- | --- | --- | --- |\n")
	for i, r := range results {
		for _, s := range r.Skipped {
			id := "—"
			if s.Rule != 0 {
				id = strconv.Itoa(s.Rule)
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n", plugins[i].Name, s.Group, id, strings.ReplaceAll(s.Reason, "|", "\\|"))
		}
	}
	fmt.Fprintf(w, "\n## Changes to imported rules\n\n| Plugin | Rule | Change |\n| --- | ---: | --- |\n")
	for i, r := range results {
		for _, n := range r.Imported.Notes {
			fmt.Fprintf(w, "| %s | %d | %s |\n", plugins[i].Name, n.Rule, strings.ReplaceAll(n.Text, "|", "\\|"))
		}
	}
	fmt.Fprintf(w, "\n## Removals left out of imported rules\n\n| Plugin | Rule | Removal |\n| --- | ---: | --- |\n")
	for i, r := range results {
		for _, d := range r.Dropped {
			fmt.Fprintf(w, "| %s | %d | %s |\n", plugins[i].Name, d.Rule, strings.ReplaceAll(d.Text, "|", "\\|"))
		}
	}
}

// gateSingle: the variables with exactly one value in every request, whose
// gate conditions negate exactly
var gateSingle = map[string]bool{
	"method": true, "protocol": true, "body_processor": true, "path": true, "uri": true,
	"uri_raw": true, "basename": true, "query_string": true, "request_line": true,
}

// gate: a skipAfter rule of the plugin, over until its marker. cond is
// the condition the gated rules get (the gate's, negated); nil: they are
// left out with reason.
type gate struct {
	from   int
	phase  string
	until  int // line of the marker
	cond   map[string]any
	reason string
}

var markerLine = regexp.MustCompile(`^\s*SecMarker\s+"?([^"\s]+)"?`)

// secMarkers: marker name -> its lines, in order.
func secMarkers(text string) map[string][]int {
	out := map[string][]int{}
	for i, line := range strings.Split(text, "\n") {
		if m := markerLine.FindStringSubmatch(line); m != nil {
			out[m[1]] = append(out[m[1]], i+1)
		}
	}
	return out
}

var setvarTx = regexp.MustCompile(`setvar:'?tx\.([^=']+)=([^']*)'?`)

// pluginConfig reads the tx.* defaults the plugin's *-config.conf sets.
func pluginConfig(files []string) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range files {
		if !strings.HasSuffix(f, "-config.conf") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range setvarTx.FindAllStringSubmatch(line, -1) {
				out[strings.ToLower(m[1])] = m[2]
			}
		}
	}
	return out, nil
}

// newGate reads a skipAfter rule. A SecAction always skips; a condition on
// a plugin option (TX:...) is decided with the plugin's defaults; any
// other condition must be one the IR can negate exactly (skipGate), else
// the gated rules are left out.
func newGate(r seclang.Rule, markers map[string][]int, config map[string]string, dataDir string) (*gate, error) {
	until := 0
	for _, l := range markers[r.SkipAfter] {
		if l > r.Line {
			until = l
			break
		}
	}
	if until == 0 {
		return nil, fmt.Errorf("no SecMarker %s after it", r.SkipAfter)
	}
	g := &gate{from: r.ID, phase: r.Phase, until: until}
	if r.Directive == "SecAction" {
		g.reason = fmt.Sprintf("skipped by SecAction %d (skipAfter %s)", r.ID, r.SkipAfter)
		return g, nil
	}
	if len(r.Chain) == 1 && len(r.Chain[0].Variables) == 1 {
		v := r.Chain[0].Variables[0]
		if name, ok := strings.CutPrefix(strings.ToLower(v), "tx:"); ok {
			l := r.Chain[0]
			value, set := config[name]
			var holds bool
			switch l.Operator {
			case "streq":
				holds = set && value == l.Argument
			default:
				return nil, fmt.Errorf("option gate @%s", l.Operator)
			}
			if holds == l.Negated {
				return nil, nil // the default does not skip
			}
			g.reason = fmt.Sprintf("skipped by default: rule %d, option tx.%s=%s (skipAfter %s)", r.ID, name, value, r.SkipAfter)
			return g, nil
		}
	}
	if c := negateGate(r, dataDir, gateSingle); c != nil {
		g.cond = c
		return g, nil
	}
	g.reason = fmt.Sprintf("gated by rule %d under a condition the IR cannot negate exactly", r.ID)
	return g, nil
}

// listOption: setvar:'tx.allowed_methods=%{tx.allowed_methods} PUT PATCH'
// and the same for allowed_request_content_type (|text/plain| ...).
// widenIDOffset: the ID of the exclusion rule split off for a list option
const widenIDOffset = 100_000

var listOption = regexp.MustCompile(`(?i)^tx\.(allowed_methods|allowed_request_content_type)=%\{tx\.(allowed_methods|allowed_request_content_type)\}\s*(.*)$`)

// widenCondition: for a CRS list option extended with values, the
// condition "the request has one of them" and the rule that checks the
// list (911100 methods, 920420 content types: the same matching as their
// IR in rules/crs).
func widenCondition(option, values string) (map[string]any, bool) {
	var alts []string
	for _, v := range strings.Fields(values) {
		v = strings.Trim(v, "|")
		if v == "" {
			continue
		}
		alts = append(alts, regexp.QuoteMeta(v))
	}
	if len(alts) == 0 {
		return nil, false
	}
	alt := strings.Join(alts, "|")
	switch option {
	case "allowed_methods":
		return map[string]any{"rule": 911100, "condition": map[string]any{
			"targets":  []map[string]any{{"var": "method"}},
			"operator": map[string]any{"type": "rx", "value": "^(?:" + alt + ")$"},
		}}, true
	case "allowed_request_content_type":
		return map[string]any{"rule": 920420, "condition": map[string]any{
			"targets":    []map[string]any{{"var": "request_headers", "key": "Content-Type"}},
			"transforms": []string{"lowercase"},
			"operator":   map[string]any{"type": "rx", "value": "^(?:" + strings.ToLower(alt) + ")(?:[;\\s]|$)"},
		}}, true
	}
	return nil, false
}

// optionOff: plugin rules lo..hi a plugin option turns off by default
type optionOff struct {
	lo, hi int
	by     string
}

func offBy(off []optionOff, id int) string {
	for _, o := range off {
		if id >= o.lo && id <= o.hi {
			return "off by default: " + o.by
		}
	}
	return ""
}

// optionGate reads a rule "TX:option @eq N" (or &TX:option) whose actions
// only remove the plugin's own rules. ok is false for any other rule.
// When the condition holds with the plugin's defaults, the rules it
// removes are returned: they are left out (a policy cannot set plugin
// options; their default is kept).
func optionGate(r seclang.Rule, config map[string]string) ([]optionOff, string, bool) {
	if r.Directive != "SecRule" || len(r.Chain) != 1 || len(r.Chain[0].Variables) != 1 {
		return nil, "", false
	}
	l := r.Chain[0]
	v := l.Variables[0]
	count := strings.HasPrefix(v, "&")
	name, isTX := strings.CutPrefix(strings.ToLower(strings.TrimPrefix(v, "&")), "tx:")
	if !isTX || l.Operator != "eq" || len(l.Ctls) == 0 {
		return nil, "", false
	}
	if strings.HasSuffix(name, "-rule-exclusions-plugin_enabled") {
		return nil, "plugin switch: a policy runs the plugin with crs_plugins", true
	}
	want, err := strconv.Atoi(strings.TrimSpace(l.Argument))
	if err != nil {
		return nil, "", false
	}
	var ranges []optionOff
	for _, c := range l.Ctls {
		arg, ok := strings.CutPrefix(c, "ruleRemoveById=")
		if !ok {
			return nil, "", false
		}
		lo, hi, ok := idRange(arg)
		if !ok || lo < 1_000_000 {
			return nil, "", false
		}
		ranges = append(ranges, optionOff{lo: lo, hi: hi})
	}
	value, set := config[name]
	got := 0
	if count {
		if set {
			got = 1
		}
	} else {
		got, _ = strconv.Atoi(value)
	}
	state := fmt.Sprintf("tx.%s=%s", name, value)
	if !set {
		state = fmt.Sprintf("tx.%s not set", name)
	}
	if (got == want) == l.Negated {
		return nil, fmt.Sprintf("plugin option gate (%s by default: nothing turned off)", state), true
	}
	by := fmt.Sprintf("rule %d (%s by default)", r.ID, state)
	for i := range ranges {
		ranges[i].by = by
	}
	return ranges, fmt.Sprintf("plugin option gate: turns plugin rules off by default (%s)", state), true
}
