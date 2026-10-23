// Package ruleactions tells what each rule of the configured catalog does
// in a policy (RS-3b, RS-5, docs/plan/rule-sets.md), as the engine runs it
// (libstrata RS-1): the paranoia level first (above the run level: not
// run; above the enforced level: log, unless an override says off), then
// the overrides, then the rule sets (a later one wins), then the rule's
// own behaviour. The API resolves a draft with it; the replay of a policy
// version lists the rules whose action it changes.
package ruleactions

import (
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/rulesets"
)

// Draft: the part of a policy spec that decides what each rule does.
type Draft struct {
	CRSParanoia       int
	CRSParanoiaShadow int
	RuleSets          []policy.RuleSetRef
	RuleOverrides     []policy.RuleOverride
}

// Of the spec s.
func Of(s policy.Spec) Draft {
	return Draft{CRSParanoia: s.CRSParanoia, CRSParanoiaShadow: s.CRSParanoiaShadow, RuleSets: s.RuleSets, RuleOverrides: s.RuleOverrides}
}

// Result: what a rule does.
type Result struct {
	// Action: off (not run), log (reported, never blocks), block (blocks
	// alone) or score (adds to the anomaly score, as the rule does).
	Action string
	// Own: what the rule does without sets and overrides at the draft's
	// paranoia levels (signature pack: log; others: score).
	Own string
	// Source of Action: rule, paranoia, set or override.
	Source string
	Set    string
	Reason string
}

// InSet: rule e of catalog c is in set.
func InSet(set rulesets.Set, c *rulecat.Catalog, e rulecat.Entry) bool {
	return set.Match.Matches(e.ID, e.Source, e.AttackType, c.Tags(e.ID))
}

// Detection: e is a detection rule (CRS plugin rules are exclusions).
func Detection(e rulecat.Entry) bool { return e.Plugin == "" }

// Resolve what rule e of catalog c does under d. A custom set is read from
// its copy (RuleSetRef.Match); one without matches nothing.
func Resolve(c *rulecat.Catalog, e rulecat.Entry, d Draft) Result {
	out := Result{Own: "score", Source: "rule"}
	if e.Pack == "signature" {
		out.Own = "log"
	}
	enforce := max(d.CRSParanoia, 1)
	run := max(d.CRSParanoiaShadow, enforce)
	switch {
	case e.Paranoia > run:
		out.Own, out.Source = "off", "paranoia"
	case e.Paranoia > enforce:
		out.Own, out.Source = "log", "paranoia"
	}
	out.Action = out.Own
	chosen, source, set, reason := "default", "", "", ""
	for _, r := range d.RuleSets {
		def, ok := rulesets.Get(r.Set)
		if r.Match != nil {
			def, ok = rulesets.Set{Name: r.Set, Match: *r.Match}, true
		}
		if ok && InSet(def, c, e) {
			chosen, source, set = r.Action, "set", r.Set
		}
	}
	for _, o := range d.RuleOverrides {
		if o.Rule == e.ID {
			chosen, source, set, reason = o.Action, "override", "", o.Reason
		}
	}
	// a rule its level does not run stays off; one it runs in shadow can
	// still be switched off, not made to block
	if chosen == "default" || (out.Source == "paranoia" && (out.Own == "off" || chosen != "off")) {
		return out
	}
	out.Action, out.Source, out.Set, out.Reason = chosen, source, set, reason
	return out
}

// Change: a rule whose action differs between two drafts.
type Change struct {
	Rule uint32 `json:"rule"`
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
	// Source and Set of To (rule, paranoia, set, override).
	Source string `json:"source"`
	Set    string `json:"set,omitempty"`
}

// MaxChanges listed; Changes counts them all.
const MaxChanges = 200

// Changes: the detection rules of c whose action differs from from to to,
// by Rule ID (at most MaxChanges), and how many there are.
func Changes(c *rulecat.Catalog, from, to Draft) ([]Change, int) {
	out, n := []Change{}, 0
	for _, e := range c.Entries() {
		if !Detection(e) {
			continue
		}
		a, b := Resolve(c, e, from), Resolve(c, e, to)
		if a.Action == b.Action {
			continue
		}
		n++
		if len(out) < MaxChanges {
			out = append(out, Change{Rule: e.ID, Name: e.Name, From: a.Action, To: b.Action, Source: b.Source, Set: b.Set})
		}
	}
	return out, n
}
