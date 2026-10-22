package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/rulesets"
)

// RS-3 (docs/plan/rule-sets.md): the rule sets a policy gives an action,
// built in and custom (RS-3c), with the rules of the configured catalog
// each one holds.

// RuleSetInfo is one set of GET /v1/rule-sets.
type RuleSetInfo struct {
	Name  string            `json:"name"`
	Group string            `json:"group"`
	Class string            `json:"class,omitempty"`
	Title map[string]string `json:"title"`
	Match rulesets.Filter   `json:"match"`
	// RuleCount: rules of the configured catalog in the set; absent while
	// the catalog is unavailable.
	RuleCount *int `json:"rule_count,omitempty"`
	// Matches24h (RS-4b): matches of the set's rules over the last 24
	// hours (an event matching two rules of the set counts twice), of
	// ?policy= only when given; absent when the caller may not read events
	// or the event store does not count.
	Matches24h *uint64 `json:"matches_24h,omitempty"`
	// Custom set (RS-3c): group "custom", and the stored details.
	Custom      bool   `json:"custom,omitempty"`
	Description string `json:"description,omitempty"`
	Version     int    `json:"version,omitempty"`
	Etag        string `json:"etag,omitempty"`
	UpdatedBy   string `json:"updated_by,omitempty"`
}

// RuleSetRule is one rule of GET /v1/rule-sets/{name}/rules.
type RuleSetRule struct {
	rulecat.Entry
	Tags []string `json:"tags,omitempty"`
}

func (s *Server) registerRuleSets(mux *http.ServeMux) {
	mux.HandleFunc("/v1/rule-sets", auth.RequireHTTP(auth.PermPoliciesRead, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			s.createCustomSet(w, r)
			return
		}
		s.ruleSetList(w, r)
	}))
	mux.HandleFunc("/v1/rule-sets/", auth.RequireHTTP(auth.PermPoliciesRead, s.ruleSetRules))
	mux.HandleFunc("/v1/rule-sets:resolve", auth.RequireHTTP(auth.PermPoliciesRead, s.ruleSetResolve))
}

// currentCatalog: the configured catalog, nil while unavailable.
func (s *Server) currentCatalog() *rulecat.Catalog {
	if s.cfg.RuleCatalog == nil {
		return nil
	}
	value, _, _ := s.cfg.RuleCatalog.Current()
	return value
}

func inSet(set rulesets.Set, c *rulecat.Catalog, e rulecat.Entry) bool {
	return set.Match.Matches(e.ID, e.Source, e.AttackType, c.Tags(e.ID))
}

func (s *Server) ruleSetList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	catalog := s.currentCatalog()
	var entries []rulecat.Entry
	if catalog != nil {
		entries = catalog.Entries()
	}
	policyName := r.URL.Query().Get("policy")
	if len(policyName) > 256 {
		writeError(w, http.StatusBadRequest, "invalid policy", "")
		return
	}
	var counts map[uint32]uint64
	if store, ok := s.handler.store.(ingest.RuleCountStore); ok && catalog != nil && auth.FromContext(r.Context()).Can(auth.PermEventsRead) {
		to := time.Now().UTC()
		if c, err := store.RuleCounts(r.Context(), policyName, to.Add(-24*time.Hour), to); err == nil {
			counts = c
		} else {
			log.Printf("[WARN] rule sets: rule counts: %v", err)
		}
	}
	all := []RuleSetInfo{}
	for _, set := range rulesets.All() {
		all = append(all, RuleSetInfo{Name: set.Name, Group: set.Group, Class: set.Class, Title: set.Title, Match: set.Match})
	}
	if s.cfg.CustomRuleSets != nil {
		custom, err := s.cfg.CustomRuleSets.ListCustomRuleSets(r.Context())
		if err != nil {
			customSetError(w, err)
			return
		}
		for _, c := range custom {
			set := customSet(c)
			all = append(all, RuleSetInfo{Name: set.Name, Group: set.Group, Title: set.Title, Match: set.Match,
				Custom: true, Description: c.Description, Version: c.Version, Etag: c.Etag, UpdatedBy: c.UpdatedBy})
		}
	}
	out := []RuleSetInfo{}
	for _, info := range all {
		set := rulesets.Set{Name: info.Name, Match: info.Match}
		if catalog != nil {
			n, matches := 0, uint64(0)
			for _, e := range entries {
				if inSet(set, catalog, e) {
					n++
					matches += counts[e.ID]
				}
			}
			info.RuleCount = &n
			if counts != nil {
				info.Matches24h = &matches
			}
		}
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sets": out, "catalog_available": catalog != nil})
}

// ruleSetRules: GET /v1/rule-sets/{name}/rules?q=&after=, by Rule ID, 200 a
// page; next_cursor 0: the last page. /v1/rule-sets/{name} alone: a
// custom set (customSetItem).
func (s *Server) ruleSetRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	name, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/rule-sets/"), "/")
	if !ok {
		s.customSetItem(w, r, name)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if rest != "rules" {
		writeError(w, http.StatusNotFound, "not found", "")
		return
	}
	set, ok, err := s.lookupSet(r.Context(), name)
	if err != nil {
		customSetError(w, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "rule set not found", "")
		return
	}
	q := r.URL.Query()
	after, err := strconv.ParseUint("0"+q.Get("after"), 10, 32)
	query := strings.ToLower(strings.TrimSpace(q.Get("q")))
	if err != nil || len(query) > 64 {
		writeError(w, http.StatusBadRequest, "invalid rule set query", "")
		return
	}
	catalog := s.currentCatalog()
	if catalog == nil {
		writeError(w, http.StatusServiceUnavailable, "configured catalog unavailable", "")
		return
	}
	const page = 200
	rules := []RuleSetRule{}
	total, next := 0, uint32(0)
	for _, e := range catalog.Entries() {
		if !inSet(set, catalog, e) {
			continue
		}
		if query != "" && !strings.Contains(strconv.FormatUint(uint64(e.ID), 10), query) && !strings.Contains(strings.ToLower(e.Name), query) {
			continue
		}
		total++
		if e.ID <= uint32(after) {
			continue
		}
		if len(rules) == page {
			next = rules[len(rules)-1].ID
			continue
		}
		rules = append(rules, RuleSetRule{Entry: e, Tags: catalog.Tags(e.ID)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"set": set.Name, "rules": rules, "total": total, "next_cursor": next})
}

// RuleActionsDraft is the body of POST /v1/rule-sets:resolve: the part of a
// policy spec, saved or not, that decides what each rule does.
type RuleActionsDraft struct {
	CRSParanoia       int                   `json:"crs_paranoia,omitempty"`
	CRSParanoiaShadow int                   `json:"crs_paranoia_shadow,omitempty"`
	RuleSets          []policy.RuleSetRef   `json:"rule_sets,omitempty"`
	RuleOverrides     []policy.RuleOverride `json:"rule_overrides,omitempty"`
}

// EffectiveRule is one rule of POST /v1/rule-sets:resolve.
type EffectiveRule struct {
	RuleSetRule
	// Action: off (not run), log (reported, never blocks), block (blocks
	// alone) or score (adds to the anomaly score, as the rule does).
	Action string `json:"action"`
	// Own: what the rule does without sets and overrides at the draft's
	// paranoia levels (signature pack: log; others: score).
	Own string `json:"own"`
	// Source of Action: rule, paranoia, set or override.
	Source string `json:"source"`
	Set    string `json:"set,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// effective: what rule e does under d, as the engine runs it (RS-1): the
// paranoia level first (above the run level: not run; above the enforced
// level: log, unless an override says off), then the overrides, then the
// sets (a later one wins), then the rule's own behaviour.
func effective(c *rulecat.Catalog, e rulecat.Entry, d RuleActionsDraft) EffectiveRule {
	out := EffectiveRule{RuleSetRule: RuleSetRule{Entry: e, Tags: c.Tags(e.ID)}, Own: "score", Source: "rule"}
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
		if ok && inSet(def, c, e) {
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

// ruleSetResolve: POST /v1/rule-sets:resolve?q=&after=&changed=1, the
// effective action of every detection rule of the configured catalog
// under a draft, by Rule ID, 200 a page; changed=1 keeps the rules whose
// action is not their own. counts: of every rule, whatever q and changed.
func (s *Server) ruleSetResolve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var d RuleActionsDraft
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid JSON", "")
		return
	}
	// a custom set without its copy (just added in the editor): its
	// current filter, as saving the policy would copy it
	for i, ref := range d.RuleSets {
		if !rulesets.IsCustom(ref.Set) || ref.Match != nil {
			continue
		}
		set, ok, err := s.lookupSet(r.Context(), ref.Set)
		if err != nil {
			customSetError(w, err)
			return
		}
		if !ok {
			writeError(w, http.StatusBadRequest, "rule set "+strconv.Quote(ref.Set)+" does not exist", "")
			return
		}
		match := set.Match
		d.RuleSets[i].Match = &match
	}
	spec := policy.Spec{Mode: "shadow", CRSParanoia: d.CRSParanoia, CRSParanoiaShadow: d.CRSParanoiaShadow, RuleSets: d.RuleSets, RuleOverrides: d.RuleOverrides}
	if err := spec.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	q := r.URL.Query()
	after, err := strconv.ParseUint("0"+q.Get("after"), 10, 32)
	query := strings.ToLower(strings.TrimSpace(q.Get("q")))
	changed := q.Get("changed") == "1"
	if err != nil || len(query) > 64 {
		writeError(w, http.StatusBadRequest, "invalid rule query", "")
		return
	}
	catalog := s.currentCatalog()
	if catalog == nil {
		writeError(w, http.StatusServiceUnavailable, "configured catalog unavailable", "")
		return
	}
	const page = 200
	rules := []EffectiveRule{}
	counts := map[string]int{"off": 0, "log": 0, "block": 0, "score": 0}
	total, next := 0, uint32(0)
	for _, e := range catalog.Entries() {
		if e.Plugin != "" {
			continue // CRS plugin exclusions, not detection rules
		}
		eff := effective(catalog, e, d)
		counts[eff.Action]++
		if changed && eff.Action == eff.Own {
			continue
		}
		if query != "" && !strings.Contains(strconv.FormatUint(uint64(e.ID), 10), query) && !strings.Contains(strings.ToLower(e.Name), query) {
			continue
		}
		total++
		if e.ID <= uint32(after) {
			continue
		}
		if len(rules) == page {
			next = rules[len(rules)-1].ID
			continue
		}
		rules = append(rules, eff)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "total": total, "next_cursor": next, "counts": counts})
}
