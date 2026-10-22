package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/rulesets"
)

// RS-3 (docs/plan/rule-sets.md): the built-in rule sets a policy gives an
// action, with the rules of the configured catalog each one holds.

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
}

// RuleSetRule is one rule of GET /v1/rule-sets/{name}/rules.
type RuleSetRule struct {
	rulecat.Entry
	Tags []string `json:"tags,omitempty"`
}

func (s *Server) registerRuleSets(mux *http.ServeMux) {
	mux.HandleFunc("/v1/rule-sets", auth.RequireHTTP(auth.PermPoliciesRead, s.ruleSetList))
	mux.HandleFunc("/v1/rule-sets/", auth.RequireHTTP(auth.PermPoliciesRead, s.ruleSetRules))
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
	out := []RuleSetInfo{}
	for _, set := range rulesets.All() {
		info := RuleSetInfo{Name: set.Name, Group: set.Group, Class: set.Class, Title: set.Title, Match: set.Match}
		if catalog != nil {
			n := 0
			for _, e := range entries {
				if inSet(set, catalog, e) {
					n++
				}
			}
			info.RuleCount = &n
		}
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sets": out, "catalog_available": catalog != nil})
}

// ruleSetRules: GET /v1/rule-sets/{name}/rules?q=&after=, by Rule ID, 200 a
// page; next_cursor 0: the last page.
func (s *Server) ruleSetRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	name, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/rule-sets/"), "/")
	if !ok || rest != "rules" {
		writeError(w, http.StatusNotFound, "not found", "")
		return
	}
	set, ok := rulesets.Get(name)
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
