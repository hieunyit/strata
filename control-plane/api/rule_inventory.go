package api

import (
	"context"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/rulehealth"
	"github.com/strata/strata/control-plane/ruleinventory"
	"github.com/strata/strata/control-plane/rulesets"
	"github.com/strata/strata/control-plane/store"
)

var catalogDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (s *Server) registerRuleInventory(mux *http.ServeMux) {
	mux.HandleFunc("/v1/rule-catalog", auth.RequireHTTP(auth.PermPoliciesRead, s.catalogList))
	mux.HandleFunc("/v1/rule-catalog/", auth.RequireHTTP(auth.PermPoliciesRead, s.catalogRule))
	mux.HandleFunc("/v1/rule-catalogs", auth.RequireHTTP(auth.PermPoliciesRead, s.catalogHistory))
	mux.HandleFunc("/v1/rule-catalogs:diff", auth.RequireHTTP(auth.PermPoliciesRead, s.catalogDiff))
	mux.HandleFunc("/v1/exceptions", auth.RequireHTTP(auth.PermPoliciesRead, s.exceptionInventory))
	mux.HandleFunc("/v1/exceptions:cleanupExpired", auth.RequireHTTP(auth.PermExceptionsWrite, s.exceptionLifecycleDraft))
	mux.HandleFunc("/v1/exceptions:revoke", auth.RequireHTTP(auth.PermExceptionsWrite, s.exceptionLifecycleDraft))
}
func (s *Server) configuredCatalog(w http.ResponseWriter, r *http.Request) (*rulecat.Catalog, time.Time, bool) {
	if s.cfg.RuleCatalog == nil {
		writeError(w, 503, "configured catalog unavailable", "")
		return nil, time.Time{}, false
	}
	value, at, stale := s.cfg.RuleCatalog.Current()
	if value == nil {
		writeError(w, 503, "configured catalog unavailable", "")
		return nil, at, false
	}
	return value, at, stale
}
func (s *Server) catalogList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	value, at, stale := s.configuredCatalog(w, r)
	if value == nil {
		return
	}
	q := r.URL.Query()
	after, err := strconv.ParseUint("0"+q.Get("after"), 10, 32)
	source, cve, attack := q.Get("source"), strings.ToUpper(q.Get("cve")), q.Get("attack_type")
	text := strings.ToLower(strings.TrimSpace(q.Get("q")))
	if err != nil || len(source) > 64 || len(cve) > 32 || len(attack) > 64 || len(text) > 64 {
		writeError(w, 400, "invalid catalog filter", "")
		return
	}
	// RS-4b: the rules of a built-in set, and a search by Rule ID or name
	var set *rulesets.Set
	if name := q.Get("set"); name != "" {
		found, ok := rulesets.Get(name)
		if !ok {
			writeError(w, 400, "unknown rule set", "")
			return
		}
		set = &found
	}
	all := rulesets.All()
	entries, next, matched := value.SearchFunc(uint32(after), 200, func(v rulecat.Entry) bool {
		if source != "" && v.Source != source || attack != "" && v.AttackType != attack || cve != "" && !slices.Contains(v.CVEs, cve) {
			return false
		}
		if set != nil && !inSet(*set, value, v) {
			return false
		}
		return text == "" || strings.Contains(strconv.FormatUint(uint64(v.ID), 10), text) || strings.Contains(strings.ToLower(v.Name), text)
	})
	rows := make([]catalogRow, 0, len(entries))
	for _, e := range entries {
		row := catalogRow{Entry: e}
		for _, s := range all {
			if inSet(s, value, e) {
				row.Sets = append(row.Sets, s.Name)
			}
		}
		rows = append(rows, row)
	}
	sources, attackTypes := value.Facets()
	writeJSON(w, 200, map[string]any{"rules": rows, "next_cursor": next, "digest": value.Digest(), "at": at, "stale": stale, "source": "configured_catalog", "total": value.Len(),
		"matched": matched, "facets": map[string]any{"sources": sources, "attack_types": attackTypes}})
}

// catalogRow: a rule of GET /v1/rule-catalog and the built-in rule sets
// it is in (RS-4b).
type catalogRow struct {
	rulecat.Entry
	Sets []string `json:"sets,omitempty"`
}

func (s *Server) catalogHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	rows, err := s.cfg.Applications.CatalogHistory(r.Context())
	if err != nil {
		investigationError(w, err)
		return
	}
	if rows == nil {
		rows = []store.CatalogSnapshot{}
	}
	writeJSON(w, 200, map[string]any{"catalogs": rows})
}
func (s *Server) catalogDiff(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	q := r.URL.Query()
	from, to := q.Get("from"), q.Get("to")
	after, err := strconv.ParseUint("0"+q.Get("after"), 10, 32)
	if err != nil || !catalogDigest.MatchString(from) || !catalogDigest.MatchString(to) {
		writeError(w, 400, "two catalog digests required", "")
		return
	}
	before, err := s.cfg.Applications.CatalogEntries(r.Context(), from)
	if err != nil {
		investigationError(w, err)
		return
	}
	current, err := s.cfg.Applications.CatalogEntries(r.Context(), to)
	if err != nil {
		investigationError(w, err)
		return
	}
	writeJSON(w, 200, rulecat.Diff(before, current, uint32(after), 200))
}
func (s *Server) catalogRule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	value, _, _ := s.configuredCatalog(w, r)
	if value == nil {
		return
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/v1/rule-catalog/"), 10, 32)
	if err != nil || id == 0 {
		writeError(w, 400, "rule ID required", "")
		return
	}
	rule, ok := value.For([]uint32{uint32(id)})[strconv.FormatUint(id, 10)]
	if !ok {
		writeError(w, 404, "configured rule not found", "")
		return
	}
	app, env := r.URL.Query().Get("application_id"), r.URL.Query().Get("environment_id")
	usage, err := ruleinventory.Usage(r.Context(), s.cfg.Applications, rulecat.Entry{ID: uint32(id), Rule: rule}, app, env)
	if err != nil {
		investigationError(w, err)
		return
	}
	bounded, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ctx, err := s.cfg.Applications.ApplicationEventScope(bounded, app, env, auth.FromContext(r.Context()))
	if err != nil {
		investigationError(w, err)
		return
	}
	var measured *rulehealth.Health
	status := "unavailable"
	if s.cfg.Health != nil {
		to := time.Now().UTC()
		health, err := s.cfg.Health.Read(ctx, uint32(id), "", to.Add(-24*time.Hour), to)
		if err == nil {
			measured = &health
			status = "available"
		}
	}
	writeJSON(w, 200, map[string]any{"rule": rulecat.Entry{ID: uint32(id), Rule: rule}, "usage": usage, "health": measured, "health_status": status})
}
func (s *Server) exceptionInventory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	var catalog *rulecat.Catalog
	if s.cfg.RuleCatalog != nil {
		catalog, _, _ = s.cfg.RuleCatalog.Current()
	}
	q := r.URL.Query()
	if len(q.Get("after")) > 256 {
		writeError(w, 400, "invalid exception cursor", "")
		return
	}
	out, err := ruleinventory.Exceptions(r.Context(), s.cfg.Applications, catalog, q.Get("application_id"), q.Get("environment_id"), q.Get("after"), time.Now().UTC())
	if err != nil {
		investigationError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
