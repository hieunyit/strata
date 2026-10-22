package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/ruleinventory"
)

const ruleSetIR = `ir_version: 1
ruleset: { name: example, version: "1" }
rules:
  - { id: 500901, name: Example scanner bot, layer: managed, metadata: { source: crawler-user-agents, attack_type: bot, tags: [scanner] } }
  - { id: 500902, name: Example search bot, layer: managed, metadata: { source: crawler-user-agents, attack_type: bot, tags: [search-engine] } }
  - { id: 942100, name: SQL injection via libinjection, layer: managed, metadata: { source: crs, attack_type: sql-injection } }
  - { id: 942200, name: SQL injection level 2, layer: managed, paranoia_level: 2, metadata: { source: crs, attack_type: sql-injection } }
  - { id: 942300, name: SQL injection level 3, layer: managed, paranoia_level: 3, metadata: { source: crs, attack_type: sql-injection } }
  - { id: 9507100, name: Example plugin exclusion, layer: pre, metadata: { source: crs, plugin: wordpress } }
`

func ruleSetServer(t *testing.T, withCatalog bool) *Server {
	t.Helper()
	cfg := ServerConfig{Auth: tokenRoles{}}
	if withCatalog {
		f := filepath.Join(t.TempDir(), "rules.yaml")
		if err := os.WriteFile(f, []byte(ruleSetIR), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := rulecat.Load([]string{f})
		if err != nil {
			t.Fatal(err)
		}
		cfg.RuleCatalog = ruleinventory.Static(c)
	}
	return NewServer(cfg, ingest.NewMockEventStore())
}

func getRuleSets(t *testing.T, s *Server, path string, out any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer viewer")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatal(err)
		}
	}
	return rec.Code
}

func TestRuleSetsCountTheConfiguredRules(t *testing.T) {
	s := ruleSetServer(t, true)
	var list struct {
		Sets      []RuleSetInfo `json:"sets"`
		Available bool          `json:"catalog_available"`
	}
	if c := getRuleSets(t, s, "/v1/rule-sets", &list); c != http.StatusOK || !list.Available || len(list.Sets) < 10 {
		t.Fatalf("%d %+v", c, list)
	}
	counts := map[string]int{}
	for _, set := range list.Sets {
		if set.RuleCount == nil {
			t.Fatalf("%s: no count", set.Name)
		}
		counts[set.Name] = *set.RuleCount
	}
	if counts["bots-scanners"] != 1 || counts["bots-trusted"] != 1 || counts["attack-sqli"] != 3 || counts["attack-xss"] != 0 {
		t.Fatalf("counts %v", counts)
	}
	var rules struct {
		Rules []RuleSetRule `json:"rules"`
		Total int           `json:"total"`
		Next  *uint32       `json:"next_cursor"`
	}
	if c := getRuleSets(t, s, "/v1/rule-sets/bots-scanners/rules", &rules); c != http.StatusOK || rules.Total != 1 || rules.Next == nil || *rules.Next != 0 || rules.Rules[0].ID != 500901 || rules.Rules[0].Tags[0] != "scanner" {
		t.Fatalf("%d %+v", c, rules)
	}
	if c := getRuleSets(t, s, "/v1/rule-sets/attack-sqli/rules?q=libinjection", &rules); c != http.StatusOK || rules.Total != 1 {
		t.Fatalf("search: %d %+v", c, rules)
	}
	if c := getRuleSets(t, s, "/v1/rule-sets/attack-sqli/rules?q=nothing-like-this", &rules); c != http.StatusOK || rules.Total != 0 || rules.Rules == nil {
		t.Fatalf("empty search: %d %+v", c, rules)
	}
	for path, want := range map[string]int{
		"/v1/rule-sets/no-such-set/rules":           http.StatusNotFound,
		"/v1/rule-sets/bots-scanners":               http.StatusOK,
		"/v1/rule-sets/custom-none":                 http.StatusNotFound,
		"/v1/rule-sets/bots-scanners/rules?after=x": http.StatusBadRequest,
	} {
		if c := getRuleSets(t, s, path, nil); c != want {
			t.Errorf("%s: %d, want %d", path, c, want)
		}
	}
}

func TestRuleSetsWithoutCatalog(t *testing.T) {
	s := ruleSetServer(t, false)
	var list struct {
		Sets      []RuleSetInfo `json:"sets"`
		Available bool          `json:"catalog_available"`
	}
	if c := getRuleSets(t, s, "/v1/rule-sets", &list); c != http.StatusOK || list.Available || list.Sets[0].RuleCount != nil {
		t.Fatalf("%d %+v", c, list)
	}
	if c := getRuleSets(t, s, "/v1/rule-sets/bots-scanners/rules", nil); c != http.StatusServiceUnavailable {
		t.Fatalf("rules without catalog: %d", c)
	}
	// a token is required
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/rule-sets", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}
}

func resolveRules(t *testing.T, s *Server, query, body string, out any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/rule-sets:resolve"+query, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer viewer")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatal(err)
		}
	}
	return rec.Code
}

// RS-3b: what each rule does under a draft, as the engine runs it.
func TestRuleSetsResolve(t *testing.T) {
	s := ruleSetServer(t, true)
	type page struct {
		Rules  []EffectiveRule `json:"rules"`
		Total  int             `json:"total"`
		Next   uint32          `json:"next_cursor"`
		Counts map[string]int  `json:"counts"`
	}
	byID := func(p page) map[uint32]EffectiveRule {
		m := map[uint32]EffectiveRule{}
		for _, r := range p.Rules {
			m[r.ID] = r
		}
		return m
	}
	// nothing chosen: signature rules log, the others score, levels above
	// 1 are not run; the plugin exclusion is no detection rule
	var p page
	call := func(query, body string) int {
		p = page{}
		return resolveRules(t, s, query, body, &p)
	}
	if c := call("", `{}`); c != http.StatusOK || p.Total != 5 {
		t.Fatalf("%d %+v", c, p)
	}
	got := byID(p)
	if got[500901].Action != "log" || got[500901].Source != "rule" || got[942100].Action != "score" ||
		got[942200].Action != "off" || got[942200].Own != "off" || got[942200].Source != "paranoia" {
		t.Fatalf("own %+v", got)
	}
	body := `{"crs_paranoia":1,"crs_paranoia_shadow":2,
		"rule_sets":[{"set":"bots-scanners","action":"block"},{"set":"attack-sqli","action":"block"}],
		"rule_overrides":[{"rule":942100,"action":"log","reason":"FP on /search"},{"rule":942300,"action":"off","reason":"never"}]}`
	if c := call("", body); c != http.StatusOK {
		t.Fatalf("%d", c)
	}
	got = byID(p)
	for id, want := range map[uint32][3]string{
		500901: {"block", "set", "bots-scanners"},
		500902: {"log", "rule", ""},
		942100: {"log", "override", ""},
		// run in shadow by its paranoia level: the set cannot make it block
		942200: {"log", "paranoia", ""},
		942300: {"off", "paranoia", ""},
	} {
		if r := got[id]; r.Action != want[0] || r.Source != want[1] || r.Set != want[2] {
			t.Errorf("%d: %+v, want %v", id, r, want)
		}
	}
	if got[942100].Reason != "FP on /search" || got[942200].Reason != "" || p.Counts["block"] != 1 || p.Counts["log"] != 3 || p.Counts["off"] != 1 {
		t.Errorf("reason/counts %+v", p)
	}
	// switched off over its paranoia level
	if c := call("", `{"crs_paranoia_shadow":2,"rule_overrides":[{"rule":942200,"action":"off","reason":"noisy"}]}`); c != http.StatusOK || byID(p)[942200].Action != "off" || byID(p)[942200].Source != "override" {
		t.Errorf("off over paranoia: %+v", byID(p)[942200])
	}
	// only what the draft changes, and a search
	if c := call("?changed=1", body); c != http.StatusOK || p.Total != 2 {
		t.Fatalf("changed: %d %+v", c, p)
	}
	if c := call("?changed=1&q=942", body); c != http.StatusOK || p.Total != 1 || p.Rules[0].ID != 942100 || p.Counts["block"] != 1 {
		t.Fatalf("search: %d %+v", c, p)
	}
	for q, b := range map[string]string{
		"":         `{"rule_sets":[{"set":"no-such-set","action":"block"}]}`,
		"?after=x": `{}`,
		" ":        `{"mode":"enforce"}`,
	} {
		if c := resolveRules(t, s, strings.TrimSpace(q), b, nil); c != http.StatusBadRequest {
			t.Errorf("%q %s: %d", q, b, c)
		}
	}
	if c := resolveRules(t, ruleSetServer(t, false), "", `{}`, nil); c != http.StatusServiceUnavailable {
		t.Errorf("without catalog: %d", c)
	}
}

// RS-4b: the catalog by set and by Rule ID or name, with the sets of each
// rule and the values its filters choose from.
func TestRuleCatalogBySetAndSearch(t *testing.T) {
	s := ruleSetServer(t, true)
	type page struct {
		Rules []struct {
			ID   uint32   `json:"id"`
			Sets []string `json:"sets"`
		} `json:"rules"`
		Total   int `json:"total"`
		Matched int `json:"matched"`
		Facets  struct {
			Sources     []string `json:"sources"`
			AttackTypes []string `json:"attack_types"`
		} `json:"facets"`
	}
	// the route needs the application store (PostgreSQL); the handler
	// itself only the catalog
	get := func(query string) (page, int) {
		var p page
		rec := httptest.NewRecorder()
		s.catalogList(rec, httptest.NewRequest(http.MethodGet, "/v1/rule-catalog"+query, nil))
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
		}
		return p, rec.Code
	}
	p, c := get("")
	if c != http.StatusOK || p.Total != 6 || p.Matched != 6 || !slices.Equal(p.Facets.Sources, []string{"crawler-user-agents", "crs"}) ||
		!slices.Equal(p.Facets.AttackTypes, []string{"bot", "sql-injection"}) {
		t.Fatalf("%d %+v", c, p)
	}
	sets := map[uint32][]string{}
	for _, r := range p.Rules {
		sets[r.ID] = r.Sets
	}
	if !slices.Equal(sets[942100], []string{"attack-sqli"}) || !slices.Equal(sets[500901], []string{"bots-scanners"}) || sets[9507100] != nil {
		t.Fatalf("sets of the rules: %v", sets)
	}
	if p, c = get("?set=bots-scanners"); c != http.StatusOK || p.Matched != 1 || p.Rules[0].ID != 500901 || p.Total != 6 {
		t.Fatalf("by set: %d %+v", c, p)
	}
	if p, c = get("?q=LEVEL&attack_type=sql-injection"); c != http.StatusOK || p.Matched != 2 {
		t.Fatalf("search: %d %+v", c, p)
	}
	if p, c = get("?q=5009"); c != http.StatusOK || p.Matched != 2 {
		t.Fatalf("by id: %d %+v", c, p)
	}
	if _, c = get("?set=no-such-set"); c != http.StatusBadRequest {
		t.Fatalf("unknown set: %d", c)
	}
}

// RS-4b: matches of each set over the last day, of one policy or all.
func TestRuleSetsCountMatches(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(f, []byte(ruleSetIR), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := rulecat.Load([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	events := ingest.NewMockEventStore()
	now := time.Now().UTC()
	ev := func(id, policy string, at time.Time, rules ...uint32) ingest.Event {
		return ingest.Event{BlockID: id, Timestamp: at, PolicyID: policy, Action: "shadow", MatchedRules: rules}
	}
	if err := events.SaveEvents(t.Context(), []ingest.Event{
		ev("STR-1", "example-api", now.Add(-time.Hour), 500901, 500901, 942100),
		ev("STR-2", "example-web", now.Add(-2*time.Hour), 500901),
		ev("STR-3", "example-api", now.Add(-30*time.Hour), 500901),
	}); err != nil {
		t.Fatal(err)
	}
	s := NewServer(ServerConfig{Auth: tokenRoles{}, RuleCatalog: ruleinventory.Static(c)}, events)
	count := func(query string) map[string]uint64 {
		var list struct {
			Sets []RuleSetInfo `json:"sets"`
		}
		if code := getRuleSets(t, s, "/v1/rule-sets"+query, &list); code != http.StatusOK {
			t.Fatalf("%s: %d", query, code)
		}
		out := map[string]uint64{}
		for _, set := range list.Sets {
			if set.Matches24h == nil {
				t.Fatalf("%s: no matches", set.Name)
			}
			out[set.Name] = *set.Matches24h
		}
		return out
	}
	if got := count(""); got["bots-scanners"] != 2 || got["attack-sqli"] != 1 || got["attack-xss"] != 0 {
		t.Fatalf("every policy: %v", got)
	}
	if got := count("?policy=example-api"); got["bots-scanners"] != 1 || got["attack-sqli"] != 1 {
		t.Fatalf("one policy: %v", got)
	}
}
