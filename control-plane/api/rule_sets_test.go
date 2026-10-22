package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
	if counts["bots-scanners"] != 1 || counts["bots-trusted"] != 1 || counts["attack-sqli"] != 1 || counts["attack-xss"] != 0 {
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
		"/v1/rule-sets/bots-scanners":               http.StatusNotFound,
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
