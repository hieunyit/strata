package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/rulecat"
	"github.com/strata/strata/control-plane/ruleinventory"
	"github.com/strata/strata/control-plane/rulesets"
	"github.com/strata/strata/control-plane/store"
)

// memCustomSets: custom rule sets in memory, etag = version.
type memCustomSets struct {
	mu   sync.Mutex
	sets map[string]store.CustomRuleSet
	log  []string
}

func (m *memCustomSets) ListCustomRuleSets(context.Context) ([]store.CustomRuleSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []store.CustomRuleSet{}
	for _, c := range m.sets {
		out = append(out, c)
	}
	return out, nil
}
func (m *memCustomSets) GetCustomRuleSet(_ context.Context, name string) (store.CustomRuleSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.sets[name]
	if !ok {
		return c, store.ErrNotFound
	}
	return c, nil
}
func (m *memCustomSets) CreateCustomRuleSet(_ context.Context, c store.CustomRuleSet, a store.Audit) (store.CustomRuleSet, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sets[c.Name]; ok {
		return c, store.ErrCustomRuleSetConflict
	}
	c.Version, c.Etag, c.CreatedBy, c.UpdatedBy = 1, "v1", a.Actor, a.Actor
	m.sets[c.Name] = c
	m.log = append(m.log, a.Actor+" "+a.Action)
	return c, nil
}
func (m *memCustomSets) UpdateCustomRuleSet(_ context.Context, c store.CustomRuleSet, etag string, a store.Audit) (store.CustomRuleSet, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	before, ok := m.sets[c.Name]
	if !ok {
		return c, store.ErrNotFound
	}
	if before.Etag != etag {
		return c, store.ErrCustomRuleSetConflict
	}
	c.Version, c.Etag, c.CreatedBy, c.UpdatedBy = before.Version+1, "v2", before.CreatedBy, a.Actor
	m.sets[c.Name] = c
	return c, nil
}
func (m *memCustomSets) DeleteCustomRuleSet(_ context.Context, name, etag string, _ store.Audit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	before, ok := m.sets[name]
	if !ok {
		return store.ErrNotFound
	}
	if before.Etag != etag {
		return store.ErrCustomRuleSetConflict
	}
	delete(m.sets, name)
	return nil
}

func callRuleSets(t *testing.T, s *Server, role, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+role)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// RS-3c: custom rule sets through the API, used like the built-in ones.
func TestCustomRuleSets(t *testing.T) {
	f := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(f, []byte(ruleSetIR), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := rulecat.Load([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	mem := &memCustomSets{sets: map[string]store.CustomRuleSet{}}
	s := NewServer(ServerConfig{Auth: tokenRoles{}, RuleCatalog: ruleinventory.Static(c), CustomRuleSets: mem}, ingest.NewMockEventStore())
	body := `{"name":"custom-our-scanners","title":"Our scanners","match":{"ids":[500901,942100]}}`
	for role, want := range map[string]int{"viewer": http.StatusForbidden, "approver": http.StatusForbidden} {
		if rec := callRuleSets(t, s, role, http.MethodPost, "/v1/rule-sets", body); rec.Code != want {
			t.Fatalf("%s: %d %s", role, rec.Code, rec.Body)
		}
	}
	if rec := callRuleSets(t, s, "operator", http.MethodPost, "/v1/rule-sets", body); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	for b, want := range map[string]int{
		body: http.StatusConflict,
		`{"name":"bots-scanners","title":"x","match":{"tags":["x"]}}`:      http.StatusConflict,
		`{"name":"custom-empty","title":"x","match":{}}`:                   http.StatusBadRequest,
		`{"name":"custom-x","title":"x","match":{"tags":["x"]},"extra":1}`: http.StatusBadRequest,
	} {
		if rec := callRuleSets(t, s, "operator", http.MethodPost, "/v1/rule-sets", b); rec.Code != want {
			t.Errorf("%s: %d, want %d", b, rec.Code, want)
		}
	}
	// listed with the built-in ones, counted, its rules listed
	var list struct {
		Sets []RuleSetInfo `json:"sets"`
	}
	if code := getRuleSets(t, s, "/v1/rule-sets", &list); code != http.StatusOK {
		t.Fatal(code)
	}
	last := list.Sets[len(list.Sets)-1]
	if !last.Custom || last.Group != "custom" || last.Name != "custom-our-scanners" || *last.RuleCount != 2 || last.Etag != "v1" {
		t.Fatalf("listed %+v", last)
	}
	var rules struct {
		Total int `json:"total"`
	}
	if code := getRuleSets(t, s, "/v1/rule-sets/custom-our-scanners/rules", &rules); code != http.StatusOK || rules.Total != 2 {
		t.Fatalf("rules %d %+v", code, rules)
	}
	// resolve fills a custom set without its copy
	var eff struct {
		Counts map[string]int `json:"counts"`
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/rule-sets:resolve", strings.NewReader(`{"rule_sets":[{"set":"custom-our-scanners","action":"block"}]}`))
	req.Header.Set("Authorization", "Bearer viewer")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"block":2`) {
		t.Fatalf("resolve %d %s %v", rec.Code, rec.Body, eff)
	}
	if rec := callRuleSets(t, s, "viewer", http.MethodPost, "/v1/rule-sets:resolve", `{"rule_sets":[{"set":"custom-none","action":"block"}]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown custom set: %d", rec.Code)
	}
	// update with the etag read, never rename, never a built-in set
	if rec := callRuleSets(t, s, "operator", http.MethodPut, "/v1/rule-sets/custom-our-scanners", `{"title":"Our scanners","match":{"tags":["scanner"]},"etag":"stale"}`); rec.Code != http.StatusConflict {
		t.Fatalf("stale: %d", rec.Code)
	}
	if rec := callRuleSets(t, s, "operator", http.MethodPut, "/v1/rule-sets/custom-our-scanners", `{"name":"custom-other","title":"x","match":{"tags":["scanner"]},"etag":"v1"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("rename: %d", rec.Code)
	}
	if rec := callRuleSets(t, s, "operator", http.MethodPut, "/v1/rule-sets/bots-scanners", `{"title":"x","match":{"tags":["x"]}}`); rec.Code != http.StatusForbidden {
		t.Fatalf("built-in: %d", rec.Code)
	}
	if rec := callRuleSets(t, s, "operator", http.MethodPut, "/v1/rule-sets/custom-our-scanners", `{"title":"Our scanners","match":{"tags":["scanner"]},"etag":"v1"}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version":2`) {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	// the catalog filtered by it
	rec = httptest.NewRecorder()
	s.catalogList(rec, httptest.NewRequest(http.MethodGet, "/v1/rule-catalog?set=custom-our-scanners", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"matched":1`) {
		t.Fatalf("catalog by custom set: %d %s", rec.Code, rec.Body)
	}
	if rec := callRuleSets(t, s, "operator", http.MethodDelete, "/v1/rule-sets/custom-our-scanners?etag=v1", ""); rec.Code != http.StatusConflict {
		t.Fatalf("delete stale: %d", rec.Code)
	}
	if rec := callRuleSets(t, s, "operator", http.MethodDelete, "/v1/rule-sets/custom-our-scanners?etag=v2", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if _, ok := rulesets.Get("custom-our-scanners"); ok || len(mem.sets) != 0 || len(mem.log) != 1 {
		t.Fatal("not deleted")
	}
	// without a store: no custom sets, writes refused
	plain := ruleSetServer(t, true)
	if rec := callRuleSets(t, plain, "operator", http.MethodPost, "/v1/rule-sets", body); rec.Code != http.StatusNotImplemented {
		t.Fatalf("no store: %d", rec.Code)
	}
}
