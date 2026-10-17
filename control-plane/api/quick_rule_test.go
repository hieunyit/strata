package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

type mockPolicyStore struct {
	mu           sync.Mutex
	policies     map[string]store.Policy
	auditRecords []store.Audit
}

func newMockPolicyStore() *mockPolicyStore {
	return &mockPolicyStore{
		policies: make(map[string]store.Policy),
	}
}

func (m *mockPolicyStore) GetPolicy(_ context.Context, id string) (store.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.policies[id]
	if !ok {
		return store.Policy{}, store.ErrNotFound
	}
	return p, nil
}

func (m *mockPolicyStore) UpdatePolicy(_ context.Context, id, etag string, spec json.RawMessage, a store.Audit) (store.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.policies[id]
	if !ok {
		return store.Policy{}, store.ErrNotFound
	}
	if p.Etag != etag {
		return store.Policy{}, store.ErrEtagMismatch
	}
	p.CurrentVersion++
	p.Etag = "etag-" + time.Now().Format(time.RFC3339Nano)
	p.Spec = spec
	m.policies[id] = p
	m.auditRecords = append(m.auditRecords, a)
	return p, nil
}

func TestQuickRuleGeoBlock(t *testing.T) {
	pStore := newMockPolicyStore()
	pStore.policies["example-api"] = store.Policy{
		ID:             "example-api",
		Name:           "Example API",
		CurrentVersion: 1,
		Etag:           "etag-1",
		Spec:           json.RawMessage(`{"mode":"enforce"}`),
	}

	server := NewServer(ServerConfig{
		Auth:     tokenRoles{},
		Policies: pStore,
	}, ingest.NewMockEventStore())

	body := `{"type":"geo","target":"KP","action":"block","reason":"DDoS surge from high-risk origin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/example-api:quick-rule", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer operator")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp QuickRuleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.PolicyID != "example-api" || resp.Version != 2 {
		t.Errorf("unexpected response: %+v", resp)
	}

	// Verify store state
	updated := pStore.policies["example-api"]
	var spec policy.Spec
	if err := json.Unmarshal(updated.Spec, &spec); err != nil {
		t.Fatalf("failed to unmarshal updated spec: %v", err)
	}

	if spec.GeoRestrictions == nil {
		t.Fatal("expected GeoRestrictions to be non-nil")
	}
	if len(spec.GeoRestrictions.BlockedCountries) != 1 || spec.GeoRestrictions.BlockedCountries[0] != "KP" {
		t.Errorf("unexpected blocked countries: %+v", spec.GeoRestrictions.BlockedCountries)
	}
}

func TestQuickRuleGeoChallengeAndSwitch(t *testing.T) {
	pStore := newMockPolicyStore()
	pStore.policies["example-api"] = store.Policy{
		ID:             "example-api",
		CurrentVersion: 1,
		Etag:           "etag-1",
		Spec:           json.RawMessage(`{"mode":"enforce","geo_restrictions":{"default_action":"pass","challenged_countries":["CN"]}}`),
	}

	server := NewServer(ServerConfig{
		Auth:     tokenRoles{},
		Policies: pStore,
	}, ingest.NewMockEventStore())

	// Switch CN from challenged to blocked
	body := `{"type":"geo_block","target":"CN","action":"block","reason":"Attacks escalated"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/example-api:quick-rule", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer operator")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	updated := pStore.policies["example-api"]
	var spec policy.Spec
	_ = json.Unmarshal(updated.Spec, &spec)

	if len(spec.GeoRestrictions.BlockedCountries) != 1 || spec.GeoRestrictions.BlockedCountries[0] != "CN" {
		t.Errorf("expected CN in blocked_countries, got %+v", spec.GeoRestrictions.BlockedCountries)
	}
	if len(spec.GeoRestrictions.ChallengedCountries) != 0 {
		t.Errorf("expected CN removed from challenged_countries, got %+v", spec.GeoRestrictions.ChallengedCountries)
	}
}

func TestQuickRuleASNBlockAndChallenge(t *testing.T) {
	pStore := newMockPolicyStore()
	pStore.policies["example-api"] = store.Policy{
		ID:             "example-api",
		CurrentVersion: 1,
		Etag:           "etag-1",
		Spec:           json.RawMessage(`{"mode":"shadow"}`),
	}

	server := NewServer(ServerConfig{
		Auth:     tokenRoles{},
		Policies: pStore,
	}, ingest.NewMockEventStore())

	// 1. Block ASN with "AS13335" prefix format
	body := `{"type":"asn","target":"AS13335","action":"block","reason":"Bulletproof hosting ASN"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/example-api:quick-rule", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer operator")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Challenge ASN 7552
	etag := pStore.policies["example-api"].Etag
	body2 := `{"type":"asn_block","target":"7552","action":"challenge","reason":"Scraper botnet"}`
	req2 := httptest.NewRequest(http.MethodPost, "/v1/policies/example-api:quick-rule", bytes.NewBufferString(body2))
	req2.Header.Set("Authorization", "Bearer admin")
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}

	updated := pStore.policies["example-api"]
	if updated.Etag == etag {
		t.Error("expected etag to change on second update")
	}

	var spec policy.Spec
	_ = json.Unmarshal(updated.Spec, &spec)

	if len(spec.GeoRestrictions.BlockedASNs) != 1 || spec.GeoRestrictions.BlockedASNs[0] != 13335 {
		t.Errorf("expected ASN 13335 blocked, got %+v", spec.GeoRestrictions.BlockedASNs)
	}
	if len(spec.GeoRestrictions.ChallengedASNs) != 1 || spec.GeoRestrictions.ChallengedASNs[0] != 7552 {
		t.Errorf("expected ASN 7552 challenged, got %+v", spec.GeoRestrictions.ChallengedASNs)
	}
}

func TestQuickRuleValidationErrors(t *testing.T) {
	pStore := newMockPolicyStore()
	pStore.policies["example-api"] = store.Policy{
		ID:             "example-api",
		CurrentVersion: 1,
		Etag:           "etag-1",
		Spec:           json.RawMessage(`{"mode":"enforce"}`),
	}

	server := NewServer(ServerConfig{
		Auth:     tokenRoles{},
		Policies: pStore,
	}, ingest.NewMockEventStore())

	cases := []struct {
		name string
		body string
	}{
		{"invalid country code length", `{"type":"geo","target":"USA","action":"block"}`},
		{"numeric country code", `{"type":"geo","target":"12","action":"block"}`},
		{"invalid ASN zero", `{"type":"asn","target":"0","action":"block"}`},
		{"invalid ASN text", `{"type":"asn","target":"notanumber","action":"block"}`},
		{"invalid action", `{"type":"geo","target":"US","action":"drop"}`},
		{"unsupported type", `{"type":"ip","target":"1.2.3.4","action":"block"}`},
		{"missing target", `{"type":"geo","target":"","action":"block"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/policies/example-api:quick-rule", bytes.NewBufferString(tc.body))
			req.Header.Set("Authorization", "Bearer operator")
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400 Bad Request, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestQuickRuleNotFoundAndConflict(t *testing.T) {
	pStore := newMockPolicyStore()
	server := NewServer(ServerConfig{
		Auth:     tokenRoles{},
		Policies: pStore,
	}, ingest.NewMockEventStore())

	// 1. Not found
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/non-existent:quick-rule", bytes.NewBufferString(`{"type":"geo","target":"VN","action":"block"}`))
	req.Header.Set("Authorization", "Bearer operator")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestQuickRuleRBAC(t *testing.T) {
	pStore := newMockPolicyStore()
	pStore.policies["example-api"] = store.Policy{
		ID:             "example-api",
		CurrentVersion: 1,
		Etag:           "etag-1",
		Spec:           json.RawMessage(`{"mode":"enforce"}`),
	}

	server := NewServer(ServerConfig{
		Auth:     tokenRoles{},
		Policies: pStore,
	}, ingest.NewMockEventStore())

	// Viewer does not have PermPoliciesWrite
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/example-api:quick-rule", bytes.NewBufferString(`{"type":"geo","target":"VN","action":"block"}`))
	req.Header.Set("Authorization", "Bearer viewer")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer, got %d", rec.Code)
	}
}

func TestSearchEventsWithGeoAndASN(t *testing.T) {
	evStore := ingest.NewMockEventStore()
	now := time.Now().UTC()
	_ = evStore.SaveEvents(context.Background(), []ingest.Event{
		{
			BlockID:    "EVT-VN-1",
			Timestamp:  now.Add(-1 * time.Minute),
			ClientIP:   "118.69.1.1",
			CountryISO: "VN",
			ASN:        7552,
			Action:     "block",
		},
		{
			BlockID:    "EVT-US-1",
			Timestamp:  now.Add(-2 * time.Minute),
			ClientIP:   "198.51.100.1",
			CountryISO: "US",
			ASN:        13335,
			Action:     "shadow",
		},
	})

	server := NewServer(ServerConfig{
		Auth: tokenRoles{},
	}, evStore)

	// Filter by CountryISO = VN
	body := `{"country_iso":"VN"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/events:search", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer viewer")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var res SearchEventsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 1 || res.Events[0].BlockID != "EVT-VN-1" {
		t.Fatalf("expected 1 VN event, got %d", len(res.Events))
	}

	// Filter by ASN = 13335
	bodyASN := `{"asn":13335}`
	reqASN := httptest.NewRequest(http.MethodPost, "/v1/events:search", bytes.NewBufferString(bodyASN))
	reqASN.Header.Set("Authorization", "Bearer viewer")
	reqASN.Header.Set("Content-Type", "application/json")
	recASN := httptest.NewRecorder()

	server.Handler().ServeHTTP(recASN, reqASN)
	if recASN.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recASN.Code, recASN.Body.String())
	}

	var resASN SearchEventsResponse
	if err := json.Unmarshal(recASN.Body.Bytes(), &resASN); err != nil {
		t.Fatal(err)
	}
	if len(resASN.Events) != 1 || resASN.Events[0].BlockID != "EVT-US-1" {
		t.Fatalf("expected 1 US event, got %d", len(resASN.Events))
	}
}
