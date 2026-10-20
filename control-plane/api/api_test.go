package api

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/strata/strata/control-plane/rulecat"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

func setupTestServer(t *testing.T) (*Server, *ingest.MockEventStore) {
	t.Helper()
	store := ingest.NewMockEventStore()

	// Seed test events
	now := time.Now().UTC()
	events := []ingest.Event{
		{
			BlockID:       "STR-8F3K-Q2VD-7XNM-A1PC",
			Timestamp:     now.Add(-10 * time.Minute),
			NodeID:        "node-01",
			ConnectorType: "nginx",
			PolicyID:      "default-api",
			PolicyVersion: 1,
			ClientIP:      "192.0.2.42",
			HTTPMethod:    "POST",
			HTTPHost:      "api.example.test",
			HTTPPath:      "/api/v1/auth",
			StatusCode:    403,
			Action:        "block",
			ScoreProtocol: 0,
			ScoreSQLi:     30,
			ScoreXSS:      0,
			ScoreAnomaly:  30,
			MatchedRules:  []uint32{942100},
			Violations: []ingest.Violation{
				{RuleID: 942100, Layer: "sqli", Field: "body.password", Snippet: "' OR '1'='1"},
			},
			UserAgent:  "sqlmap/1.8",
			Referer:    "https://app.example.test/login?next=/home",
			Headers:    []ingest.Header{{Name: "Authorization", Value: "[MASKED]"}, {Name: "X-Request-Source", Value: "mobile"}},
			Inspection: "full",
		},
		{
			BlockID:       "EVT-8F3K-Q2VD-7XNM-A1PC",
			Timestamp:     now.Add(-5 * time.Minute),
			NodeID:        "node-02",
			ConnectorType: "nginx",
			PolicyID:      "default-api",
			PolicyVersion: 1,
			ClientIP:      "198.51.100.15",
			HTTPMethod:    "GET",
			HTTPHost:      "api.example.test",
			HTTPPath:      "/search",
			StatusCode:    200,
			Action:        "shadow",
			ScoreXSS:      20,
			MatchedRules:  []uint32{941100},
			Violations: []ingest.Violation{
				{RuleID: 941100, Layer: "xss", Field: "query.q", Snippet: "<script>alert(1)</script>"},
			},
		},
		{
			BlockID:       "STR-0000-0000-0000-0003",
			Timestamp:     now.Add(-1 * time.Minute),
			NodeID:        "node-01",
			ConnectorType: "nginx",
			PolicyID:      "admin-portal",
			PolicyVersion: 2,
			ClientIP:      "203.0.113.88",
			HTTPMethod:    "PUT",
			HTTPHost:      "admin.example.test",
			HTTPPath:      "/config",
			StatusCode:    403,
			Action:        "block",
			ScoreProtocol: 15,
			MatchedRules:  []uint32{100001},
		},
	}

	_ = store.SaveEvents(context.Background(), events)

	server := NewServer(ServerConfig{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Auth:         tokenRoles{},
	}, store)

	return server, store
}

func TestGetEventEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)

	t.Run("200 OK for existing Block ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/events/STR-8F3K-Q2VD-7XNM-A1PC", nil)
		rec := httptest.NewRecorder()

		serve(server, rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp GetEventResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Event.BlockID != "STR-8F3K-Q2VD-7XNM-A1PC" {
			t.Errorf("expected BlockID STR-8F3K-Q2VD-7XNM-A1PC, got %s", resp.Event.BlockID)
		}
		if len(resp.Event.Violations) != 1 || resp.Event.Violations[0].RuleID != 942100 {
			t.Errorf("expected violation with rule 942100, got %+v", resp.Event.Violations)
		}
	})

	t.Run("404 Not Found for non-existent Block ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/events/STR-9999-9999-9999-9999", nil)
		rec := httptest.NewRecorder()

		serve(server, rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d: %s", rec.Code, rec.Body.String())
		}

		var errResp ErrorResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
		if errResp.BlockID != "STR-9999-9999-9999-9999" {
			t.Errorf("expected block_id in error response, got %s", errResp.BlockID)
		}
	})

	t.Run("400 Bad Request for malformed Block ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/events/INVALID-ID", nil)
		rec := httptest.NewRecorder()

		serve(server, rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("405 Method Not Allowed for POST on /v1/events/{id}", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/events/STR-8F3K-Q2VD-7XNM-A1PC", nil)
		rec := httptest.NewRecorder()

		serve(server, rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405, got %d", rec.Code)
		}
	})
}

func TestSearchEventsEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)

	t.Run("200 OK Search all events", func(t *testing.T) {
		body := SearchEventsRequest{
			PageSize: 10,
		}
		data, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/events:search", bytes.NewReader(data))
		rec := httptest.NewRecorder()

		serve(server, rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp SearchEventsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.TotalMatched != 3 {
			t.Errorf("expected 3 total matched, got %d", resp.TotalMatched)
		}
		if len(resp.Events) != 3 {
			t.Errorf("expected 3 events returned, got %d", len(resp.Events))
		}
	})

	t.Run("geo filters are checked", func(t *testing.T) {
		for _, body := range []string{`{"country":"vn"}`, `{"country":"VNM"}`, `{"attack_type":"nope"}`, `{"asn":-1}`} {
			req := httptest.NewRequest(http.MethodPost, "/v1/events:search", strings.NewReader(body))
			rec := httptest.NewRecorder()
			serve(server, rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: %d", body, rec.Code)
			}
		}
		for _, body := range []string{`{"country":"VN"}`, `{"country":"INTERNAL","asn":7552,"attack_type":"sqli"}`} {
			req := httptest.NewRequest(http.MethodPost, "/v1/events:search", strings.NewReader(body))
			rec := httptest.NewRecorder()
			serve(server, rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
			}
		}
	})

	t.Run("Filter by action=block", func(t *testing.T) {
		body := SearchEventsRequest{
			Action: "block",
		}
		data, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/events:search", bytes.NewReader(data))
		rec := httptest.NewRecorder()

		serve(server, rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp SearchEventsResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)

		if resp.TotalMatched != 2 {
			t.Errorf("expected 2 blocked events, got %d", resp.TotalMatched)
		}
	})

	t.Run("Filter by rule_id=942100", func(t *testing.T) {
		body := SearchEventsRequest{
			RuleID: 942100,
		}
		data, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/events:search", bytes.NewReader(data))
		rec := httptest.NewRecorder()

		serve(server, rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp SearchEventsResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)

		if resp.TotalMatched != 1 {
			t.Errorf("expected 1 event matching rule 942100, got %d", resp.TotalMatched)
		}
		if len(resp.Events) > 0 && resp.Events[0].BlockID != "STR-8F3K-Q2VD-7XNM-A1PC" {
			t.Errorf("expected STR-8F3K-Q2VD-7XNM-A1PC, got %s", resp.Events[0].BlockID)
		}
	})

	t.Run("Pagination with page_size and next_page_token", func(t *testing.T) {
		// Request page 1 with page_size=2
		body1 := SearchEventsRequest{
			PageSize: 2,
		}
		data1, _ := json.Marshal(body1)
		req1 := httptest.NewRequest(http.MethodPost, "/v1/events:search", bytes.NewReader(data1))
		rec1 := httptest.NewRecorder()
		serve(server, rec1, req1)

		var resp1 SearchEventsResponse
		_ = json.Unmarshal(rec1.Body.Bytes(), &resp1)

		if len(resp1.Events) != 2 {
			t.Fatalf("expected 2 events on page 1, got %d", len(resp1.Events))
		}
		if resp1.NextPageToken == "" {
			t.Fatalf("expected non-empty next_page_token")
		}

		// Request page 2 using NextPageToken
		body2 := SearchEventsRequest{
			PageSize:  2,
			PageToken: resp1.NextPageToken,
		}
		data2, _ := json.Marshal(body2)
		req2 := httptest.NewRequest(http.MethodPost, "/v1/events:search", bytes.NewReader(data2))
		rec2 := httptest.NewRecorder()
		serve(server, rec2, req2)

		var resp2 SearchEventsResponse
		_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)

		if len(resp2.Events) != 1 {
			t.Fatalf("expected 1 event on page 2, got %d", len(resp2.Events))
		}
		if resp2.NextPageToken != "" {
			t.Errorf("expected empty next_page_token on last page, got %s", resp2.NextPageToken)
		}
	})

	t.Run("400 Bad Request for invalid time range", func(t *testing.T) {
		now := time.Now().UTC()
		body := SearchEventsRequest{
			From: now.Add(1 * time.Hour),
			To:   now,
		}
		data, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/v1/events:search", bytes.NewReader(data))
		rec := httptest.NewRecorder()

		serve(server, rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected status 400 for inverted time range, got %d", rec.Code)
		}
	})

	t.Run("405 Method Not Allowed for GET /v1/events:search", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/events:search", nil)
		rec := httptest.NewRecorder()

		serve(server, rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405, got %d", rec.Code)
		}
	})
}

// The decision trace carries what the rule catalog knows about the event's
// rules, the author of a Sigma rule among them (W09-F-01); without a
// catalog the response has no "rules".
func TestGetEventRuleCatalog(t *testing.T) {
	store := ingest.NewMockEventStore()
	_ = store.SaveEvents(context.Background(), []ingest.Event{{
		BlockID: "STR-8F3K-Q2VD-7XNM-A1PC", Timestamp: time.Now().UTC(), NodeID: "node-01",
		ConnectorType: "nginx", PolicyID: "example-api", Action: "block", HTTPMethod: "GET",
		MatchedRules: []uint32{600001, 942100},
		Violations:   []ingest.Violation{{RuleID: 600001, Layer: "managed", Field: "REQUEST_HEADERS:User-Agent", Snippet: "x"}},
	}})
	f := filepath.Join(t.TempDir(), "rules.yaml")
	_ = os.WriteFile(f, []byte(`rules:
  - { id: 600001, name: Webshell probe, metadata: { source: sigma, author: "A. Author (Example Org)", license: DRL-1.1 } }
  - { id: 942100, name: SQL Injection via libinjection, metadata: { source: owasp-crs } }
`), 0o644)
	catalog, err := rulecat.Load([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	for _, withCatalog := range []bool{true, false} {
		cfg := ServerConfig{Auth: tokenRoles{}}
		if withCatalog {
			cfg.Rules = catalog
		}
		server := NewServer(cfg, store)
		rec := httptest.NewRecorder()
		serve(server, rec, httptest.NewRequest(http.MethodGet, "/v1/events/STR-8F3K-Q2VD-7XNM-A1PC", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var resp GetEventResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !withCatalog {
			if resp.Rules != nil {
				t.Errorf("rules without a catalog: %+v", resp.Rules)
			}
			continue
		}
		if r := resp.Rules["600001"]; r.Author != "A. Author (Example Org)" || r.Source != "sigma" || r.Name != "Webshell probe" {
			t.Errorf("sigma rule: %+v", r)
		}
		if r := resp.Rules["942100"]; r.Source != "owasp-crs" {
			t.Errorf("matched rule without a violation: %+v", r)
		}
	}
}
