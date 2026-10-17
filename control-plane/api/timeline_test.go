package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

func TestTimelineEndpoint(t *testing.T) {
	store := ingest.NewMockEventStore()
	base := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

	events := []ingest.Event{
		{
			BlockID:    "STR-0000-0000-0000-0001",
			Timestamp:  base.Add(-45 * time.Minute),
			PolicyID:   "pilot-api",
			Action:     "block",
			ScoreSQLi:  20,
			CountryISO: "VN",
			City:       "Da Nang",
			ASN:        7552,
			ASOrg:      "Viettel",
		},
		{
			BlockID:    "STR-0000-0000-0000-0002",
			Timestamp:  base.Add(-15 * time.Minute),
			PolicyID:   "pilot-api",
			Action:     "monitor",
			ScoreXSS:   30,
			CountryISO: "VN",
			City:       "Hanoi",
			ASN:        7552,
			ASOrg:      "Viettel",
		},
		{
			BlockID:    "STR-0000-0000-0000-0003",
			Timestamp:  base.Add(-10 * time.Minute),
			PolicyID:   "pilot-api",
			Action:     "pass",
			CountryISO: "SG",
			City:       "Singapore",
			ASN:        4657,
			ASOrg:      "StarHub",
		},
	}
	if err := store.SaveEvents(t.Context(), events); err != nil {
		t.Fatal(err)
	}

	server := NewServer(ServerConfig{Auth: tokenRoles{}}, store)

	// 1. Query timeline with step=5m
	q := url.Values{}
	q.Set("from", base.Add(-2*time.Hour).Format(time.RFC3339))
	q.Set("to", base.Format(time.RFC3339))
	q.Set("step", "5m")

	req := httptest.NewRequest(http.MethodGet, "/v1/stats/timeline?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer viewer")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ingest.TimelineResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode timeline response: %v", err)
	}

	if len(resp.Buckets) == 0 {
		t.Fatalf("expected buckets, got 0")
	}

	totalEvents := uint64(0)
	totalBlocked := uint64(0)
	totalMonitored := uint64(0)
	totalPassed := uint64(0)
	for _, b := range resp.Buckets {
		totalEvents += b.Total
		totalBlocked += b.Blocked
		totalMonitored += b.Monitored
		totalPassed += b.Passed
	}
	if totalEvents != 3 {
		t.Errorf("expected 3 total events, got %d", totalEvents)
	}
	if totalBlocked != 1 {
		t.Errorf("expected 1 blocked event, got %d", totalBlocked)
	}
	if totalMonitored != 1 {
		t.Errorf("expected 1 monitored event, got %d", totalMonitored)
	}
	if totalPassed != 1 {
		t.Errorf("expected 1 passed event, got %d", totalPassed)
	}

	// 2. Filter by country_iso=VN
	qVN := url.Values{}
	qVN.Set("from", base.Add(-2*time.Hour).Format(time.RFC3339))
	qVN.Set("to", base.Format(time.RFC3339))
	qVN.Set("country_iso", "VN")
	req = httptest.NewRequest(http.MethodGet, "/v1/stats/timeline?"+qVN.Encode(), nil)
	req.Header.Set("Authorization", "Bearer viewer")
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for VN filter, got %d", rec.Code)
	}
	var respVN ingest.TimelineResponse
	if err := json.NewDecoder(rec.Body).Decode(&respVN); err != nil {
		t.Fatalf("decode VN timeline response: %v", err)
	}
	eventsVN := uint64(0)
	for _, b := range respVN.Buckets {
		eventsVN += b.Total
	}
	if eventsVN != 2 {
		t.Errorf("expected 2 events for country_iso=VN, got %d", eventsVN)
	}

	// 3. from > to returns 400
	qBad := url.Values{}
	qBad.Set("from", base.Format(time.RFC3339))
	qBad.Set("to", base.Add(-1*time.Hour).Format(time.RFC3339))
	req = httptest.NewRequest(http.MethodGet, "/v1/stats/timeline?"+qBad.Encode(), nil)
	req.Header.Set("Authorization", "Bearer viewer")
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for from > to, got %d", rec.Code)
	}

	// 4. Invalid step returns 400
	qInvalidStep := url.Values{}
	qInvalidStep.Set("from", base.Add(-1*time.Hour).Format(time.RFC3339))
	qInvalidStep.Set("to", base.Format(time.RFC3339))
	qInvalidStep.Set("step", "37s")
	req = httptest.NewRequest(http.MethodGet, "/v1/stats/timeline?"+qInvalidStep.Encode(), nil)
	req.Header.Set("Authorization", "Bearer viewer")
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid step, got %d", rec.Code)
	}

	// 5. POST returns 405
	req = httptest.NewRequest(http.MethodPost, "/v1/stats/timeline", nil)
	req.Header.Set("Authorization", "Bearer operator")
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", rec.Code)
	}
}
