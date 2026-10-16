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

func TestGeoStatsEndpoint(t *testing.T) {
	store := ingest.NewMockEventStore()
	base := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

	events := []ingest.Event{
		{
			BlockID:    "STR-0000-0000-0000-0001",
			Timestamp:  base.Add(-30 * time.Minute),
			PolicyID:   "pilot-api",
			Action:     "block",
			ScoreSQLi:  20,
			CountryISO: "VN",
			City:       "Da Nang",
			Lat:        16.0544,
			Lon:        108.2022,
			ASN:        7552,
			ASOrg:      "Viettel",
		},
		{
			BlockID:    "STR-0000-0000-0000-0002",
			Timestamp:  base.Add(-15 * time.Minute),
			PolicyID:   "pilot-api",
			Action:     "block",
			ScoreXSS:   30,
			CountryISO: "SG",
			City:       "Singapore",
			Lat:        1.3521,
			Lon:        103.8198,
			ASN:        4657,
			ASOrg:      "StarHub",
		},
	}
	if err := store.SaveEvents(t.Context(), events); err != nil {
		t.Fatal(err)
	}

	server := NewServer(ServerConfig{Auth: tokenRoles{}}, store)

	// 1. Viewer or Operator queries GeoStats
	q := url.Values{}
	q.Set("from", base.Add(-2*time.Hour).Format(time.RFC3339))
	q.Set("to", base.Format(time.RFC3339))
	q.Set("groupBy", "all")

	req := httptest.NewRequest(http.MethodGet, "/v1/stats/geo?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer viewer")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ingest.GeoStatsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode geo stats response: %v", err)
	}

	if len(resp.Countries) != 2 {
		t.Errorf("expected 2 countries, got %d", len(resp.Countries))
	}
	if len(resp.ASNs) != 2 {
		t.Errorf("expected 2 ASNs, got %d", len(resp.ASNs))
	}
	if len(resp.Grid) != 2 {
		t.Errorf("expected 2 grid points, got %d", len(resp.Grid))
	}
}
