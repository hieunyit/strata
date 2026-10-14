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

// overviewServer: a fixed window [base-24h, base) with events of two
// policies, three actions and one event outside the window.
func overviewServer(t *testing.T) (*Server, time.Time) {
	t.Helper()
	store := ingest.NewMockEventStore()
	base := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	ev := func(id string, ago time.Duration, policy, ip, path, action string, rules ...uint32) ingest.Event {
		return ingest.Event{BlockID: id, Timestamp: base.Add(-ago), NodeID: "node-01", PolicyID: policy,
			ClientIP: ip, HTTPHost: "api.example.test", HTTPPath: path, Action: action, MatchedRules: rules}
	}
	events := []ingest.Event{
		ev("STR-0000-0000-0000-0001", 30*time.Minute, "pilot-verify", "198.51.100.1", "/v1/verify/abc?x=1", "block", 942100, 942100, 941100),
		ev("STR-0000-0000-0000-0002", 90*time.Minute, "pilot-verify", "198.51.100.1", "/v1/verify", "block", 942100),
		ev("EVT-0000-0000-0000-0003", 90*time.Minute, "pilot-upload", "198.51.100.2", "/v1/upload", "shadow", 942100, 932100),
		ev("EVT-0000-0000-0000-0004", 5*time.Hour, "pilot-upload", "198.51.100.3", "/v2/upload", "pass"),
		ev("EVT-0000-0000-0000-0006", 2*time.Hour, "pilot-upload", "198.51.100.3", "/v3/upload", "error"),
		ev("STR-0000-0000-0000-0005", 30*time.Hour, "pilot-verify", "198.51.100.4", "/v1/verify", "block", 930100),
	}
	if err := store.SaveEvents(t.Context(), events); err != nil {
		t.Fatal(err)
	}
	return NewServer(ServerConfig{Auth: tokenRoles{}}, store), base
}

func getOverview(t *testing.T, s *Server, token string, q url.Values) (*httptest.ResponseRecorder, OverviewResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/stats/overview?"+q.Encode(), nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var resp OverviewResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rec, resp
}

func window(base time.Time, d time.Duration) url.Values {
	return url.Values{"from": {base.Add(-d).Format(time.RFC3339)}, "to": {base.Format(time.RFC3339)}}
}

func TestOverview_CountsTopsAndSeries(t *testing.T) {
	s, base := overviewServer(t)
	rec, o := getOverview(t, s, "operator", window(base, 24*time.Hour))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	want := ingest.OverviewTotals{Events: 5, Block: 2, Shadow: 1, Other: 2, Error: 1, Clients: 3, Nodes: 1, Policies: 2}
	if o.Totals != want {
		t.Errorf("totals = %+v, want %+v (the event 30 h ago is outside)", o.Totals, want)
	}
	if o.StepSecond != 3600 || len(o.Series) != 24 {
		t.Errorf("step %d s, %d buckets; want hourly, 24", o.StepSecond, len(o.Series))
	}
	var sum uint64
	for _, b := range o.Series {
		sum += b.Block + b.Shadow + b.Other
	}
	if sum != 5 {
		t.Errorf("series sums to %d, want 5", sum)
	}
	last := o.Series[len(o.Series)-1]
	if !last.Start.Equal(base.Add(-time.Hour)) || last.Block != 1 {
		t.Errorf("last bucket = %+v, want the block 30 min ago", last)
	}
	var errs uint64
	for _, b := range o.Series {
		errs += b.Error
	}
	if errs != 1 {
		t.Errorf("series has %d fail-mode events, want 1", errs)
	}
	var routeErr bool
	for _, r := range o.TopRoutes {
		routeErr = routeErr || (r.PathPrefix == "/v3/upload" && r.Error == 1)
	}
	if !routeErr {
		t.Errorf("top routes %+v: the fail-mode event is not on /v3/upload", o.TopRoutes)
	}
	// 942100 counts once for the event that matched it twice.
	if len(o.TopRules) == 0 || o.TopRules[0].RuleID != 942100 || o.TopRules[0].Events != 3 ||
		o.TopRules[0].Block != 2 || o.TopRules[0].Shadow != 1 {
		t.Errorf("top rule = %+v, want 942100 with 3 events (2 block, 1 shadow)", o.TopRules)
	}
	if r := o.TopRoutes[0]; r.PolicyID != "pilot-verify" || r.PathPrefix != "/v1/verify" || r.Events != 2 || r.Block != 2 {
		t.Errorf("top route = %+v, want pilot-verify /v1/verify with 2 blocks", r)
	}
	if len(o.TopClients) == 0 || o.TopClients[0].ClientIP != "198.51.100.1" || o.TopClients[0].Events != 2 {
		t.Errorf("top clients = %+v, want 198.51.100.1 first", o.TopClients)
	}
}

func TestOverview_ViewerGetsNoClients(t *testing.T) {
	s, base := overviewServer(t)
	rec, o := getOverview(t, s, "viewer", window(base, 24*time.Hour))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if o.TopClients != nil {
		t.Errorf("viewer got top clients %+v", o.TopClients)
	}
	if o.Totals.Events != 5 {
		t.Errorf("viewer totals = %+v", o.Totals)
	}
}

func TestOverview_PolicyFilterAndSteps(t *testing.T) {
	s, base := overviewServer(t)
	q := window(base, 24*time.Hour)
	q.Set("policy_id", "pilot-upload")
	_, o := getOverview(t, s, "operator", q)
	if o.Totals.Events != 3 || o.Totals.Block != 0 || o.Totals.Shadow != 1 || o.Totals.Error != 1 {
		t.Errorf("pilot-upload totals = %+v", o.Totals)
	}
	for _, c := range []struct {
		d       time.Duration
		step    int64
		buckets int
	}{{7 * 24 * time.Hour, 6 * 3600, 28}, {30 * 24 * time.Hour, 86400, 31}} {
		rec, o := getOverview(t, s, "viewer", window(base, c.d))
		if rec.Code != http.StatusOK || o.StepSecond != c.step || len(o.Series) != c.buckets {
			t.Errorf("%v: status %d, step %d, %d buckets; want step %d, %d buckets", c.d, rec.Code, o.StepSecond, len(o.Series), c.step, c.buckets)
		}
		if o.Totals.Events != 6 {
			t.Errorf("%v: %d events, want 6", c.d, o.Totals.Events)
		}
	}
}

func TestOverview_BadRequests(t *testing.T) {
	s, base := overviewServer(t)
	for name, q := range map[string]url.Values{
		"too long":    window(base, 32*24*time.Hour),
		"reversed":    {"from": {base.Format(time.RFC3339)}, "to": {base.Add(-time.Hour).Format(time.RFC3339)}},
		"bad from":    {"from": {"yesterday"}},
		"bad step":    {"step": {"5m"}},
		"step syntax": {"step": {"hourly"}},
	} {
		rec, _ := getOverview(t, s, "operator", q)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, rec.Code)
		}
	}
	if rec, _ := getOverview(t, s, "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status %d, want 401", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/stats/overview", nil)
	req.Header.Set("Authorization", "Bearer operator")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d, want 405", rec.Code)
	}
}

func TestOverview_DefaultsToLast24Hours(t *testing.T) {
	store := ingest.NewMockEventStore()
	_ = store.SaveEvents(t.Context(), []ingest.Event{
		{BlockID: "STR-0000-0000-0000-0009", Timestamp: time.Now().Add(-time.Hour), Action: "block", PolicyID: "example-api"},
		{BlockID: "STR-0000-0000-0000-0010", Timestamp: time.Now().Add(-25 * time.Hour), Action: "block", PolicyID: "example-api"},
	})
	s := NewServer(ServerConfig{Auth: tokenRoles{}}, store)
	rec, o := getOverview(t, s, "viewer", nil)
	if rec.Code != http.StatusOK || o.Totals.Events != 1 {
		t.Errorf("status %d, totals %+v; want 1 event in the last 24 h", rec.Code, o.Totals)
	}
}

func TestPathPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"/v1/verify/abc?x=1": "/v1/verify",
		"/v1/verify":         "/v1/verify",
		"/search?q=1":        "/search",
		"/":                  "/",
		"":                   "",
		"/a/b/c/d#frag":      "/a/b",
	} {
		if got := ingest.PathPrefix(in); got != want {
			t.Errorf("PathPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
