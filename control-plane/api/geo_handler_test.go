package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
)

// fakeGeo serves rows that a test can change between reads.
type fakeGeo struct {
	*ingest.MockEventStore
	mu      sync.Mutex
	last    ingest.GeoFilter
	group   string
	step    time.Duration
	rows    []ingest.GeoCount
	buckets []ingest.GeoBucket
}

func (f *fakeGeo) read(group string, flt ingest.GeoFilter) ([]ingest.GeoCount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last, f.group = flt, group
	return append([]ingest.GeoCount(nil), f.rows...), nil
}
func (f *fakeGeo) GeoByCountry(_ context.Context, flt ingest.GeoFilter) ([]ingest.GeoCount, error) {
	return f.read("country", flt)
}
func (f *fakeGeo) GeoByASN(_ context.Context, flt ingest.GeoFilter) ([]ingest.GeoCount, error) {
	return f.read("asn", flt)
}
func (f *fakeGeo) GeoByAttackType(_ context.Context, flt ingest.GeoFilter) ([]ingest.GeoCount, error) {
	return f.read("attack_type", flt)
}
func (f *fakeGeo) GeoByCell(_ context.Context, flt ingest.GeoFilter) ([]ingest.GeoCount, error) {
	return f.read("city", flt)
}
func (f *fakeGeo) GeoTimeline(_ context.Context, flt ingest.GeoFilter, step time.Duration) ([]ingest.GeoBucket, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last, f.step = flt, step
	return f.buckets, nil
}
func (f *fakeGeo) set(rows ...ingest.GeoCount) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = rows
}

func geoServer(t *testing.T) (*Server, *fakeGeo) {
	t.Helper()
	g := &fakeGeo{MockEventStore: ingest.NewMockEventStore()}
	return NewServer(ServerConfig{Auth: tokenRoles{}}, g), g
}

func getJSON(t *testing.T, s *Server, path, token string, out any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	return rec.Code
}

func TestGeoStats_FiltersAndGroups(t *testing.T) {
	s, g := geoServer(t)
	g.set(ingest.GeoCount{Key: "VN", Events: 4, Blocked: 3, TopAttack: "sqli"})
	var resp GeoResponse
	if code := getJSON(t, s, "/v1/stats/geo", "viewer", &resp); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if resp.GroupBy != "country" || g.group != "country" || len(resp.Rows) != 1 || !resp.Approximate ||
		resp.To.Sub(resp.From) != 24*time.Hour {
		t.Fatalf("default: %+v (store got %s)", resp, g.group)
	}
	q := "/v1/stats/geo?groupBy=asn&from=2026-10-01T00:00:00Z&to=2026-10-02T00:00:00Z&policy_id=example-api" +
		"&action=block&attack_type=sqli&country=VN&asn=7552&limit=5"
	if code := getJSON(t, s, q, "viewer", &resp); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	want := ingest.GeoFilter{From: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC),
		PolicyID: "example-api", Action: "block", AttackType: "sqli", CountryISO: "VN", ASN: 7552, Limit: 5}
	if g.last != want || g.group != "asn" {
		t.Fatalf("filter %+v, want %+v", g.last, want)
	}
	for _, by := range []string{"city", "attack_type"} {
		if code := getJSON(t, s, "/v1/stats/geo?groupBy="+by, "viewer", nil); code != http.StatusOK || g.group != by {
			t.Fatalf("%s: %d %s", by, code, g.group)
		}
	}
	g.set()
	if code := getJSON(t, s, "/v1/stats/geo", "viewer", &resp); code != http.StatusOK || resp.Rows == nil {
		t.Fatalf("empty rows must be [], got %v", resp.Rows)
	}

	for _, bad := range []string{
		"groupBy=region", "from=yesterday", "to=2026-10-01", "from=2026-10-02T00:00:00Z&to=2026-10-01T00:00:00Z",
		"from=2025-01-01T00:00:00Z&to=2026-10-01T00:00:00Z", "action=monitor", "attack_type=anomaly",
		"country=vn", "country=VNM", "asn=0", "asn=-1", "asn=4294967296", "limit=0", "limit=1001",
		"policy_id=" + strings.Repeat("p", 257),
	} {
		if code := getJSON(t, s, "/v1/stats/geo?"+bad, "viewer", nil); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}
	if code := getJSON(t, s, "/v1/stats/geo", "", nil); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	plain := NewServer(ServerConfig{Auth: tokenRoles{}}, ingest.NewMockEventStore())
	if code := getJSON(t, plain, "/v1/stats/geo", "viewer", nil); code != http.StatusNotImplemented {
		t.Errorf("store without aggregates: %d", code)
	}
	if code := getJSON(t, s, "/v1/stats/geo?country=INTERNAL", "viewer", nil); code != http.StatusOK {
		t.Errorf("INTERNAL: %d", code)
	}
}

func TestTimeline_Steps(t *testing.T) {
	s, g := geoServer(t)
	g.buckets = []ingest.GeoBucket{{Start: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Block: 1}}
	var resp TimelineResponse
	if code := getJSON(t, s, "/v1/stats/timeline", "viewer", &resp); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if g.step != time.Hour || resp.Step != "1h0m0s" || len(resp.Buckets) != 1 || !resp.Approximate {
		t.Fatalf("default step for 24 h: %s %+v", g.step, resp)
	}
	for q, want := range map[string]time.Duration{
		"from=2026-10-01T00:00:00Z&to=2026-10-01T01:00:00Z":         time.Minute,
		"from=2026-10-01T00:00:00Z&to=2026-10-01T10:00:00Z":         5 * time.Minute,
		"from=2026-09-01T00:00:00Z&to=2026-10-01T00:00:00Z":         6 * time.Hour,
		"from=2026-01-01T00:00:00Z&to=2026-10-01T00:00:00Z":         24 * time.Hour,
		"from=2026-10-01T00:00:00Z&to=2026-10-02T00:00:00Z&step=1m": time.Minute,
		"": time.Hour, // default window: 24 hours
	} {
		if code := getJSON(t, s, "/v1/stats/timeline?"+q, "viewer", nil); code != http.StatusOK || g.step != want {
			t.Errorf("%s: %d step %s, want %s", q, code, g.step, want)
		}
	}
	for _, bad := range []string{"step=2m", "step=1d", "from=2026-09-01T00:00:00Z&to=2026-10-01T00:00:00Z&step=1m",
		"from=2026-10-01T00:00:00Z&to=2026-10-02T01:00:00Z&step=1m"} {
		if code := getJSON(t, s, "/v1/stats/timeline?"+bad, "viewer", nil); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}
}

type sseEvent struct{ name, data string }

// readSSE sends events of the stream at r until it ends.
func readSSE(r *bufio.Reader, out chan<- sseEvent) {
	defer close(out)
	var ev sseEvent
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case line == "":
			if ev.name != "" || ev.data != "" {
				out <- ev
			}
			ev = sseEvent{}
		case strings.HasPrefix(line, ":"):
			out <- sseEvent{name: "comment"}
		case strings.HasPrefix(line, "event: "):
			ev.name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			ev.data = strings.TrimPrefix(line, "data: ")
		}
	}
}

func next(t *testing.T, ch <-chan sseEvent, name string, within time.Duration) sseEvent {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("stream ended waiting for %s", name)
			}
			if ev.name == name {
				return ev
			}
		case <-deadline:
			t.Fatalf("no %s within %s", name, within)
		}
	}
}

// The stream outlives the server's 1 s read and write timeouts and the
// request timeout; snapshot, then deltas with what changed.
func TestGeoWatch_SnapshotDeltasAndTimeouts(t *testing.T) {
	g := &fakeGeo{MockEventStore: ingest.NewMockEventStore()}
	s := NewServer(ServerConfig{Auth: tokenRoles{}, WriteTimeout: time.Second}, g)
	hs := httptest.NewUnstartedServer(s.Handler())
	hs.Config.ReadTimeout, hs.Config.WriteTimeout = time.Second, time.Second
	hs.Start()
	t.Cleanup(hs.Close)
	g.set(ingest.GeoCount{Key: "VN", Events: 1, Blocked: 1, TopAttack: "sqli"},
		ingest.GeoCount{Key: "US", Events: 2, TopAttack: "scanner"})

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
		hs.URL+"/v1/stats/geo:watch?interval=2s&window=30m&policy_id=example-api", nil)
	req.Header.Set("Authorization", "Bearer viewer")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	events := make(chan sseEvent, 16)
	go readSSE(bufio.NewReader(resp.Body), events)

	var snap GeoSnapshot
	if err := json.Unmarshal([]byte(next(t, events, "snapshot", 3*time.Second).data), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Rows) != 2 || snap.GroupBy != "country" || snap.To.Sub(snap.From) != 30*time.Minute+time.Second {
		t.Fatalf("snapshot %+v", snap)
	}
	g.mu.Lock()
	if g.last.PolicyID != "example-api" {
		t.Errorf("filter not applied: %+v", g.last)
	}
	g.mu.Unlock()

	// after the server's timeouts: VN changed, US gone, CN new
	time.Sleep(1500 * time.Millisecond)
	g.set(ingest.GeoCount{Key: "VN", Events: 2, Blocked: 2, TopAttack: "sqli"},
		ingest.GeoCount{Key: "CN", Events: 1, TopAttack: "bot"})
	var d GeoDelta
	if err := json.Unmarshal([]byte(next(t, events, "delta", 5*time.Second).data), &d); err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for _, c := range d.Changed {
		keys = append(keys, c.Key)
	}
	if strings.Join(keys, ",") != "VN,CN" || strings.Join(d.Removed, ",") != "US" {
		t.Fatalf("delta %+v", d)
	}
}

func TestGeoWatch_Limits(t *testing.T) {
	s, _ := geoServer(t)
	for _, bad := range []string{"interval=1s", "interval=6s", "window=30s", "window=169h",
		"from=2026-10-01T00:00:00Z", "groupBy=region", "action=monitor"} {
		if code := getJSON(t, s, "/v1/stats/geo:watch?"+bad, "viewer", nil); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}
	if code := getJSON(t, s, "/v1/stats/geo:watch", "", nil); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	// every slot taken: 503
	for range MaxGeoWatchers {
		geoWatchers <- struct{}{}
	}
	code := getJSON(t, s, "/v1/stats/geo:watch", "viewer", nil)
	for range MaxGeoWatchers {
		<-geoWatchers
	}
	if code != http.StatusServiceUnavailable {
		t.Errorf("all streams taken: %d, want 503", code)
	}
	// the query token of the URL is not a credential
	if code := getJSON(t, s, "/v1/stats/geo:watch?token=viewer", "", nil); code != http.StatusUnauthorized {
		t.Errorf("query token: %d", code)
	}
}
