package api

// W09-G2-01 (review): the targets measured through the REST API, as the
// plan asks, not through the store: a real HTTP server (this package's
// handlers, authentication, JSON encoding), a real ClickHouse filled by
// tests/perf/clickhouse.sh. Skipped unless CLICKHOUSE_PERF_ADDR and
// CLICKHOUSE_PERF_PASSWORD are set; the script sets them.
//
//   GET  /v1/events/{block_id}  200 random Block IDs, p99 under 1 s
//   POST /v1/events:search      24-hour searches with the filters of the
//                               Events page, 10 runs each, p99 under 2 s

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
	pgstore "github.com/strata/strata/control-plane/store"
)

func TestClickHouseAPIPerf(t *testing.T) {
	clickHouseAPIPerf(t, false)
}

func TestClickHouseAPIAnnotatedPerf(t *testing.T) {
	clickHouseAPIPerf(t, true)
}

func clickHouseAPIPerf(t *testing.T, annotated bool) {
	addr := os.Getenv("CLICKHOUSE_PERF_ADDR")
	if addr == "" {
		t.Skip("CLICKHOUSE_PERF_ADDR not set (run tests/perf/clickhouse.sh)")
	}
	ctx := context.Background()
	store, err := ingest.NewClickHouseStore(ctx, ingest.ClickHouseConfig{
		Addr: addr, Database: "default", Username: "strata",
		Password: os.Getenv("CLICKHOUSE_PERF_PASSWORD"), Table: "events",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var annotations *pgstore.Store
	cfg := ServerConfig{Auth: tokenRoles{}}
	if annotated {
		if os.Getenv("STRATA_TEST_POSTGRES_DSN") == "" {
			t.Fatal("annotated API performance requires STRATA_TEST_POSTGRES_DSN")
		}
		annotations = pgstore.New(localauthtest.Pool(t))
		cfg.Annotations = annotations
	}
	ts := httptest.NewServer(NewServer(cfg, store).Handler())
	defer ts.Close()

	call := func(method, path string, body any) (int, []byte, time.Duration) {
		var rd io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rd)
		req.Header.Set("Authorization", "Bearer operator")
		req.Header.Set("Content-Type", "application/json")
		start := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, out, time.Since(start)
	}
	pct := func(d []time.Duration, p float64) time.Duration {
		s := append([]time.Duration(nil), d...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		return s[min(int(float64(len(s))*p), len(s)-1)]
	}

	// 200 Block IDs picked at random over the whole table
	rows, err := store.Conn().Query(ctx, "SELECT block_id FROM events WHERE cityHash64(block_id) % 100000 = 11 LIMIT 200")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) < 100 {
		t.Fatalf("only %d Block IDs sampled: fill the table first", len(ids))
	}
	marked := map[string]bool{}
	if annotated {
		for i, id := range ids {
			if i%10 != 0 {
				continue
			}
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			e, err := store.GetEvent(bounded, id)
			if err == nil {
				_, err = annotations.MarkEventFalsePositive(bounded, id, "benign performance fixture", "", pgstore.Audit{Actor: "example-operator", Subject: "example-operator", RequestID: "perf-" + id, RuleContext: &pgstore.EventRuleContext{BundleVersion: e.PolicyVersion, PolicyID: e.PolicyID, EventTime: e.Timestamp, RuleIDs: e.MatchedRules}})
			}
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			marked[id] = true
		}
		t.Logf("durable PostgreSQL annotation overlay enabled; %d/%d lookup IDs annotated", len(marked), len(ids))
	}
	var lookup []time.Duration
	for _, id := range ids {
		code, body, d := call(http.MethodGet, "/v1/events/"+id, nil)
		var resp GetEventResponse
		if code != http.StatusOK || json.Unmarshal(body, &resp) != nil || resp.Event.BlockID != id {
			t.Fatalf("GET /v1/events/%s: %d %s", id, code, body)
		}
		if annotated && resp.Event.FalsePositive != marked[id] {
			t.Fatalf("annotation overlay missing for %s", id)
		}
		lookup = append(lookup, d)
	}
	code, _, miss := call(http.MethodGet, "/v1/events/STR-0000-0000-0000-0000", nil)
	if code != http.StatusNotFound {
		t.Fatalf("unknown Block ID: %d, want 404", code)
	}
	t.Logf("GET /v1/events/{id}, %d IDs: p50 %v, p99 %v, max %v; unknown ID %v (404)",
		len(lookup), pct(lookup, 0.5), pct(lookup, 0.99), pct(lookup, 1), miss)
	if pct(lookup, 0.99) > time.Second || miss > time.Second {
		t.Errorf("Block ID lookup over 1 s")
	}

	to := time.Now().UTC()
	from := to.Add(-24 * time.Hour)
	searches := []struct {
		name string
		req  SearchEventsRequest
	}{
		{"all", SearchEventsRequest{}},
		{"policy", SearchEventsRequest{PolicyID: "example-api"}},
		{"action block", SearchEventsRequest{Action: "block"}},
		{"rule 942100", SearchEventsRequest{RuleID: 942100}},
		{"client IP", SearchEventsRequest{ClientIP: "203.0.113.1"}},
		{"node + method", SearchEventsRequest{NodeID: "node-3", HTTPMethod: "POST"}},
		{"policy + rule + action", SearchEventsRequest{PolicyID: "example-api", RuleID: 941100, Action: "block"}},
		{"all, page 41", SearchEventsRequest{PageToken: EncodePageToken(2000)}},
	}
	var report []string
	var worst time.Duration
	for _, s := range searches {
		s.req.From, s.req.To, s.req.PageSize = from, to, 50
		var d []time.Duration
		var resp SearchEventsResponse
		for i := 0; i < 10; i++ {
			code, body, took := call(http.MethodPost, "/v1/events:search", s.req)
			if code != http.StatusOK || json.Unmarshal(body, &resp) != nil {
				t.Fatalf("%s: %d %s", s.name, code, body)
			}
			d = append(d, took)
		}
		if len(resp.Events) != 50 {
			t.Errorf("%s: %d events on the page, want 50", s.name, len(resp.Events))
		}
		worst = max(worst, pct(d, 0.99))
		report = append(report, fmt.Sprintf("%-24s total %9d  p50 %8v  p99 %8v", s.name, resp.TotalMatched,
			pct(d, 0.5).Round(time.Millisecond), pct(d, 0.99).Round(time.Millisecond)))
	}
	t.Logf("POST /v1/events:search, 24 hours (count + first 50):\n%s", strings.Join(report, "\n"))
	if worst > 2*time.Second {
		t.Errorf("a 24-hour search took %v (target under 2 s)", worst)
	}
}
