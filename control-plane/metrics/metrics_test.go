package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

func TestRoute(t *testing.T) {
	for path, want := range map[string]string{
		"/healthz":                              "/healthz",
		"/v1/events:search":                     "/v1/events:search",
		"/v1/events/STR-D16E-F7W4-JHTR-Y9D8":    "/v1/events/{id}",
		"/v1/policies/example-api:deploy":       "/v1/policies/{id}:deploy",
		"/v1/nodes:forceShadow":                 "/v1/nodes:forceShadow",
		"/v1/nodes/node-a:collectDiagnostics":   "/v1/nodes/{id}:collectDiagnostics",
		"/v1/rollouts/1:abort":                  "/v1/rollouts/{id}:abort",
		"/v1/commands/a/b/c":                    "/v1/commands/{id}/other",
		"/v1/version":                           "/v1/version",
		"/v1/groups/lab/enrollmentTokens":       "/v1/groups/{id}/enrollmentTokens",
		"/v1/policies/example-api/versions/3":   "/v1/policies/{id}/versions/{id}",
		"/v1/policies/example-api/x-attacker-4": "/v1/policies/{id}/other",
		"/v1/policies/a/versions/3/x/y":         "other",
		"/v1/auth/login":                        "/v1/auth/login",
		"/v1/auth/x-attacker-5":                 "other",
		"/v1/users/alice":                       "/v1/users/{id}",
		// made-up resources, verbs and paths do not make new labels
		"/v1/x-attacker-1":        "other",
		"/v1/nodes:x-attacker-2":  "/v1/nodes:other",
		"/v1/nodes/a:x-attacker3": "/v1/nodes/{id}:other",
		"/v2/events":              "other",
		"/":                       "other",
		"/v1/../etc/passwd":       "other",
		"":                        "other",
	} {
		if got := Route(path); got != want {
			t.Errorf("Route(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestHTTPCountsByRouteAndClass(t *testing.T) {
	m := New("1.2.3", "abc")
	h := m.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":search"):
			_, _ = w.Write([]byte("{}")) // implicit 200
		case strings.HasPrefix(r.URL.Path, "/v1/events/"):
			http.Error(w, "nope", http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			w.WriteHeader(http.StatusOK) // ignored by net/http: the first one counts
		}
	}))
	for _, p := range []string{"/v1/events:search", "/v1/events:search", "/v1/events/STR-1", "/v1/nodes"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	for _, c := range []struct {
		route, code string
		want        float64
	}{
		{"/v1/events:search", "2xx", 2},
		{"/v1/events/{id}", "4xx", 1},
		{"/v1/nodes", "5xx", 1},
		{"/v1/nodes", "2xx", 0},
	} {
		if got := testutil.ToFloat64(m.httpRequests.WithLabelValues(c.route, c.code)); got != c.want {
			t.Errorf("%s %s = %v, want %v", c.route, c.code, got, c.want)
		}
	}
	if n := testutil.CollectAndCount(m.httpSeconds); n != 3 {
		t.Errorf("duration series = %d, want 3 routes", n)
	}
}

type fakeDeployer struct{ err error }

func (f fakeDeployer) Deploy(context.Context, store.Audit) (policy.Deployment, error) {
	return policy.Deployment{}, f.err
}

func TestDeployerCountsResults(t *testing.T) {
	m := New("dev", "")
	ok, bad := m.Deployer(fakeDeployer{}), m.Deployer(fakeDeployer{err: errors.New("compile failed")})
	_, _ = ok.Deploy(context.Background(), store.Audit{})
	if _, err := bad.Deploy(context.Background(), store.Audit{}); err == nil {
		t.Fatal("the error of the inner deployer was lost")
	}
	_, _ = bad.Deploy(context.Background(), store.Audit{})
	if got := testutil.ToFloat64(m.deploys.WithLabelValues("ok")); got != 1 {
		t.Errorf("ok = %v", got)
	}
	if got := testutil.ToFloat64(m.deploys.WithLabelValues("error")); got != 2 {
		t.Errorf("error = %v", got)
	}
}

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape: %d %s", rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func TestStateCollector(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	m := New("dev", "")
	m.Watch(Sources{
		Connected: func() []string { return []string{"node-a"} },
		Enrolled:  func(context.Context) ([]string, error) { return []string{"node-a", "node-b"}, nil },
		Active: func(context.Context) ([]store.Rollout, error) {
			return []store.Rollout{{CreatedAt: now.Add(-10 * time.Minute)}, {CreatedAt: now.Add(-time.Minute)}}, nil
		},
		Ingest: func() ingest.IngestStats {
			return ingest.IngestStats{TotalBatchesReceived: 10, TotalBatchesAccepted: 7, TotalBatchesDropped: 2,
				TotalEventsValid: 50, TotalEventsInvalid: 3, TotalEventsFlushed: 48, TotalGeoIPErrors: 5, BufferQueueLen: 2}
		},
		IngestErrors:            func() uint64 { return 4 },
		CanaryTrips:             func() map[string]uint64 { return map[string]uint64{"block_rate": 1} },
		CanarySourceSaturations: func() uint64 { return 3 },
		OpenTrips: func(context.Context) ([]store.CanaryTrip, error) {
			return []store.CanaryTrip{{GroupID: "edge", Reason: "block_rate"}}, nil
		},
		Now:                 func() time.Time { return now },
		GeoIPLastUpdate:     func() time.Time { return now },
		GeoIPUpdateFailures: func() uint64 { return 2 },
		GoodBotsLastUpdate:  func() time.Time { return now },
		GoodBotsFailures:    func() uint64 { return 1 },
	})
	out := scrape(t, m)
	for _, want := range []string{
		"strata_cp_geoip_update_last_success_timestamp_seconds 1.7918928e+09",
		"strata_cp_geoip_update_failures_total 2",
		"strata_cp_good_bots_update_last_success_timestamp_seconds 1.7918928e+09",
		"strata_cp_good_bots_update_failures_total 1",
		"strata_cp_nodes_connected 1",
		"strata_cp_nodes_enrolled 2",
		"strata_cp_rollouts_active 2",
		"strata_cp_rollout_oldest_seconds 600",
		"strata_cp_store_up 1",
		`strata_cp_ingest_batches_total{result="accepted"} 7`,
		`strata_cp_ingest_batches_total{result="duplicate"} 2`,
		`strata_cp_ingest_batches_total{result="failed"} 1`,
		`strata_cp_ingest_events_total{result="invalid"} 3`,
		"strata_cp_ingest_events_stored_total 48",
		"strata_cp_ingest_geoip_errors_total 5",
		"strata_cp_ingest_queue 2",
		"strata_cp_ingest_store_errors_total 4",
		`strata_cp_build_info{commit="",version="dev"} 1`,
		`strata_cp_canary_trips_total{reason="block_rate"} 1`,
		`strata_cp_canary_trips_total{reason="latency"} 0`,
		"strata_cp_canary_source_saturations_total 3",
		`strata_cp_canary_fallback_active{group="edge",reason="block_rate"} 1`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
}

// A PostgreSQL outage shows as store_up 0, not as a failed scrape, and the
// series that could not be read are left out rather than reported as 0.
func TestStateCollectorStoreDown(t *testing.T) {
	m := New("dev", "")
	down := errors.New("connection refused")
	m.Watch(Sources{
		Enrolled: func(context.Context) ([]string, error) { return nil, down },
		Active:   func(context.Context) ([]store.Rollout, error) { return nil, down },
		Ingest: func() ingest.IngestStats {
			// read while a batch is in flight: accepted+duplicate > received
			return ingest.IngestStats{TotalBatchesReceived: 3, TotalBatchesAccepted: 3, TotalBatchesDropped: 1}
		},
	})
	out := scrape(t, m)
	if !strings.Contains(out, "strata_cp_store_up 0\n") {
		t.Error("store_up is not 0")
	}
	for _, absent := range []string{"strata_cp_nodes_enrolled ", "strata_cp_rollouts_active ", "strata_cp_nodes_connected "} {
		if strings.Contains(out, absent) {
			t.Errorf("%q reported without data", absent)
		}
	}
	if !strings.Contains(out, `strata_cp_ingest_batches_total{result="failed"} 0`+"\n") {
		t.Error("failed batches did not clamp at 0")
	}
}
