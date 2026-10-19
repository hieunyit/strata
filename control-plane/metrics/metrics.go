// Package metrics exports the control plane's Prometheus metrics (W10-Q-01):
// the REST API, deploys, nodes, rollouts and event ingest. They are served
// on their own listener (-metrics-addr), without authentication, for the
// scraper only; nothing in them names a client or carries event content.
package metrics

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/strata/strata/control-plane/admin"
	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/policy"
	"github.com/strata/strata/control-plane/store"
)

// Metrics owns one registry; the zero value is not usable, call New.
type Metrics struct {
	Registry *prometheus.Registry

	httpRequests *prometheus.CounterVec
	httpSeconds  *prometheus.HistogramVec
	deploys      *prometheus.CounterVec
	deploySecs   prometheus.Histogram
}

// New registers the process and build metrics and the request and deploy
// counters.
func New(version, commit string) *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "strata_cp_http_requests_total",
			Help: "REST requests, by route pattern and status class (2xx, 4xx, 5xx).",
		}, []string{"route", "code"}),
		httpSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "strata_cp_http_request_seconds",
			Help:    "REST request duration, by route pattern.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{"route"}),
		deploys: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "strata_cp_deploys_total",
			Help: "Policy deploys (compile, sign, store, start a rollout), by result.",
		}, []string{"result"}),
		deploySecs: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "strata_cp_deploy_seconds",
			Help:    "Duration of a deploy, compile and signature included.",
			Buckets: []float64{.5, 1, 2, 5, 10, 20, 30, 60, 120, 300},
		}),
	}
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "strata_cp_build_info",
		Help:        "Always 1; the labels name the running build.",
		ConstLabels: prometheus.Labels{"version": version, "commit": commit},
	})
	info.Set(1)
	m.Registry.MustRegister(m.httpRequests, m.httpSeconds, m.deploys, m.deploySecs, info,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler serves the registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}

// HTTP counts the requests next serves, labelled by Route.
func (m *Metrics) HTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		route := Route(r.URL.Path)
		m.httpRequests.WithLabelValues(route, strconv.Itoa(sw.code/100)+"xx").Inc()
		m.httpSeconds.WithLabelValues(route).Observe(time.Since(start).Seconds())
	})
}

// The resources, sub-resources and custom verbs of the REST API
// (docs/spec/openapi.yaml, proto/strata/admin). Route keeps only these, so
// a client cannot grow the label set by sending made-up paths.
var (
	resources = map[string]bool{"events": true, "policies": true, "nodes": true, "rollouts": true,
		"commands": true, "bundles": true, "groups": true, "rules": true, "audit": true, "stats": true, "version": true, "users": true}
	// authPaths are fixed paths, not resources with ids.
	authPaths = map[string]bool{"/v1/auth/login": true, "/v1/auth/logout": true, "/v1/auth/me": true,
		"/v1/auth/methods": true, "/v1/auth/password": true}
	subresources = map[string]bool{"versions": true, "enrollmentTokens": true}
	verbs        = map[string]bool{"search": true, "deploy": true, "abort": true, "pause": true, "resume": true,
		"forceShadow": true, "clearForceShadow": true, "collectDiagnostics": true,
		"emergencyDisable": true, "enable": true, "disabled": true}
)

// Route maps a request path to a bounded label: /v1/<resource>[:verb],
// /v1/<resource>/{id}[/<sub-resource>[/{id}]][:verb], /healthz, or "other".
func Route(path string) string {
	if path == "/healthz" || authPaths[path] {
		return path
	}
	rest, ok := strings.CutPrefix(path, "/v1/")
	if !ok {
		return "other"
	}
	segs := strings.Split(rest, "/")
	if len(segs) > 4 {
		return "other"
	}
	last := len(segs) - 1
	verb := ""
	if i := strings.LastIndexByte(segs[last], ':'); i >= 0 {
		segs[last], verb = segs[last][:i], segs[last][i+1:]
	}
	if !resources[segs[0]] {
		return "other"
	}
	out := "/v1/" + segs[0]
	for i, seg := range segs[1:] {
		switch {
		case i%2 == 0:
			out += "/{id}"
		case subresources[seg]:
			out += "/" + seg
		default:
			return out + "/other"
		}
	}
	if verb != "" {
		if !verbs[verb] {
			return out + ":other"
		}
		out += ":" + verb
	}
	return out
}

type statusWriter struct {
	http.ResponseWriter
	code    int
	written bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.written {
		s.code, s.written = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.written = true
	return s.ResponseWriter.Write(b)
}

// Flush keeps streaming responses working through the wrapper.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the real writer.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Deployer counts the deploys of inner.
func (m *Metrics) Deployer(inner admin.Deployer) admin.Deployer {
	return deployer{m: m, inner: inner}
}

type deployer struct {
	m     *Metrics
	inner admin.Deployer
}

func (d deployer) Deploy(ctx context.Context, a store.Audit) (policy.Deployment, error) {
	start := time.Now()
	dep, err := d.inner.Deploy(ctx, a)
	d.m.deploySecs.Observe(time.Since(start).Seconds())
	result := "ok"
	if err != nil {
		result = "error"
	}
	d.m.deploys.WithLabelValues(result).Inc()
	return dep, err
}

// Sources are what the state collector reads at each scrape; a nil one
// is skipped.
type Sources struct {
	// Connected lists the nodes with an open stream (fleet.Presence).
	Connected func() []string
	// Enrolled and Active read PostgreSQL.
	Enrolled func(context.Context) ([]string, error)
	Active   func(context.Context) ([]store.Rollout, error)
	// Ingest gives the event ingest counters.
	Ingest func() ingest.IngestStats
	// IngestErrors counts failed writes to the event store.
	IngestErrors func() uint64
	// CanaryTrips: the canary fallbacks this replica made, by reason;
	// OpenTrips reads the open ones (W12-G2-01).
	CanaryTrips func() map[string]uint64
	OpenTrips   func(context.Context) ([]store.CanaryTrip, error)
	Now         func() time.Time

	// CanarySourceSaturations counts incomplete source buckets across groups.
	CanarySourceSaturations func() uint64
}

// Watch registers a collector over s.
func (m *Metrics) Watch(s Sources) {
	if s.Now == nil {
		s.Now = time.Now
	}
	m.Registry.MustRegister(stateCollector{s})
}

var (
	dConnected    = prometheus.NewDesc("strata_cp_nodes_connected", "Nodes with an open stream to this control plane.", nil, nil)
	dEnrolled     = prometheus.NewDesc("strata_cp_nodes_enrolled", "Enrolled nodes that are not revoked.", nil, nil)
	dRollouts     = prometheus.NewDesc("strata_cp_rollouts_active", "Rollouts that have not finished.", nil, nil)
	dRolloutAge   = prometheus.NewDesc("strata_cp_rollout_oldest_seconds", "Age of the oldest unfinished rollout (0 without one).", nil, nil)
	dStoreUp      = prometheus.NewDesc("strata_cp_store_up", "1 when the last PostgreSQL read of the scrape worked.", nil, nil)
	dBatches      = prometheus.NewDesc("strata_cp_ingest_batches_total", "Event batches received from agents, by result.", []string{"result"}, nil)
	dEvents       = prometheus.NewDesc("strata_cp_ingest_events_total", "Events received from agents, by result.", []string{"result"}, nil)
	dFlushed      = prometheus.NewDesc("strata_cp_ingest_events_stored_total", "Events written to the event store.", nil, nil)
	dGeoIPErrors  = prometheus.NewDesc("strata_cp_ingest_geoip_errors_total", "Failed GeoIP enrichment attempts; valid security events are still persisted.", nil, nil)
	dQueue        = prometheus.NewDesc("strata_cp_ingest_queue", "Events waiting to be written to the event store.", nil, nil)
	dStoreErrors  = prometheus.NewDesc("strata_cp_ingest_store_errors_total", "Writes to the event store that failed.", nil, nil)
	dTrips        = prometheus.NewDesc("strata_cp_canary_trips_total", "Canary fallbacks this control plane made (canary policies of a connector group forced into shadow), by reason.", []string{"reason"}, nil)
	dSourceFull   = prometheus.NewDesc("strata_cp_canary_source_saturations_total", "Canary source buckets that overflowed; block-rate decisions and learning pause until their windows expire.", nil, nil)
	dTripOpen     = prometheus.NewDesc("strata_cp_canary_fallback_active", "1 while a connector group's canary policies are held in shadow by the canary fallback.", []string{"group", "reason"}, nil)
	scrapeTimeout = 3 * time.Second
)

type stateCollector struct{ s Sources }

func (c stateCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{dConnected, dEnrolled, dRollouts, dRolloutAge, dStoreUp,
		dBatches, dEvents, dFlushed, dGeoIPErrors, dQueue, dStoreErrors, dTrips, dTripOpen, dSourceFull} {
		ch <- d
	}
}

func (c stateCollector) Collect(ch chan<- prometheus.Metric) {
	gauge := func(d *prometheus.Desc, v float64, l ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, l...)
	}
	counter := func(d *prometheus.Desc, v uint64, l ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v), l...)
	}
	s := c.s
	if s.CanarySourceSaturations != nil {
		counter(dSourceFull, s.CanarySourceSaturations())
	}
	if s.Connected != nil {
		gauge(dConnected, float64(len(s.Connected())))
	}
	if s.Enrolled != nil || s.Active != nil {
		ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
		defer cancel()
		up := 1.0
		if s.Enrolled != nil {
			if nodes, err := s.Enrolled(ctx); err == nil {
				gauge(dEnrolled, float64(len(nodes)))
			} else {
				up = 0
			}
		}
		if s.Active != nil {
			if ros, err := s.Active(ctx); err == nil {
				gauge(dRollouts, float64(len(ros)))
				oldest := 0.0
				for _, ro := range ros {
					oldest = max(oldest, s.Now().Sub(ro.CreatedAt).Seconds())
				}
				gauge(dRolloutAge, oldest)
			} else {
				up = 0
			}
		}
		gauge(dStoreUp, up)
	}
	if s.CanaryTrips != nil {
		t := s.CanaryTrips()
		for _, r := range []string{"block_rate", "upstream_5xx", "latency"} {
			counter(dTrips, t[r], r)
		}
	}
	if s.OpenTrips != nil {
		ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
		defer cancel()
		if trips, err := s.OpenTrips(ctx); err == nil {
			for _, t := range trips {
				gauge(dTripOpen, 1, t.GroupID, t.Reason)
			}
		}
	}
	if s.Ingest != nil {
		st := s.Ingest()
		// received = accepted + duplicate + failed (not persisted, not
		// acked); the counters are read one by one, so clamp at 0.
		failed := uint64(0)
		if done := st.TotalBatchesAccepted + st.TotalBatchesDropped; st.TotalBatchesReceived > done {
			failed = st.TotalBatchesReceived - done
		}
		counter(dBatches, st.TotalBatchesAccepted, "accepted")
		counter(dBatches, st.TotalBatchesDropped, "duplicate")
		counter(dBatches, failed, "failed")
		counter(dEvents, st.TotalEventsValid, "valid")
		counter(dEvents, st.TotalEventsInvalid, "invalid")
		counter(dFlushed, st.TotalEventsFlushed)
		counter(dGeoIPErrors, st.TotalGeoIPErrors)
		gauge(dQueue, float64(st.BufferQueueLen))
	}
	if s.IngestErrors != nil {
		counter(dStoreErrors, s.IngestErrors())
	}
}
