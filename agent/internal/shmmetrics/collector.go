package shmmetrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var actions = [4]string{"allow", "log", "challenge", "block"}

var (
	dUp       = prometheus.NewDesc("strata_metrics_file_up", "1 when the NGINX metrics file was read and follows the layout.", nil, nil)
	dWorkers  = prometheus.NewDesc("strata_workers", "NGINX workers with a slot in the metrics file.", nil, nil)
	dRequests = prometheus.NewDesc("strata_requests_total", "Requests inspected, by action.", []string{"action"}, nil)
	dEngine   = prometheus.NewDesc("strata_engine_seconds", "Time spent in libstrata per request.", nil, nil)
	dBody     = prometheus.NewDesc("strata_body_inspected_bytes_total", "Body bytes inspected.", nil, nil)
	dFail     = prometheus.NewDesc("strata_fail_mode_total", "Requests handled by the fail mode, by mode.", []string{"mode"}, nil)
	dDropped  = prometheus.NewDesc("strata_events_dropped_total", "Events a worker dropped because the event socket was full.", nil, nil)
	dBudget   = prometheus.NewDesc("strata_budget_exceeded_total", "Requests that ran over the CPU budget.", nil, nil)
	dBundle   = prometheus.NewDesc("strata_bundle_version", "Bundle version running in each worker.", []string{"worker"}, nil)
	dBreaker  = prometheus.NewDesc("strata_breaker_state", "Circuit breaker of each worker: 0 closed, 1 open, 2 half-open.", []string{"worker"}, nil)
	dOpens    = prometheus.NewDesc("strata_breaker_opens_total", "Times a worker circuit breaker opened.", nil, nil)
	dDegraded = prometheus.NewDesc("strata_degraded_requests_total", "Requests run in degraded mode (circuit breaker open or half-open).", nil, nil)
	// W12-G2-01: requests of policies with an enforce canary, by group
	// (canary: inside, enforced; shadow: outside)
	dCanaryReq     = prometheus.NewDesc("strata_canary_requests_total", "Requests of policies with an enforce canary, by canary group.", []string{"group"}, nil)
	dCanaryBlocked = prometheus.NewDesc("strata_canary_blocked_total", "Of those, blocked, by canary group.", []string{"group"}, nil)
	dCanaryLogged  = prometheus.NewDesc("strata_canary_logged_total", "Of those, logged (in shadow: would have been blocked), by canary group.", []string{"group"}, nil)
	dCanary5xx     = prometheus.NewDesc("strata_canary_upstream_5xx_total", "Of those, answered 5xx by the upstream, by canary group.", []string{"group"}, nil)
	dCanaryLatency = prometheus.NewDesc("strata_canary_request_seconds", "Request latency of those, by canary group.", []string{"group"}, nil)
)

var canaryGroups = [2]string{"canary", "shadow"}

// Collector exports one metrics file.
type Collector struct {
	path string
}

// NewCollector reads path at each scrape.
func NewCollector(path string) *Collector { return &Collector{path: path} }

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{dUp, dWorkers, dRequests, dEngine, dBody, dFail, dDropped, dBudget, dBundle, dBreaker, dOpens, dDegraded,
		dCanaryReq, dCanaryBlocked, dCanaryLogged, dCanary5xx, dCanaryLatency} {
		ch <- d
	}
}

// Collect implements prometheus.Collector. A missing or malformed file
// only sets strata_metrics_file_up to 0.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	s, err := Read(c.path)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(dUp, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(dUp, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(dWorkers, prometheus.GaugeValue, float64(len(s.Workers)))

	var req [4]uint64
	var body, open, closed, dropped, budget, nanos, opens, degraded uint64
	hasBreaker := false
	buckets := make([]uint64, len(BucketBounds)+1)
	for _, w := range s.Workers {
		for i := range req {
			req[i] += w.Requests[i]
		}
		body += w.BodyBytes
		open += w.FailOpen
		closed += w.FailClosed
		dropped += w.EventsDropped
		budget += w.BudgetExceed
		nanos += w.EngineNanos
		for i, n := range w.EngineBuckets {
			buckets[i] += n
		}
		ch <- prometheus.MustNewConstMetric(dBundle, prometheus.GaugeValue, float64(w.BundleVersion), strconv.Itoa(w.Index))
		if w.HasBreaker {
			hasBreaker = true
			opens += w.BreakerOpens
			degraded += w.Degraded
			ch <- prometheus.MustNewConstMetric(dBreaker, prometheus.GaugeValue, float64(w.BreakerState), strconv.Itoa(w.Index))
		}
	}
	if hasBreaker {
		ch <- prometheus.MustNewConstMetric(dOpens, prometheus.CounterValue, float64(opens))
		ch <- prometheus.MustNewConstMetric(dDegraded, prometheus.CounterValue, float64(degraded))
	}
	for i, a := range actions {
		ch <- prometheus.MustNewConstMetric(dRequests, prometheus.CounterValue, float64(req[i]), a)
	}
	cum := make(map[float64]uint64, len(BucketBounds))
	var total uint64
	for i, bound := range BucketBounds {
		total += buckets[i]
		cum[bound] = total
	}
	total += buckets[len(BucketBounds)]
	ch <- prometheus.MustNewConstHistogram(dEngine, total, float64(nanos)/1e9, cum)
	ch <- prometheus.MustNewConstMetric(dBody, prometheus.CounterValue, float64(body))
	ch <- prometheus.MustNewConstMetric(dFail, prometheus.CounterValue, float64(open), "open")
	ch <- prometheus.MustNewConstMetric(dFail, prometheus.CounterValue, float64(closed), "closed")
	ch <- prometheus.MustNewConstMetric(dDropped, prometheus.CounterValue, float64(dropped))
	ch <- prometheus.MustNewConstMetric(dBudget, prometheus.CounterValue, float64(budget))
	if g, ok := s.Canary(); ok {
		for i, name := range canaryGroups {
			ch <- prometheus.MustNewConstMetric(dCanaryReq, prometheus.CounterValue, float64(g[i].Requests), name)
			ch <- prometheus.MustNewConstMetric(dCanaryBlocked, prometheus.CounterValue, float64(g[i].Blocked), name)
			ch <- prometheus.MustNewConstMetric(dCanaryLogged, prometheus.CounterValue, float64(g[i].Logged), name)
			ch <- prometheus.MustNewConstMetric(dCanary5xx, prometheus.CounterValue, float64(g[i].Upstream5xx), name)
			cum := make(map[float64]uint64, len(LatencyBounds))
			var n uint64
			for b, bound := range LatencyBounds {
				n += g[i].Latency[b]
				cum[bound] = n
			}
			n += g[i].Latency[len(LatencyBounds)]
			// the module keeps no latency sum
			ch <- prometheus.MustNewConstHistogram(dCanaryLatency, n, 0, cum, name)
		}
	}
}

// Serve exposes reg on addr at /metrics until ctx is done.
func Serve(ctx context.Context, addr string, reg *prometheus.Registry) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("shmmetrics: listen %s: %w", addr, err)
	}
	return ServeListener(ctx, ln, reg)
}

// ServeListener is Serve on an open listener.
func ServeListener(ctx context.Context, ln net.Listener, reg *prometheus.Registry) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	stop := context.AfterFunc(ctx, func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	})
	defer stop()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("shmmetrics: serve: %w", err)
	}
	return nil
}
