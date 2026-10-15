// Package policycount sums the NGINX workers' per-policy request counts
// (RV-N-01): libstrata sends them on the event socket about once a second
// per worker (eventsock.CountersMagic). The sums since the agent started go
// in every heartbeat, and to Prometheus.
package policycount

import (
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

// MaxPolicies kept; counts of further policy names are dropped (a bundle
// has far fewer policies).
const MaxPolicies = 1024

// Totals is safe for concurrent use.
type Totals struct {
	started time.Time
	mu      sync.Mutex
	m       map[string]*eventv1.PolicyCount
	dropped uint64
}

// New starts the sums at now.
func New(now time.Time) *Totals {
	return &Totals{started: now, m: map[string]*eventv1.PolicyCount{}}
}

// StartedMs: when the sums started (the heartbeat's agent_started_ms).
func (t *Totals) StartedMs() uint64 { return uint64(t.started.UnixMilli()) }

// Add sums one worker's datagram.
func (t *Totals) Add(c *eventv1.PolicyCounters) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range c.GetPolicies() {
		s, ok := t.m[p.GetPolicy()]
		if !ok {
			if len(t.m) >= MaxPolicies {
				t.dropped++
				continue
			}
			s = &eventv1.PolicyCount{Policy: p.GetPolicy()}
			t.m[p.GetPolicy()] = s
		}
		s.Requests += p.GetRequests()
		s.Partial += p.GetPartial()
		s.BodySkipped += p.GetBodySkipped()
		s.Error += p.GetError()
		s.Degraded += p.GetDegraded()
	}
}

// Snapshot: copies of the sums, by policy name.
func (t *Totals) Snapshot() []*eventv1.PolicyCount {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*eventv1.PolicyCount, 0, len(t.m))
	for _, s := range t.m {
		out = append(out, &eventv1.PolicyCount{Policy: s.Policy, Requests: s.Requests, Partial: s.Partial,
			BodySkipped: s.BodySkipped, Error: s.Error, Degraded: s.Degraded})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Policy < out[j].Policy })
	return out
}

var (
	dRequests = prometheus.NewDesc("strata_policy_requests_total",
		"Requests per policy (strata_policy) since the agent started; policy \"\" is a name the bundle does not have.", []string{"policy"}, nil)
	dGap = prometheus.NewDesc("strata_policy_not_inspected_total",
		"Requests per policy not fully inspected (the fail mode decided), by reason: partial (CPU budget), body_skipped, error.", []string{"policy", "reason"}, nil)
	dDegraded = prometheus.NewDesc("strata_policy_degraded_total",
		"Requests per policy the worker's circuit breaker ran degraded.", []string{"policy"}, nil)
)

// Describe implements prometheus.Collector.
func (t *Totals) Describe(ch chan<- *prometheus.Desc) {
	ch <- dRequests
	ch <- dGap
	ch <- dDegraded
}

// Collect implements prometheus.Collector.
func (t *Totals) Collect(ch chan<- prometheus.Metric) {
	for _, s := range t.Snapshot() {
		c := func(d *prometheus.Desc, v uint64, l ...string) {
			ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v), l...)
		}
		c(dRequests, s.Requests, s.Policy)
		c(dGap, s.Partial, s.Policy, "partial")
		c(dGap, s.BodySkipped, s.Policy, "body_skipped")
		c(dGap, s.Error, s.Policy, "error")
		c(dDegraded, s.Degraded, s.Policy)
	}
}
