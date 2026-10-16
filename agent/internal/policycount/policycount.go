// Package policycount sums the NGINX workers' per-policy request counts
// (RV-N-01): libstrata sends them on the event socket about once a second
// per worker (eventsock.CountersMagic). The sums since the agent started go
// in every heartbeat, and to Prometheus.
package policycount

import (
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
)

// MaxPolicies kept; counts of further policy names are dropped (a bundle
// has far fewer policies).
const MaxPolicies = 1024

// MaxRuleLabels: rules with a label of their own in the cost metrics
// (W13-R-02); the costs of the others are summed under rule="other".
const MaxRuleLabels = 50

// RuleCostSum: the sampled time of one rule since the agent started.
type RuleCostSum struct {
	Samples, TotalNs, MaxNs uint64
}

// Totals is safe for concurrent use.
type Totals struct {
	started time.Time
	mu      sync.Mutex
	m       map[string]*eventv1.PolicyCount
	dropped uint64

	// W13-R-02: rule costs by label ("prefilter", a Rule ID, "other"). A
	// rule keeps the label it got first: the counters never go down. Rules
	// get one, most expensive first as the engine sends them, while there
	// are fewer than MaxRuleLabels; the later ones go to "other".
	costs           map[string]*RuleCostSum
	sampledRequests uint64
	sampledEngineNs uint64
}

// New starts the sums at now.
func New(now time.Time) *Totals {
	return &Totals{started: now, m: map[string]*eventv1.PolicyCount{}, costs: map[string]*RuleCostSum{}}
}

// ruleLabel: "prefilter" for Rule ID 0, the Rule ID, or "other".
func (t *Totals) ruleLabel(id uint32) string {
	if id == 0 {
		return "prefilter"
	}
	l := strconv.FormatUint(uint64(id), 10)
	if _, ok := t.costs[l]; ok {
		return l
	}
	labelled := len(t.costs)
	if _, ok := t.costs["prefilter"]; ok {
		labelled--
	}
	if _, ok := t.costs["other"]; ok {
		labelled--
	}
	if labelled < MaxRuleLabels {
		return l
	}
	return "other"
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
	t.sampledRequests += c.GetSampledRequests()
	t.sampledEngineNs += c.GetSampledEngineNs()
	for _, r := range c.GetRuleCosts() {
		l := t.ruleLabel(r.GetRuleId())
		s, ok := t.costs[l]
		if !ok {
			s = &RuleCostSum{}
			t.costs[l] = s
		}
		s.Samples += r.GetSamples()
		s.TotalNs += r.GetTotalNs()
		if r.GetMaxNs() > s.MaxNs {
			s.MaxNs = r.GetMaxNs()
		}
	}
}

// RuleCosts: copies of the rule cost sums by label, and the sampled
// transactions with their engine time (W13-R-02).
func (t *Totals) RuleCosts() (map[string]RuleCostSum, uint64, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string]RuleCostSum, len(t.costs))
	for l, s := range t.costs {
		out[l] = *s
	}
	return out, t.sampledRequests, t.sampledEngineNs
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
	// W13-R-02
	dRuleSeconds = prometheus.NewDesc("strata_rule_cost_seconds_total",
		"Engine time of each rule in the sampled requests (1% by default); rule=\"prefilter\" is the Hyperscan scans every rule shares, rule=\"other\" the rules past the first 50 labelled.", []string{"rule"}, nil)
	dRuleSamples = prometheus.NewDesc("strata_rule_cost_samples_total",
		"Evaluations of each rule in the sampled requests.", []string{"rule"}, nil)
	dRuleMax = prometheus.NewDesc("strata_rule_cost_max_seconds",
		"Longest single evaluation of each rule in the sampled requests since the agent started.", []string{"rule"}, nil)
	dSampledRequests = prometheus.NewDesc("strata_rule_cost_sampled_requests_total",
		"Requests whose rules were timed.", nil, nil)
	dSampledSeconds = prometheus.NewDesc("strata_rule_cost_sampled_engine_seconds_total",
		"Engine time of the sampled requests, all of it: a rule's share is its strata_rule_cost_seconds_total over this.", nil, nil)
)

// Describe implements prometheus.Collector.
func (t *Totals) Describe(ch chan<- *prometheus.Desc) {
	ch <- dRequests
	ch <- dGap
	ch <- dDegraded
	ch <- dRuleSeconds
	ch <- dRuleSamples
	ch <- dRuleMax
	ch <- dSampledRequests
	ch <- dSampledSeconds
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
	costs, reqs, ns := t.RuleCosts()
	for l, s := range costs {
		ch <- prometheus.MustNewConstMetric(dRuleSeconds, prometheus.CounterValue, float64(s.TotalNs)/1e9, l)
		ch <- prometheus.MustNewConstMetric(dRuleSamples, prometheus.CounterValue, float64(s.Samples), l)
		ch <- prometheus.MustNewConstMetric(dRuleMax, prometheus.GaugeValue, float64(s.MaxNs)/1e9, l)
	}
	ch <- prometheus.MustNewConstMetric(dSampledRequests, prometheus.CounterValue, float64(reqs))
	ch <- prometheus.MustNewConstMetric(dSampledSeconds, prometheus.CounterValue, float64(ns)/1e9)
}
