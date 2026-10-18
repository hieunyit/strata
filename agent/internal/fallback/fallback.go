// Package fallback is the node tier of the automatic fallback
// (nginx-module.md › Bật enforce theo canary, "Tự fallback hai tầng", tier
// 1): every 5 seconds the agent reads the workers' counters in the metrics
// file and, when the node blocks far more than it did in shadow, or engine
// errors or CPU budget overruns jump, forces every policy of the node into
// shadow through the control file. Workers apply it within a second; the
// control plane is not needed.
//
// The metrics file has no per-policy counters, so the decision is for the
// whole node and forces every policy (PO decision 13/10/2026,
// docs/plan/w11-plan.md). The reference levels are learnt from the node's
// own traffic: the share of requests the engine would block (blocked plus
// logged: in shadow every would-be block is logged), of engine errors (fail
// mode) and of budget overruns, as moving averages over the samples that
// did not trip.
//
// A burst of real attacks also raises the would-block share. In shadow
// nothing is blocked, so nothing trips; with enforce it could trip and put
// the node in shadow until the control plane lifts it (W12-G1-01: a
// ForceShadow clear for every policy, POST /v1/nodes:clearForceShadow; no
// deadline, and an agent restart keeps it): a way to switch the WAF off from
// outside (#65). So:
//   - the blocks of an interval count at most SourceCap per client address
//     (IPv6 per /64), from the agent's own events: one source sending a
//     flood of blocked payloads counts as SourceCap blocks; a rule that
//     blocks real users blocks many sources. The reference is learnt from
//     counts capped the same way (blocks and would-be blocks logged in
//     shadow), or the same flood would first raise it;
//   - a count trips only when it is both Factor times the reference and
//     improbable under it (one-sided Poisson test, PValue): a fixed ratio
//     on a few expected blocks tripped on chance alone at low traffic
//     (lab, 14/10: 2 false trips out of 2 runs at 60 req/s, 1% attacks);
//   - engine errors and budget overruns are only reported (Alerts), unless
//     Options.Errors: shadow does not change the fail mode, so forcing it
//     neither lets fail-closed requests through nor stops the overruns,
//     while an attacker able to cause overruns (large bodies, #28) would
//     switch the blocking off.
//
// The control plane tier (W12-G2-01) compares the canary and shadow groups
// instead, which an attack burst does not move.
package fallback

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"github.com/strata/strata/agent/internal/forceshadow"
	"github.com/strata/strata/agent/internal/shmmetrics"
	"github.com/strata/strata/agent/pkg/stats"
)

// Options of the detector; zero values take the defaults.
type Options struct {
	// Interval between two reads of the metrics file (5 s).
	Interval time.Duration
	// Factor over the reference level that trips (3).
	Factor float64
	// Floor: reference levels below it count as Floor (0.5%), so that a
	// node that almost never blocks does not trip on a handful of blocks.
	Floor float64
	// MinRequests in one interval for the interval to count (100).
	MinRequests uint64
	// Warmup: intervals learnt before the detector may trip (12, one
	// minute at 5 s).
	Warmup int
	// Alpha of the moving averages (0.1).
	Alpha float64
	// PValue: a count trips only when its one-sided Poisson tail under the
	// reference is below it (1e-6: at one test per 5 s, a false trip every
	// few thousand hours per node).
	PValue float64
	// SourceCap: blocks of one client address counted per interval (3).
	SourceCap uint64
	// MaxSources tracked per interval (4096). Overflow suspends block-rate
	// fallback and baseline learning until the next complete interval.
	MaxSources int
	// Errors: also force shadow on engine errors and budget overruns, as
	// before #65; by default they are only reported.
	Errors bool
}

func (o Options) withDefaults() Options {
	if o.Interval <= 0 {
		o.Interval = 5 * time.Second
	}
	if o.Factor <= 0 {
		o.Factor = 3
	}
	if o.Floor <= 0 {
		o.Floor = 0.005
	}
	if o.MinRequests == 0 {
		o.MinRequests = 100
	}
	if o.Warmup <= 0 {
		o.Warmup = 12
	}
	if o.Alpha <= 0 || o.Alpha > 1 {
		o.Alpha = 0.1
	}
	if o.PValue <= 0 || o.PValue >= 1 {
		o.PValue = 1e-6
	}
	if o.SourceCap == 0 {
		o.SourceCap = 3
	}
	if o.MaxSources <= 0 {
		o.MaxSources = 4096
	}
	return o
}

// Reasons a node trips.
const (
	ReasonBlockRate   = "block_rate"
	ReasonErrors      = "engine_errors"
	ReasonBudget      = "budget"
	ReasonSourceLimit = "source_limit" // alert only, even with Options.Errors
)

// Totals: the node's counters, summed over the workers.
type Totals struct {
	Requests, Blocked, Logged, Errors, Budget uint64
}

// FromSnapshot sums the workers of a metrics file.
func FromSnapshot(s shmmetrics.Snapshot) Totals {
	var t Totals
	for _, w := range s.Workers {
		for _, n := range w.Requests {
			t.Requests += n
		}
		t.Logged += w.Requests[1]
		t.Blocked += w.Requests[3]
		t.Errors += w.FailOpen + w.FailClosed
		t.Budget += w.BudgetExceed
	}
	return t
}

// Detector holds the reference levels. Not safe for concurrent Step calls.
type Detector struct {
	o       Options
	prev    *Totals
	samples int
	would   float64 // reference: (blocked + logged) / requests
	errs    float64
	budget  float64
}

// NewDetector with o (defaults for zero fields).
func NewDetector(o Options) *Detector { return &Detector{o: o.withDefaults()} }

// Step takes the totals read at the end of an interval and returns the
// reason to trip, or "". Every block counts (no source information).
func (d *Detector) Step(t Totals) string {
	return d.StepCapped(t, Capped{Blocked: math.MaxUint64, Would: math.MaxUint64})
}

// StepCapped is Step with the interval's blocks and would-be blocks
// counted at most SourceCap per source (Sources.Take): each count is the
// smaller of the metrics file's and the capped one.
func (d *Detector) StepCapped(t Totals, capped Capped) (reason string) {
	defer func() {
		if capped.Saturated && reason == "" {
			reason = ReasonSourceLimit
		}
	}()
	prev := d.prev
	d.prev = &t
	if prev == nil {
		return ""
	}
	// counters only go down when NGINX reloads (a new metrics file): start
	// over from these totals
	if t.Requests < prev.Requests || t.Blocked < prev.Blocked || t.Logged < prev.Logged ||
		t.Errors < prev.Errors || t.Budget < prev.Budget {
		return ""
	}
	n := t.Requests - prev.Requests
	if n < d.o.MinRequests {
		return ""
	}
	rate := func(a, b uint64) float64 { return float64(a-b) / float64(n) }
	blocked := min(t.Blocked-prev.Blocked, capped.Blocked)
	would := float64(min(t.Blocked-prev.Blocked+t.Logged-prev.Logged, capped.Would)) / float64(n)
	errs := rate(t.Errors, prev.Errors)
	budget := rate(t.Budget, prev.Budget)

	// k events in the interval against the reference share: Factor times
	// the expected count, and improbable under it
	over := func(k uint64, ref float64) bool {
		lambda := float64(n) * max(ref, d.o.Floor)
		return float64(k) > d.o.Factor*lambda && PoissonTail(k, lambda) < d.o.PValue
	}
	if d.samples >= d.o.Warmup {
		switch {
		case !capped.Saturated && blocked > 0 && over(blocked, d.would):
			return ReasonBlockRate
		case over(t.Errors-prev.Errors, d.errs):
			return ReasonErrors
		case over(t.Budget-prev.Budget, d.budget):
			return ReasonBudget
		}
	}
	if capped.Saturated {
		return ReasonSourceLimit // never learn an incomplete source count
	}
	if d.samples == 0 {
		d.would, d.errs, d.budget = would, errs, budget
	} else {
		a := d.o.Alpha
		if d.samples < d.o.Warmup {
			a = 1 / float64(d.samples+1) // plain mean while warming up
		}
		d.would += a * (would - d.would)
		d.errs += a * (errs - d.errs)
		d.budget += a * (budget - d.budget)
	}
	d.samples++
	return ""
}

// PoissonTail is P(X >= k) for X ~ Poisson(lambda), for k above lambda
// (summed from k up; the terms shrink).
func PoissonTail(k uint64, lambda float64) float64 { return stats.PoissonTail(k, lambda) }

// Capped counts of an interval: blocks, and blocks plus would-be blocks
// logged in shadow, at most SourceCap per source.
type Capped struct {
	Blocked, Would uint64
	Saturated      bool
}

// Sources counts an interval's blocks (a Block ID STR-, action BLOCK) and
// would-be blocks (an Event ID with action LOG that would have blocked) by
// client address, from the events the agent receives.
type Sources struct {
	max       int
	mu        sync.Mutex
	n         map[string]*[2]uint64 // blocks, would-be blocks logged
	saturated bool
}

// NewSources tracks up to max sources per interval.
func NewSources(max int) *Sources { return &Sources{max: max, n: map[string]*[2]uint64{}} }

// Observe counts ev when it is a block or a would-be block.
func (s *Sources) Observe(ev *eventv1.Event) {
	var i int
	switch {
	case ev.GetAction() == eventv1.Action_ACTION_BLOCK && strings.HasPrefix(ev.GetBlockId(), "STR-"):
		i = 0
	case ev.GetAction() == eventv1.Action_ACTION_LOG && strings.HasPrefix(ev.GetBlockId(), "EVT-") && len(ev.GetRuleIds()) > 0 &&
		// modules before RV-G2-01 send no inspection and no would_block
		(ev.GetWouldBlock() || ev.GetInspection() == eventv1.Inspection_INSPECTION_UNSPECIFIED):
		i = 1
	default:
		return
	}
	k := sourceKey(ev.GetClientIp())
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.n[k]
	if !ok {
		if len(s.n) >= s.max {
			s.saturated = true
			return
		}
		c = new([2]uint64)
		s.n[k] = c
	}
	c[i]++
}

// Take returns the counts since the last Take, at most limit per source,
// and starts a new interval.
func (s *Sources) Take(limit uint64) Capped {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Capped{Saturated: s.saturated}
	for _, c := range s.n {
		out.Blocked += min(c[0], limit)
		out.Would += min(c[0]+c[1], limit)
	}
	clear(s.n)
	s.saturated = false
	return out
}

func sourceKey(ip string) string { return stats.SourceKey(ip) }

// Reference levels learnt so far.
func (d *Detector) Reference() (would, errs, budget float64, samples int) {
	return d.would, d.errs, d.budget, d.samples
}

// Forcer is what the detector drives: forceshadow.Manager.
type Forcer interface {
	HoldAll(reason string) error
	Snapshot() forceshadow.State
}

// Watcher runs a Detector on a metrics file.
type Watcher struct {
	file  string
	force Forcer
	o     Options
	d     *Detector
	read  func(string) (shmmetrics.Snapshot, error)
	src   *Sources

	mu       sync.Mutex
	triggers map[string]uint64
	alerts   map[string]uint64
}

// NewWatcher reads metricsFile every o.Interval and forces shadow through f.
func NewWatcher(metricsFile string, f Forcer, o Options) *Watcher {
	o = o.withDefaults()
	return &Watcher{file: metricsFile, force: f, o: o, d: NewDetector(o), read: shmmetrics.Read,
		src: NewSources(o.MaxSources), triggers: map[string]uint64{}, alerts: map[string]uint64{}}
}

// Observe feeds an event the agent received (the event socket) to the
// per-source block count.
func (w *Watcher) Observe(ev *eventv1.Event) { w.src.Observe(ev) }

// Run until ctx is done.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.o.Interval)
	defer t.Stop()
	w.tick()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick()
		}
	}
}

func (w *Watcher) tick() {
	s, err := w.read(w.file)
	if err != nil {
		return // no NGINX or a bad file: the metrics exporter reports it
	}
	capped := w.src.Take(w.o.SourceCap)
	reason := w.d.StepCapped(FromSnapshot(s), capped)
	if capped.Saturated {
		w.mu.Lock()
		w.alerts[ReasonSourceLimit]++
		w.mu.Unlock()
		slog.Warn("fallback: source limit reached; block-rate decisions and learning suspended for this interval")
	}
	if reason == "" || reason == ReasonSourceLimit {
		return
	}
	would, errs, budget, _ := w.d.Reference()
	if reason != ReasonBlockRate && !w.o.Errors {
		w.mu.Lock()
		w.alerts[reason]++
		w.mu.Unlock()
		slog.Warn("fallback: engine errors or budget overruns jumped; policies left as they are (--fallback-on-errors)",
			"reason", reason, "ref_errors", fmt.Sprintf("%.4f", errs), "ref_budget", fmt.Sprintf("%.4f", budget))
		return
	}
	if w.force.Snapshot().Fallback != nil {
		return // held by an earlier trip
	}
	// also under a ForceShadow command for every policy (nothing is blocked
	// then, so this is rare): the hold outlives the command's deadline
	err = w.force.HoldAll(reason)
	if err != nil {
		slog.Error("fallback: force shadow", "reason", reason, "err", err)
		return
	}
	w.mu.Lock()
	w.triggers[reason]++
	w.mu.Unlock()
	slog.Warn("fallback: every policy of this node forced into shadow", "reason", reason,
		"until", "lifted by the control plane", "ref_would_block", fmt.Sprintf("%.4f", would),
		"ref_errors", fmt.Sprintf("%.4f", errs), "ref_budget", fmt.Sprintf("%.4f", budget))
}

// Alerts: source saturation, or jumps of engine errors or budget overruns
// that did not force shadow (Options.Errors off), by reason.
func (w *Watcher) Alerts() map[string]uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]uint64, len(w.alerts))
	for k, v := range w.alerts {
		out[k] = v
	}
	return out
}

// Triggers: the trips so far, by reason.
func (w *Watcher) Triggers() map[string]uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]uint64, len(w.triggers))
	for k, v := range w.triggers {
		out[k] = v
	}
	return out
}
