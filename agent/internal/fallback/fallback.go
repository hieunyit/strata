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
// nothing is blocked, so nothing trips; with enforce it trips and the node
// stays in shadow for Hold. The control plane tier (W12-G2-01) compares the
// canary and shadow groups instead, which an attack burst does not move.
package fallback

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	fleetv1 "github.com/strata/strata/agent/gen/strata/fleet/v1"
	"github.com/strata/strata/agent/internal/forceshadow"
	"github.com/strata/strata/agent/internal/shmmetrics"
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
	// Hold: how long the node stays forced into shadow (1 h). Lifting it
	// early is a ForceShadow command with clear (W12-G1-01: only the control
	// plane lifts it).
	Hold time.Duration
	// Alpha of the moving averages (0.1).
	Alpha float64
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
	if o.Hold <= 0 {
		o.Hold = time.Hour
	}
	if o.Alpha <= 0 || o.Alpha > 1 {
		o.Alpha = 0.1
	}
	return o
}

// Reasons a node trips.
const (
	ReasonBlockRate = "block_rate"
	ReasonErrors    = "engine_errors"
	ReasonBudget    = "budget"
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
// reason to trip, or "".
func (d *Detector) Step(t Totals) string {
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
	block := rate(t.Blocked, prev.Blocked)
	would := block + rate(t.Logged, prev.Logged)
	errs := rate(t.Errors, prev.Errors)
	budget := rate(t.Budget, prev.Budget)

	over := func(v, ref float64) bool { return v > d.o.Factor*max(ref, d.o.Floor) }
	if d.samples >= d.o.Warmup {
		switch {
		case block > 0 && over(block, d.would):
			return ReasonBlockRate
		case over(errs, d.errs):
			return ReasonErrors
		case over(budget, d.budget):
			return ReasonBudget
		}
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

// Reference levels learnt so far.
func (d *Detector) Reference() (would, errs, budget float64, samples int) {
	return d.would, d.errs, d.budget, d.samples
}

// Forcer is what the detector drives: forceshadow.Manager.
type Forcer interface {
	Apply(*fleetv1.ForceShadow) error
	Snapshot() forceshadow.State
}

// Watcher runs a Detector on a metrics file.
type Watcher struct {
	file  string
	force Forcer
	o     Options
	d     *Detector
	read  func(string) (shmmetrics.Snapshot, error)

	mu       sync.Mutex
	triggers map[string]uint64
}

// NewWatcher reads metricsFile every o.Interval and forces shadow through f.
func NewWatcher(metricsFile string, f Forcer, o Options) *Watcher {
	o = o.withDefaults()
	return &Watcher{file: metricsFile, force: f, o: o, d: NewDetector(o), read: shmmetrics.Read,
		triggers: map[string]uint64{}}
}

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
	reason := w.d.Step(FromSnapshot(s))
	if reason == "" {
		return
	}
	if !w.force.Snapshot().All.IsZero() {
		return // already forced: an earlier trip or a ForceShadow command
	}
	would, errs, budget, _ := w.d.Reference()
	err = w.force.Apply(&fleetv1.ForceShadow{DurationSeconds: uint32(w.o.Hold / time.Second)})
	if err != nil {
		slog.Error("fallback: force shadow", "reason", reason, "err", err)
		return
	}
	w.mu.Lock()
	w.triggers[reason]++
	w.mu.Unlock()
	slog.Warn("fallback: every policy of this node forced into shadow", "reason", reason,
		"hold", w.o.Hold.String(), "ref_would_block", fmt.Sprintf("%.4f", would),
		"ref_errors", fmt.Sprintf("%.4f", errs), "ref_budget", fmt.Sprintf("%.4f", budget))
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
