package fallback

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	eventv1 "github.com/strata/strata/agent/gen/strata/event/v1"
	"github.com/strata/strata/agent/internal/bundles"
	"github.com/strata/strata/agent/internal/forceshadow"
	"github.com/strata/strata/agent/internal/shmmetrics"
)

// tot builds cumulative totals: n requests of which blocked, logged...
func tot(n, blocked, logged, errs, budget uint64) Totals {
	return Totals{Requests: n, Blocked: blocked, Logged: logged, Errors: errs, Budget: budget}
}

// feed steps the detector through intervals of 1000 requests with the
// given per-interval counts, from cumulative totals at *cur.
func feed(d *Detector, cur *Totals, blocked, logged, errs, budget uint64) string {
	cur.Requests += 1000
	cur.Blocked += blocked
	cur.Logged += logged
	cur.Errors += errs
	cur.Budget += budget
	return d.Step(*cur)
}

func warm(t *testing.T, o Options, blocked, logged uint64) (*Detector, *Totals) {
	t.Helper()
	d := NewDetector(o)
	cur := &Totals{}
	d.Step(*cur)
	for i := 0; i < d.o.Warmup; i++ {
		if r := feed(d, cur, blocked, logged, 0, 0); r != "" {
			t.Fatalf("tripped during warmup: %s", r)
		}
	}
	return d, cur
}

func TestBlockRateThreeTimesTheShadowLevelTrips(t *testing.T) {
	// shadow: 2% of requests would be blocked (logged)
	d, cur := warm(t, Options{}, 0, 20)
	// enforce at the same level: no trip
	for i := 0; i < 5; i++ {
		if r := feed(d, cur, 20, 0, 0, 0); r != "" {
			t.Fatalf("same level tripped: %s", r)
		}
	}
	// 2.9x: no trip (and it is learnt: the reference moves up a little)
	if r := feed(d, cur, 58, 0, 0, 0); r != "" {
		t.Fatalf("2.9x tripped: %s", r)
	}
	// 3x and a bit, on a node that learnt 2%: trips
	d, cur = warm(t, Options{}, 0, 20)
	if r := feed(d, cur, 61, 0, 0, 0); r != ReasonBlockRate {
		t.Fatalf("3x: %q", r)
	}
}

func TestShadowOnlyNeverTripsOnBlocks(t *testing.T) {
	// an attack burst in shadow: logged x10, nothing blocked
	d, cur := warm(t, Options{}, 0, 20)
	if r := feed(d, cur, 0, 200, 0, 0); r != "" {
		t.Fatalf("shadow burst tripped: %s", r)
	}
}

func TestFloorAndWarmup(t *testing.T) {
	// a node that almost never blocks: reference 0.1% counts as 0.5%, so
	// 1% does not trip, 2% does
	d, cur := warm(t, Options{}, 1, 0)
	if r := feed(d, cur, 10, 0, 0, 0); r != "" {
		t.Fatalf("1%% tripped: %s", r)
	}
	if r := feed(d, cur, 20, 0, 0, 0); r != ReasonBlockRate {
		t.Fatalf("2%%: %q", r)
	}
	// nothing trips before the warmup ends
	d = NewDetector(Options{})
	c := &Totals{}
	d.Step(*c)
	if r := feed(d, c, 900, 0, 0, 0); r != "" {
		t.Fatalf("tripped on the first interval: %s", r)
	}
}

func TestErrorsAndBudgetTrip(t *testing.T) {
	d, cur := warm(t, Options{}, 5, 5)
	if r := feed(d, cur, 5, 5, 20, 0); r != ReasonErrors {
		t.Fatalf("errors: %q", r)
	}
	d, cur = warm(t, Options{}, 5, 5)
	if r := feed(d, cur, 5, 5, 0, 20); r != ReasonBudget {
		t.Fatalf("budget: %q", r)
	}
	// below the floor x factor (1.5%): no trip
	d, cur = warm(t, Options{}, 5, 5)
	if r := feed(d, cur, 5, 5, 10, 10); r != "" {
		t.Fatalf("1%% errors tripped: %s", r)
	}
}

func TestQuietIntervalsAndReloadsAreSkipped(t *testing.T) {
	d, cur := warm(t, Options{}, 0, 20)
	// 50 requests in an interval: not enough to judge
	cur.Requests += 50
	cur.Blocked += 50
	if r := d.Step(*cur); r != "" {
		t.Fatalf("quiet interval tripped: %s", r)
	}
	// NGINX reload: the counters start again from 0
	if r := d.Step(tot(10, 10, 0, 0, 0)); r != "" {
		t.Fatalf("reload tripped: %s", r)
	}
	_, _, _, n := d.Reference()
	if n != d.o.Warmup {
		t.Fatalf("learnt %d samples, want %d", n, d.o.Warmup)
	}
	// and it still trips afterwards
	c := tot(10, 10, 0, 0, 0)
	if r := feed(d, &c, 100, 0, 0, 0); r != ReasonBlockRate {
		t.Fatalf("after reload: %q", r)
	}
}

// metrics writes a metrics file with one worker (control-file.md › Metrics
// file): allow, log, block requests.
func metrics(t *testing.T, path string, allow, log, block uint64) {
	t.Helper()
	const counters, slot = 24, 256
	b := make([]byte, 64+slot)
	copy(b, "STRMET1\x00")
	le := binary.LittleEndian
	le.PutUint32(b[8:], 1)
	le.PutUint32(b[12:], 1)
	le.PutUint32(b[16:], slot)
	le.PutUint32(b[20:], counters)
	c := func(i int, v uint64) { le.PutUint64(b[64+8*i:], v) }
	c(0, 4242) // pid
	c(2, allow)
	c(3, log)
	c(5, block)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// W11-G1-01 "Xong khi": the block rate goes 3x up, the node is in shadow
// within 6 seconds, without the control plane, and stays there. Real interval (5 s), real
// metrics and control files.
func TestNodeFallsBackWithinSixSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 11 s")
	}
	dir := t.TempDir()
	ctl, met := filepath.Join(dir, "control"), filepath.Join(dir, "metrics")
	if _, err := bundles.WriteControl(ctl, 1, [32]byte{}, "bundle-1.sbn"); err != nil {
		t.Fatal(err)
	}
	fs := forceshadow.New(ctl, filepath.Join(dir, "force-shadow.json"))
	w := NewWatcher(met, fs, Options{Warmup: 1})
	if w.o.Interval != 5*time.Second {
		t.Fatalf("interval %v", w.o.Interval)
	}

	// enforce, 2% blocked: 1000 requests per interval
	var allow, block uint64 = 980, 20
	metrics(t, met, allow, 0, block)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx) // reads at once, then every 5 s
	time.Sleep(5500 * time.Millisecond)
	// the second read (t = 5 s) learnt 2% if the file moved; move it now
	// for the third read, then spike: 8% blocked
	allow, block = allow+980, block+20
	metrics(t, met, allow, 0, block)
	time.Sleep(5 * time.Second)
	spike := time.Now()
	metrics(t, met, allow+920, 0, block+80)
	// the 80 blocks come from 40 clients (#65: blocks count per source)
	for i := 0; i < 80; i++ {
		w.Observe(blockEvent(fmt.Sprintf("192.0.2.%d", i%40)))
	}

	for time.Since(spike) < 7*time.Second {
		c, err := bundles.ReadControl(ctl)
		if err != nil {
			t.Fatal(err)
		}
		if c.ForceAll {
			el := time.Since(spike)
			// the watcher counts the trip just after it writes the file
			for i := 0; i < 100 && w.Triggers()[ReasonBlockRate] == 0; i++ {
				time.Sleep(10 * time.Millisecond)
			}
			t.Logf("node in shadow %v after the spike, triggers %v", el.Round(time.Millisecond), w.Triggers())
			if el > 6*time.Second {
				t.Fatalf("took %v", el)
			}
			if w.Triggers()[ReasonBlockRate] != 1 {
				t.Fatalf("triggers %v", w.Triggers())
			}
			// held with no deadline, across an agent restart, until the
			// control plane clears every policy (W12-G1-01)
			st := forceshadow.New(ctl, filepath.Join(dir, "force-shadow.json")).Snapshot()
			if st.Fallback == nil || st.Fallback.Reason != ReasonBlockRate || !st.All.IsZero() {
				t.Fatalf("after restart: %+v", st)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("node not forced into shadow within 7 s of the spike")
}

func blockEvent(ip string) *eventv1.Event {
	return &eventv1.Event{BlockId: "STR-8F3K-Q2VD-7XNM-A1PC", Action: eventv1.Action_ACTION_BLOCK, ClientIp: ip, RuleIds: []uint32{942100}}
}

func TestPoissonTail(t *testing.T) {
	for _, c := range []struct {
		k      uint64
		lambda float64
		want   float64
	}{
		{0, 3, 1},
		{1, 1, 1 - math.Exp(-1)},
		{20, 5, 3.4521e-7},
		{8, 2.5, 4.2467e-3},
	} {
		got := PoissonTail(c.k, c.lambda)
		if math.Abs(got-c.want) > c.want*1e-3 {
			t.Errorf("P(X>=%d | %v) = %g, want %g", c.k, c.lambda, got, c.want)
		}
	}
	if p := PoissonTail(1000, 2); p > 1e-300 {
		t.Errorf("far tail %g", p)
	}
}

// #65, lab 14/10: about 300 requests per interval with 1% blocks (1.5 to 3
// expected) tripped a fixed 3x ratio by chance within minutes. The Poisson
// test does not, over a week of intervals; a real 10x jump still trips.
func TestLowTrafficDoesNotTripByChance(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	poisson := func(lambda float64) uint64 { // Knuth
		l, k, p := math.Exp(-lambda), uint64(0), 1.0
		for {
			p *= r.Float64()
			if p <= l {
				return k
			}
			k++
		}
	}
	run := func(o Options) int {
		d := NewDetector(o)
		cur := &Totals{}
		d.Step(*cur)
		trips := 0
		for i := 0; i < 120_000; i++ { // a week of 5 s intervals
			cur.Requests += 300
			cur.Blocked += poisson(3) // 1%
			if d.Step(*cur) != "" {
				trips++
			}
		}
		return trips
	}
	n, old := run(Options{}), run(Options{PValue: 0.999999})
	t.Logf("a week at 300 requests per 5 s, 1%% blocked: %d false trips, %d with the fixed ratio alone", n, old)
	if n != 0 {
		t.Fatalf("%d false trips in a week", n)
	}
	if old < 100 {
		t.Fatalf("a fixed ratio alone tripped only %d times: the test does not show the problem", old)
	}
	d, cur := warm(t, Options{}, 10, 0) // 1% learnt
	if r := feed(d, cur, 100, 0, 0, 0); r != ReasonBlockRate {
		t.Fatalf("10x: %q", r)
	}
}

// #65: one source flooding blocked payloads counts as SourceCap blocks
// and cannot force the node into shadow; the same jump from many sources
// trips.
func TestOneSourceCannotTrip(t *testing.T) {
	d, cur := warm(t, Options{}, 10, 0)
	cur.Requests += 1000
	cur.Blocked += 500
	if r := d.StepCapped(*cur, Capped{Blocked: 3, Would: 3}); r != "" {
		t.Fatalf("one source tripped: %s", r)
	}
	cur.Requests += 1000
	cur.Blocked += 500
	if r := d.StepCapped(*cur, Capped{Blocked: 300, Would: 300}); r != ReasonBlockRate {
		t.Fatalf("100 sources: %q", r)
	}
}

// #65, lab 14/10: a flood from one source must not raise the reference
// either, or the next spike from many sources no longer trips.
func TestOneSourceDoesNotRaiseTheReference(t *testing.T) {
	d, cur := warm(t, Options{}, 10, 0) // 1%
	for i := 0; i < 5; i++ {
		cur.Requests += 1000
		cur.Blocked += 500
		if r := d.StepCapped(*cur, Capped{Blocked: 3, Would: 3}); r != "" {
			t.Fatalf("one source tripped: %s", r)
		}
	}
	if would, _, _, _ := d.Reference(); would > 0.011 {
		t.Fatalf("reference raised to %.4f by one source", would)
	}
	cur.Requests += 1000
	cur.Blocked += 100
	if r := d.StepCapped(*cur, Capped{Blocked: 100, Would: 100}); r != ReasonBlockRate {
		t.Fatalf("spike from many sources after the flood: %q", r)
	}
}

func TestSources(t *testing.T) {
	s := NewSources(3)
	for i := 0; i < 10; i++ {
		s.Observe(blockEvent("192.0.2.1"))
	}
	// one IPv6 host, several addresses of its /64
	s.Observe(blockEvent("2001:db8:1:2::1"))
	s.Observe(blockEvent("2001:db8:1:2::2"))
	s.Observe(blockEvent("2001:db8:1:2:aaaa::3"))
	s.Observe(blockEvent("2001:db8:1:2:bbbb::4"))
	// not counted: a fail-closed 503 (EVT, BLOCK), an engine error (no
	// rule), a finding below the threshold (would_block false)
	s.Observe(&eventv1.Event{BlockId: "EVT-8F3K-Q2VD-7XNM-A1PC", Action: eventv1.Action_ACTION_BLOCK, ClientIp: "192.0.2.9"})
	s.Observe(&eventv1.Event{BlockId: "EVT-8F3K-Q2VD-7XNM-A1PC", Action: eventv1.Action_ACTION_LOG, ClientIp: "192.0.2.9"})
	s.Observe(&eventv1.Event{BlockId: "EVT-8F3K-Q2VD-7XNM-A1PC", Action: eventv1.Action_ACTION_LOG, ClientIp: "192.0.2.9",
		RuleIds: []uint32{920350}, Inspection: eventv1.Inspection_INSPECTION_FULL})
	// would-be blocks in shadow: a new module (would_block), an old one
	for _, ip := range []string{"198.51.100.7", "198.51.100.7", "198.51.100.7", "198.51.100.7"} {
		s.Observe(&eventv1.Event{BlockId: "EVT-8F3K-Q2VD-7XNM-A1PC", Action: eventv1.Action_ACTION_LOG, ClientIp: ip,
			RuleIds: []uint32{942100}, WouldBlock: true, Inspection: eventv1.Inspection_INSPECTION_FULL})
	}
	if got := s.Take(3); got != (Capped{Blocked: 6, Would: 9}) {
		t.Fatalf("capped %v, want {6 9}", got)
	}
	if got := s.Take(3); got != (Capped{}) {
		t.Fatalf("not reset: %v", got)
	}
	// Past MaxSources, exclude untracked sources and mark the interval incomplete.
	for i := 0; i < 5; i++ {
		s.Observe(blockEvent(fmt.Sprintf("198.51.100.%d", i)))
		s.Observe(blockEvent(fmt.Sprintf("198.51.100.%d", i)))
	}
	if got := s.Take(1); got != (Capped{Blocked: 3, Would: 3, Saturated: true}) {
		t.Fatalf("with overflow %v, want 3 with saturation", got)
	}
}

// #65: forcing shadow does not change the fail mode, so engine errors and
// budget overruns only raise an alert, unless Options.Errors.
func TestErrorsOnlyAlertByDefault(t *testing.T) {
	for _, forceOnErrors := range []bool{false, true} {
		f := &fakeForcer{}
		w := NewWatcher("", f, Options{Warmup: 1, Errors: forceOnErrors})
		var tot Totals
		w.read = func(string) (shmmetrics.Snapshot, error) {
			return shmmetrics.Snapshot{Workers: []shmmetrics.Worker{{Requests: [4]uint64{tot.Requests}, FailOpen: tot.Errors}}}, nil
		}
		for _, errs := range []uint64{0, 0, 0, 200} {
			tot.Requests += 1000
			tot.Errors += errs
			w.tick()
		}
		if forceOnErrors {
			if len(f.held) != 1 || w.Triggers()[ReasonErrors] != 1 {
				t.Fatalf("--fallback-on-errors: held %v, triggers %v", f.held, w.Triggers())
			}
		} else if len(f.held) != 0 || w.Alerts()[ReasonErrors] != 1 {
			t.Fatalf("default: held %v, alerts %v", f.held, w.Alerts())
		}
	}
}

// W12-G1-01: each threshold, just under and just over, with the defaults
// and with the options set.
func TestThresholdEdges(t *testing.T) {
	step := func(d *Detector, cur *Totals, n, blocked, errs, budget uint64) string {
		cur.Requests += n
		cur.Blocked += blocked
		cur.Errors += errs
		cur.Budget += budget
		return d.Step(*cur)
	}
	for _, c := range []struct {
		name                     string
		o                        Options
		learn                    uint64 // logged per 1000 while learning
		n, blocked, errs, budget uint64
		want                     string
	}{
		// factor 3 over a learnt 2%
		{"block 2.95x", Options{}, 20, 10000, 590, 0, 0, ""},
		{"block 3.05x", Options{}, 20, 10000, 610, 0, 0, ReasonBlockRate},
		// factor 2
		{"factor 2: 1.95x", Options{Factor: 2}, 20, 10000, 390, 0, 0, ""},
		{"factor 2: 2.05x", Options{Factor: 2}, 20, 10000, 410, 0, 0, ReasonBlockRate},
		// floor 0.5% under a learnt 0.1%: trips over 1.5%
		{"floor: 1.4%", Options{}, 1, 10000, 140, 0, 0, ""},
		{"floor: 1.6%", Options{}, 1, 10000, 160, 0, 0, ReasonBlockRate},
		// floor 2%: trips over 6%
		{"floor 2%: 5.9%", Options{Floor: 0.02}, 1, 10000, 590, 0, 0, ""},
		{"floor 2%: 6.1%", Options{Floor: 0.02}, 1, 10000, 610, 0, 0, ReasonBlockRate},
		// errors and budget: learnt 0, so the floor (1.5%)
		{"errors 1.4%", Options{}, 20, 10000, 200, 140, 0, ""},
		{"errors 1.6%", Options{}, 20, 10000, 200, 160, 0, ReasonErrors},
		{"budget 1.4%", Options{}, 20, 10000, 200, 0, 140, ""},
		{"budget 1.6%", Options{}, 20, 10000, 200, 0, 160, ReasonBudget},
		// at least MinRequests in the interval
		{"99 requests", Options{}, 20, 99, 99, 0, 0, ""},
		{"100 requests", Options{}, 20, 100, 100, 0, 0, ReasonBlockRate},
		{"min 500: 499", Options{MinRequests: 500}, 20, 499, 499, 0, 0, ""},
		{"min 500: 500", Options{MinRequests: 500}, 20, 500, 500, 0, 0, ReasonBlockRate},
		// no block, however much is logged or errors: errors still trip
		{"no block", Options{}, 20, 10000, 0, 0, 0, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, cur := warm(t, c.o, 0, c.learn)
			if r := step(d, cur, c.n, c.blocked, c.errs, c.budget); r != c.want {
				t.Fatalf("got %q, want %q", r, c.want)
			}
		})
	}
	// warmup: the Warmup-th learnt interval is the last that cannot trip
	for _, w := range []int{1, 12, 30} {
		d := NewDetector(Options{Warmup: w})
		cur := &Totals{}
		d.Step(*cur)
		for i := 0; i < w; i++ {
			if r := feed(d, cur, 0, 20, 0, 0); r != "" {
				t.Fatalf("warmup %d: tripped at %d", w, i)
			}
		}
		if r := feed(d, cur, 500, 0, 0, 0); r != ReasonBlockRate {
			t.Fatalf("warmup %d: %q after it", w, r)
		}
	}
}

// fakeForcer records holds.
type fakeForcer struct {
	held []string
	st   forceshadow.State
}

func (f *fakeForcer) HoldAll(r string) error {
	f.held = append(f.held, r)
	f.st.Fallback = &forceshadow.Hold{Reason: r}
	return nil
}
func (f *fakeForcer) Snapshot() forceshadow.State { return f.st }

// W12-G1-01: a trip holds the node with no deadline; trips while it is held
// change nothing; once the control plane clears it, the next trip holds
// again.
func TestWatcherHoldsUntilCleared(t *testing.T) {
	f := &fakeForcer{}
	w := NewWatcher("unused", f, Options{Warmup: 1})
	var cur Totals
	w.read = func(string) (shmmetrics.Snapshot, error) {
		var wk shmmetrics.Worker
		wk.Requests[0] = cur.Requests - cur.Blocked - cur.Logged
		wk.Requests[1], wk.Requests[3] = cur.Logged, cur.Blocked
		return shmmetrics.Snapshot{Workers: []shmmetrics.Worker{wk}}, nil
	}
	// the blocks and would-be blocks come from as many client addresses,
	// so the per-source cap (#65) keeps them all
	next := func(blocked, logged uint64) {
		cur.Requests += 1000
		cur.Blocked += blocked
		cur.Logged += logged
		for i := uint64(0); i < blocked; i++ {
			w.Observe(blockEvent(fmt.Sprintf("198.51.%d.%d", i/256, i%256)))
		}
		for i := uint64(0); i < logged; i++ {
			w.Observe(&eventv1.Event{BlockId: "EVT-8F3K-Q2VD-7XNM-A1PC", Action: eventv1.Action_ACTION_LOG,
				ClientIp: fmt.Sprintf("203.0.%d.%d", i/256, i%256), RuleIds: []uint32{942100}, WouldBlock: true,
				Inspection: eventv1.Inspection_INSPECTION_FULL})
		}
		w.tick()
	}
	w.tick()
	next(0, 20)
	next(200, 0)
	if len(f.held) != 1 || f.held[0] != ReasonBlockRate || w.Triggers()[ReasonBlockRate] != 1 {
		t.Fatalf("held %v, triggers %v", f.held, w.Triggers())
	}
	next(300, 0)
	if len(f.held) != 1 || w.Triggers()[ReasonBlockRate] != 1 {
		t.Fatalf("held again while held: %v", f.held)
	}
	// a ForceShadow command for every policy does not stop a hold
	f.st = forceshadow.State{All: time.Now().Add(time.Hour)}
	next(300, 0)
	if len(f.held) != 2 {
		t.Fatalf("not held under a command: %v", f.held)
	}
	f.st = forceshadow.State{} // cleared by the control plane
	next(300, 0)
	if len(f.held) != 3 || w.Triggers()[ReasonBlockRate] != 3 {
		t.Fatalf("after clear: %v %v", f.held, w.Triggers())
	}
}
