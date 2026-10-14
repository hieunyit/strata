package fallback

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/strata/strata/agent/internal/bundles"
	"github.com/strata/strata/agent/internal/forceshadow"
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
// within 6 seconds, without the control plane. Real interval (5 s), real
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

	for time.Since(spike) < 7*time.Second {
		c, err := bundles.ReadControl(ctl)
		if err != nil {
			t.Fatal(err)
		}
		if c.ForceAll {
			el := time.Since(spike)
			t.Logf("node in shadow %v after the spike, triggers %v", el.Round(time.Millisecond), w.Triggers())
			if el > 6*time.Second {
				t.Fatalf("took %v", el)
			}
			if w.Triggers()[ReasonBlockRate] != 1 {
				t.Fatalf("triggers %v", w.Triggers())
			}
			if st := fs.Snapshot(); st.All.Before(time.Now().Add(59 * time.Minute)) {
				t.Fatalf("held until %v, want about 1 h", st.All)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("node not forced into shadow within 7 s of the spike")
}
