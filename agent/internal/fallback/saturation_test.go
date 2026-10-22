package fallback

import (
	"sync"
	"testing"

	"github.com/strata/strata/agent/internal/shmmetrics"
)

func TestSourceOverflowDoesNotForceShadow(t *testing.T) {
	for _, forceErrors := range []bool{false, true} {
		f := &fakeForcer{}
		w := NewWatcher("", f, Options{Warmup: 1, MaxSources: 2, Errors: forceErrors})
		var requests, blocked uint64
		w.read = func(string) (shmmetrics.Snapshot, error) {
			return shmmetrics.Snapshot{Workers: []shmmetrics.Worker{{Requests: [4]uint64{requests - blocked, 0, 0, blocked}}}}, nil
		}
		for i := 0; i < 2; i++ {
			requests += 1000
			w.tick()
		}
		before, _, _, samples := w.d.Reference()
		w.Observe(blockEvent("192.0.2.1"))
		w.Observe(blockEvent("198.51.100.2"))
		for i := 0; i < 200; i++ {
			w.Observe(blockEvent("203.0.113.3"))
		}
		requests += 1000
		blocked += 202
		w.tick()
		if len(f.held) != 0 || len(w.Triggers()) != 0 {
			t.Fatalf("overflow forced shadow (Errors=%v): %v", forceErrors, f.held)
		}
		if got, _, _, n := w.d.Reference(); got != before || n != samples {
			t.Fatalf("overflow changed the baseline: %v/%d -> %v/%d", before, samples, got, n)
		}
		if w.Alerts()["source_limit"] != 1 {
			t.Fatal("source saturation was not reported")
		}
		// Learning resumes in a fresh complete interval: saturation is not sticky.
		for i := 0; i < 2; i++ {
			w.Observe(blockEvent("192.0.2.1"))
		}
		requests += 1000
		w.tick()
		if _, _, _, n := w.d.Reference(); n != samples+1 {
			t.Fatal("learning did not resume after a complete interval")
		}
	}
}

func TestSourceSaturationIPv6AndReset(t *testing.T) {
	s := NewSources(1)
	var wg sync.WaitGroup
	for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2"} {
		wg.Go(func() {
			for i := 0; i < 100; i++ {
				s.Observe(blockEvent(ip))
			}
		})
	}
	wg.Wait()
	if got := s.Take(3); got != (Capped{Blocked: 3, Would: 3, Sources: 1}) {
		t.Fatalf("one /48 must fit one slot: %+v", got)
	}
	s.Observe(blockEvent("192.0.2.1"))
	for i := 0; i < 100; i++ {
		s.Observe(blockEvent("198.51.100.2"))
	}
	if got := s.Take(3); got != (Capped{Blocked: 1, Would: 1, Sources: 1, Saturated: true}) {
		t.Fatalf("overflow was counted or not reported: %+v", got)
	}
	if got := s.Take(3); got != (Capped{}) {
		t.Fatalf("saturation did not reset: %+v", got)
	}
}

func TestSourceSaturationStillDetectsErrors(t *testing.T) {
	d, cur := warm(t, Options{}, 0, 0)
	cur.Requests += 1000
	cur.Errors += 200
	if got := d.StepCapped(*cur, Capped{Saturated: true}); got != ReasonErrors {
		t.Fatalf("saturation masked independent engine errors: %s", got)
	}
	d = NewDetector(Options{})
	if got := d.StepCapped(Totals{}, Capped{Saturated: true}); got != ReasonSourceLimit {
		t.Fatalf("saturation during warmup was not reported: %s", got)
	}
}
